import com.github.tototoshi.csv._

class DatabaseConstraint(val cpg: Cpg) {
    val sanitizationObject = new SanitizationFilter(cpg)
    implicit val vulnerabilityInst: sanitizationObject.vulnerabilityType = sanitizationObject.vulnerabilityType("XSS", Constants.san_functions_xss)
    val removeChars = Set(',', '"', '\\', '`', '\'')
    val calculationPattern = "\\s*([-+=/*><!()])\\s*".r

    // Get all database calls (unsafe queries on the database)
    val databaseCalls: List[nodes.Call] = cpg.call.filter(x => Constants.sqli_sink.map(x.name.contains(_)).reduce((x,y) => x || y)).l
    val queries = databaseCalls.map(DBQuery(_))

    // Get database schema from csv file
    val file_name = cpg.metaData.root.head.split("/").last
    val reader = CSVReader.open("navex_utils/code/db/" + file_name + "-database.csv")
    val reader_data: List[List[String]] = reader.all()
    val list_schema: List[List[String]] = reader_data.map(ls => List(ls(0), ls(1), ls(3))) 
    val db_schema = scala.collection.mutable.Map[String, Map[String, Boolean]]()
    reader_data.map(row => db_schema(row.head) = db_schema.get(row.head).getOrElse(Map()) + (row(1) -> row(3).toBooleanOption.getOrElse(false)))
    val tables: List[String] = db_schema.keys.toList

    def getUnsafeColumnOutput(query: DBQuery): List[(String, String)] = {
        query.queryType match {
            case QueryType.InsertQuery => List()
            case QueryType.UpdateQuery => List()
            case QueryType.OtherQuery => List()
            case QueryType.SelectQuery => {
                val queryCode = query.queryCode.map(_.filter(!removeChars.contains(_))).filterNot(_.isEmpty)
                val queryScope = queryCode.dropWhile(_.toLowerCase() != "select").drop(1).takeWhile(_.toLowerCase() != "from")
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "from").drop(1).takeWhile(_.toLowerCase() != "where")
                val queryCond = queryCode.dropWhile(_.toLowerCase() != "where").drop(1)
                val queryTableName = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).headOption.getOrElse("NA")
                if (queryTableName == "NA") {
                    // println(query)
                    List()
                }
                else {
                    val queryColumns = db_schema(queryTableName) 
                    val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                    if (queryScope.contains("*")) unsafeColumns.map((queryTableName, _))
                    else {
                        queryScope.filter(unsafeColumns.contains(_)).toList.map((queryTableName, _))
                    }
                }
            }
        }
    }
    
    def labelQueryOutput(query: DBQuery): QueryLabel.Value =  {
        query.queryType match {
            case QueryType.InsertQuery => QueryLabel.SafeQuery
            case QueryType.UpdateQuery => QueryLabel.SafeQuery
            case QueryType.OtherQuery => QueryLabel.SafeQuery
            case QueryType.SelectQuery => {
                val queryCode = query.queryCode.map(_.filter(!removeChars.contains(_))).filterNot(_.isEmpty)
                val queryScope = queryCode.dropWhile(_.toLowerCase() != "select").drop(1).takeWhile(_.toLowerCase() != "from")
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "from").drop(1).takeWhile(_.toLowerCase() != "where")
                val queryCond = queryCode.dropWhile(_.toLowerCase() != "where").drop(1)
                val queryTableName = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).headOption.getOrElse("NA")
                if (queryTableName == "NA") {
                    // println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                    val queryColumns = db_schema(queryTableName) 
                    val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                    if (queryScope.map(scope => (scope == "*" && !unsafeColumns.isEmpty) || (!safeSQLFunctions.exists(scope.contains(_)) && unsafeColumns.exists(scope.contains(_)))).contains(true))
                        QueryLabel.UnsafeQuery
                    else QueryLabel.SafeQuery
                }
            }
        }
    }
    
    def labelQueryInput(query: DBQuery): QueryLabel.Value = {
        // println(query)
        query.queryType match {
            case QueryType.OtherQuery => QueryLabel.SafeQuery
            case QueryType.SelectQuery => QueryLabel.SafeQuery
            case QueryType.InsertQuery => {
                val queryCode = query.queryCode.mkString(" ").toLowerCase.replace("values(", "values ( ").split(" ")
                val queryTable = queryCode.dropWhile(_ != "into").drop(1).takeWhile(!_.contains("values"))
                val queryValues = queryCode.dropWhile(!_.contains("values")).drop(1).takeWhile(token => !token.contains(";") && token.toLowerCase!="where")
                val tableDistances = tables.map(db_table => queryTable.map(metric.compare(db_table, _))).flatten.l
                val closestTable = if (tableDistances.max < 0.3) "NA" else tables(tableDistances.indexOf(tableDistances.max)/queryTable.size)
                if (closestTable == "NA") {
                    // Unable to find a matching table from the query
                    // println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                    // val queryTableName = {
                    //     if (queryTableNames.size == 1) queryTableNames(0)
                    //     else {
                    //         val tableColumns = queryTableNames.map(db_schema.get(_).get.keys)
                    //         // get most likely table
                    //         val mostLikelyIndex = tableColumns.map(_.toList.map(s => queryCode.exists({
                    //             val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                    //             regex.findFirstIn(_).isDefined}))).map(_.filter(_==true).size).zipWithIndex.maxBy(_._1)._2 
                    //         queryTableNames(mostLikelyIndex)
                    //     }
                    // }
                    val queryTableName = closestTable
                    val sortedColumns: List[String] = {
                        if (queryTable.mkString(" ").contains("("))
                            queryTable.dropWhile(!_.contains("(")).drop(0).toList.map(_.replace("(", "").replace(")", ""))
                        else list_schema.filter(_(0) == queryTableName).map(_(1))
                        } 
                    val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                    val insertValuesUnsafe = unsafeColumns.map(s => sortedColumns.exists({
                            val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                            regex.findFirstIn(_).isDefined}))
                    if (unsafeColumns.isEmpty || !insertValuesUnsafe.contains(true))
                        QueryLabel.SafeQuery
                    else {
                        val valuesParsed =  calculationPattern.replaceAllIn(queryValues.mkString(" "), matchResult => "PARSED_SPACE" + matchResult.group(1) + "PARSED_SPACE").split(" ").filter(_.exists(_.isLetterOrDigit)).toList
                        if (valuesParsed.size != sortedColumns.size) QueryLabel.UnsafeQuery
                        else {
                            val unsafeIndices = unsafeColumns.map(sortedColumns.indexOf(_))
                            val unsafeNodes = unsafeIndices.map(valuesParsed.lift(_).getOrElse("").replace("PARSED_SPACE", " ")).map(query.searchNodeFromQuery(_, 0.7F)).filterNot(_==None)                         
                            if (unsafeNodes.map(sanitizationObject.isSanitized(_)).contains(false))
                                QueryLabel.UnsafeQuery
                            else QueryLabel.SafeQuery
                        }
                    }
                }
            }
            case QueryType.UpdateQuery => {
                val queryCode = query.queryCode.map(_.toLowerCase)
                val queryTable = queryCode.dropWhile(_ != "update").drop(1).takeWhile(_ != "set")
                val queryValues = queryCode.dropWhile(_ != "set").drop(1).takeWhile(token => !token.contains(";") && token.toLowerCase!="where")
                val tableDistances = tables.map(db_table => queryTable.map(metric.compare(db_table, _))).flatten.l
                val closestTable = if (tableDistances.max < 0.3) "NA" else tables(tableDistances.indexOf(tableDistances.max)/queryTable.size)
                if (closestTable == "NA") {
                    // Unable to find a matching table from the query
                    // println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                    // val queryTableName = {
                    //     if (queryTableNames.size == 1) queryTableNames(0)
                    //     else {
                    //         val tableColumns = queryTableNames.map(db_schema.get(_).get.keys)
                    //         // get most likely table
                    //         val mostLikelyIndex = tableColumns.map(_.toList.map(s => queryCode.exists({
                    //             val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                    //             regex.findFirstIn(_).isDefined}))).map(_.filter(_==true).size).zipWithIndex.maxBy(_._1)._2 
                    //         queryTableNames(mostLikelyIndex)
                    //     }
                    // }
                    val queryTableName = closestTable
                    val queryColumns = db_schema(queryTableName) 
                    val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                    val setValuesUnsafe = unsafeColumns.map(s => queryValues.exists({
                            val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                            regex.findFirstIn(_).isDefined}))
                    if (unsafeColumns.isEmpty || !setValuesUnsafe.contains(true))
                        QueryLabel.SafeQuery
                    else {
                        val valuesParsed =  calculationPattern.replaceAllIn(queryValues.map(_.filter(!removeChars.contains(_))).filterNot(_.isEmpty).mkString(" "), matchResult => matchResult.group(1)).split(" ").filter(_.exists(_.isLetterOrDigit)).toList
                        val unsafeValues = valuesParsed.filter(token => unsafeColumns.contains(token.split("=")(0)))
                        val unsafeNodes = unsafeValues.map(_.split("=").lift(1).getOrElse("")).map(query.searchNodeFromQuery(_)) 
                        if (unsafeNodes.map(sanitizationObject.isSanitized(_)).contains(false))
                            QueryLabel.UnsafeQuery
                        else QueryLabel.SafeQuery
                    }
                }
            }
            case _ => {
                QueryLabel.UnsafeQuery
            }
        }
    }

    // val allDbCalls = cpg.call.filter(x => Constants.sql_func.map(x.name.contains(_)).reduce((x,y) => x || y)).l
    // def filterInnerCalls(path: List[AstNode]): Boolean = {
    //     if (!path.map(allDbCalls.contains(_)).contains(true)) true
        
    // }

    // def filterPath(path: List[AstNode]): Boolean = {
    //     val safeDbCalls: List[nodes.Call] = cpg.call.filter(x => Constants.sql_func.map(x.name.contains(_)).reduce((x,y) => x || y)).l.filterNot(element => databaseCalls.contains(element))
    //     val queries = path.filter(databaseCalls.contains).map(getQuery(_))
    //     queries.map(labelQuery(_)).contains(QueryLabel.SafeQuery) || !path.filter(safeDbCalls.contains).isEmpty
    // }

    def debug() = {
        val typeAndCode = (queries.map(_.queryType) zip queries.map("\"" + _.queryCode.mkString(" ") + "\"")).map(_.toString)
        typeAndCode.map(_.replaceAll("^.|.$", "")) #> "parsedQueries.csv"
        println("\tNumber of queries\t|\tSafe Input\t|\tSafe Output")
        println("Select: \t" + queries.filter(_.queryType == QueryType.SelectQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.SelectQuery).filter(labelQueryOutput(_) == QueryLabel.SafeQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.SelectQuery).filter(labelQueryInput(_) == QueryLabel.SafeQuery).size)
        println("Insert: \t" + queries.filter(_.queryType == QueryType.InsertQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.InsertQuery).filter(labelQueryOutput(_) == QueryLabel.SafeQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.InsertQuery).filter(labelQueryInput(_) == QueryLabel.SafeQuery).size)
        println("Update: \t" + queries.filter(_.queryType == QueryType.UpdateQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.UpdateQuery).filter(labelQueryOutput(_) == QueryLabel.SafeQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.UpdateQuery).filter(labelQueryInput(_) == QueryLabel.SafeQuery).size)
        println("Other: \t\t" + queries.filter(_.queryType == QueryType.OtherQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.OtherQuery).filter(labelQueryOutput(_) == QueryLabel.SafeQuery).size + "\t\t|\t" + queries.filter(_.queryType == QueryType.OtherQuery).filter(labelQueryInput(_) == QueryLabel.SafeQuery).size)
        println("Total: \t\t" + queries.size + "\t\t|\t" + queries.filter(labelQueryOutput(_) == QueryLabel.SafeQuery).size + "\t\t|\t" + queries.filter(labelQueryInput(_) == QueryLabel.SafeQuery).size)
        // println("Safe queries: " + queries.filter(labelQueryOutput(_) == QueryLabel.SafeQuery).size)
        println("Unsafe database columns: " + queries.map(getUnsafeColumnOutput(_)).flatten.dedup.l.size + " out of " + list_schema.size)
    }
}