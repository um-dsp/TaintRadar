import com.github.tototoshi.csv._

class DatabaseConstraint(val cpg: Cpg) {
    val sanitizationObject = new SanitizationFilter(cpg)
    implicit val vulnerabilityInst: sanitizationObject.vulnerabilityType = sanitizationObject.vulnerabilityType("XSS", Constants.san_functions_xss)
    val removeChars = Set(',', '"', '\\', '`', '\'')
    val calculationPattern = "\\s*([-+=/*><!()])\\s*".r
    val parenthesisPattern = "\\([^)]*\\)".r

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

    def getQueryCodeAndScope(query: DBQuery): (Array[String], Array[String]) = {
        query.queryType match {
            case QueryType.OtherQuery => (Array(), Array())
            case QueryType.SelectQuery => {   
                val queryCode = query.queryCode.map(_.toLowerCase)
                val queryScope = queryCode.dropWhile(_ != "select").drop(1).takeWhile(_ != "from")
                (queryCode, queryScope)
            }
            case QueryType.InsertQuery => {
                val queryCode = query.queryCode.mkString(" ").toLowerCase.replace("values(", "values ( ").split(" ")
                val queryScope = queryCode.dropWhile(_ != "into").drop(1).takeWhile(!_.contains("values")).map(_.replace("(", " ( ").replace(")", " ) ")).mkString(" ").split(" ").filterNot(_.isEmpty)
                (queryCode, queryScope)
            }
            case QueryType.UpdateQuery => {
                val queryCode = query.queryCode.map(_.toLowerCase)
                val queryValues = queryCode.dropWhile(_ != "set").drop(1).takeWhile(token => !token.contains(";") && token.toLowerCase!="where")
                (queryCode, queryValues)
            }
        }
    }

    def parseQuery(query: DBQuery): (String, List[String], List[String]) = {
        query.queryType match {
            case QueryType.OtherQuery => ("NA", List(), List())
            case QueryType.SelectQuery => {
                    val (queryCode, queryScope) = getQueryCodeAndScope(query)

                    val queryTable = queryCode.dropWhile(_ != "from").drop(1).takeWhile(_ != "where")
                    val tableDistances = tables.map(db_table => queryTable.map(metric.compare(db_table, _))).flatten.l
                    val closestTable = if (tableDistances.max < 0.2) "NA" else tables(tableDistances.indexOf(tableDistances.max)/queryTable.size)

                    val scopeWithoutAlias = queryScope.sliding(2).filterNot(_(0) == "as").flatten.filterNot(_ == "as").l
                    val removeFuncHash = Constants.sql_builtin_function.map(fun => scopeWithoutAlias.map(s=> s.replace(fun.toLowerCase+"(","").filter(_.isLetterOrDigit)).l)
                    val scopeWithoutFunc = scopeWithoutAlias.indices.map(i => removeFuncHash.map(_(i)).reduce((x,y) => if (x.length < y.length) x else y)).toList
                    val dbColumns = list_schema.filter(_(0) == closestTable).map(_(1))
                    val queryColumns = if (queryScope.contains("*")) dbColumns else scopeWithoutFunc

                    val queryCond = query.queryCode.dropWhile(_.toLowerCase() != "where").drop(1)
                    val condCodes = queryCond.map(query.searchNodeFromQuery(_)).filterNot(_ == None).map(_.get.code).toList
                    // val condCode = condNodes.map(_.code).mkString("; ")
                    (closestTable, queryColumns.dedup.l, condCodes.dedup.l)
                }
            case QueryType.InsertQuery => {
                val (queryCode, queryScope) = getQueryCodeAndScope(query)
                
                val queryTable = parenthesisPattern.replaceAllIn(queryScope.mkString(" "), "").split(" ")
                val tableDistances = tables.map(db_table => queryTable.map(metric.compare(db_table, _))).flatten.l
                val closestTable = if (tableDistances.max < 0.3) "NA" else tables(tableDistances.indexOf(tableDistances.max)/queryTable.size)
                val sortedColumns: List[String] = {
                    if (queryScope.contains("("))
                        queryScope.dropWhile(!_.contains("(")).drop(1).takeWhile(!_.contains(")")).map(_.filterNot(_ == ',')).toList
                    else list_schema.filter(_(0) == closestTable).map(_(1))
                    } 
                
                val queryValues = queryCode.dropWhile(!_.contains("values")).drop(1).takeWhile(token => !token.contains(";") && token.toLowerCase!="where")
                val valueCodes = queryValues.map(query.searchNodeFromQuery(_)).filterNot(_ == None).map(_.get.code).toList

                (closestTable, sortedColumns.dedup.l, valueCodes.dedup.l)
                }
            case QueryType.UpdateQuery => {
                val (queryCode, queryValues) = getQueryCodeAndScope(query)

                val queryTable = queryCode.dropWhile(_ != "update").drop(1).takeWhile(_ != "set")
                val tableDistances = tables.map(db_table => queryTable.map(metric.compare(db_table, _))).flatten.l
                val closestTable = if (tableDistances.max < 0.3) "NA" else tables(tableDistances.indexOf(tableDistances.max)/queryTable.size)
                
                val valuesParsed =  queryValues.mkString(" ").replace("=", " = ").split(" ").filterNot(_.isEmpty)
                val potentialCol = valuesParsed.sliding(2).filter(_(1)=="=").map(_(0)).l
                val colInd = potentialCol.indices
                val dbColumns = list_schema.filter(_(0) == closestTable).map(_(1))
                val closestColMetric = colInd.map(i => dbColumns.map(col => potentialCol.map(metric.compare(col, _))).map(_(i)))
                val queryColumns = closestColMetric.map(x => x.indexOf(x.maxOption.getOrElse(-1))).map(dbColumns.lift(_).getOrElse("")).toList

                val valueCodes = queryValues.map(query.searchNodeFromQuery(_)).filterNot(_ == None).map(_.get.code).toList

                (closestTable, queryColumns.dedup.l, valueCodes.dedup.l)
                }
            case _ => ("NA", List(), List())
        }
    }

    def getUnsafeColumn(query: DBQuery): List[(String, String)] = {
        query.queryType match {
            case QueryType.OtherQuery => List()
            case QueryType.SelectQuery => {
                val (queryTable, queryColumns, condCodes) = parseQuery(query)
                if (queryTable == "NA") {
                    // println(query)
                    List()
                }
                else {
                    val unsafeColumns = db_schema(queryTable).filterNot(_._2).keys.toList
                    queryColumns.filter(unsafeColumns.contains(_)).toList.map((queryTable, _))
                }
            }
            case QueryType.InsertQuery => {
                val (queryTable, queryColumns, condCodes) = parseQuery(query)
                if (queryTable == "NA") List()
                else {
                    val unsafeColumns = db_schema(queryTable).filterNot(_._2).keys.toList
                    queryColumns.filter(unsafeColumns.contains(_)).toList.map((queryTable, _))
                }
            }
            case QueryType.UpdateQuery => {
                val (queryTable, queryColumns, condCodes) = parseQuery(query)
                if (queryTable == "NA") List()
                else {
                    val unsafeColumns = db_schema(queryTable).filterNot(_._2).keys.toList
                    queryColumns.filter(unsafeColumns.contains(_)).toList.map((queryTable, _))
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
                val (queryTable, queryColumns, condCodes) = parseQuery(query)
                val queryScope = query.queryCode.map(_.toLowerCase).dropWhile(_ != "select").drop(1).takeWhile(_ != "from")
                val scopeWithoutAlias = queryScope.sliding(2).filterNot(_(0) == "as").flatten.filterNot(_ == "as").l
                if (queryTable == "NA") {
                    // queryTable(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                    val unsafeColumns = db_schema(queryTable).filterNot(_._2).keys.toList
                    if (scopeWithoutAlias.map(scope => (scope == "*" && !unsafeColumns.isEmpty) || (!safeSQLFunctions.exists(scope.contains(_)) && unsafeColumns.exists(scope.contains(_)))).contains(true))
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
                val (queryCode, queryScope) = getQueryCodeAndScope(query)
                val (queryTable, queryColumns, condCodes) = parseQuery(query)
                if (queryTable == "NA") {
                    QueryLabel.UnsafeQuery
                }
                else { 
                    val unsafeColumns = db_schema(queryTable).filterNot(_._2).keys.toList
                    val insertValuesUnsafe = unsafeColumns.map(s => queryColumns.exists({
                            val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                            regex.findFirstIn(_).isDefined}))
                    if (unsafeColumns.isEmpty || !insertValuesUnsafe.contains(true))
                        QueryLabel.SafeQuery
                    else {
                        val queryValues = queryCode.dropWhile(!_.contains("values")).drop(1).takeWhile(token => !token.contains(";") && token.toLowerCase!="where")
                        val parsedVal = queryValues.map(_.replace("(", " ( ").replace(")", " ) ")).mkString(" ").split(" ").filterNot(_.isEmpty)
                        val start = if (parsedVal.lift(0).getOrElse("") == "(") 1 else 0
                        val end = if (parsedVal.lift(parsedVal.size-1).getOrElse("") == ")") parsedVal.size-1 else parsedVal.size
                        val valuesParsed =  calculationPattern.replaceAllIn(parsedVal.slice(start, end).mkString(" "), matchResult => matchResult.group(1)).split(" ").filter(_.exists(_.isLetterOrDigit)).toList
                        if (valuesParsed.size != queryColumns.size) QueryLabel.UnsafeQuery
                        else {
                            val unsafeIndices = unsafeColumns.map(queryColumns.indexOf(_))
                            val unsafeNodes = unsafeIndices.map(valuesParsed.lift(_).getOrElse("")).map(query.searchNodeFromQuery(_, 0.7F)).filterNot(_==None)                         
                            if (unsafeNodes.map(sanitizationObject.isSanitized(_)).contains(false))
                                QueryLabel.UnsafeQuery
                            else QueryLabel.SafeQuery
                        }
                    }
                }
            }
            case QueryType.UpdateQuery => {
                val (queryCode, queryValues) = getQueryCodeAndScope(query)
                val (queryTable, queryColumns, condCodes) = parseQuery(query)
                if (queryTable == "NA") {
                    QueryLabel.UnsafeQuery
                }
                else {
                    val unsafeColumns = db_schema(queryTable).filterNot(_._2).keys.toList
                    val setValuesUnsafe = queryColumns.map(unsafeColumns.contains(_))
                    if (unsafeColumns.isEmpty || !setValuesUnsafe.contains(true))
                        QueryLabel.SafeQuery
                    else {
                        val queryValuesEqSign =  queryValues.mkString(" ").replace("=", " = ").split(" ").filterNot(_.isEmpty)
                        val valuesParsed = queryValuesEqSign.sliding(2).filter(_(0)=="=").map(_(1)).l
                        val valuesIndices = valuesParsed.indices.l
                        val unsafeNodes = valuesIndices.map(i => if (setValuesUnsafe.lift(i).getOrElse(false)) query.searchNodeFromQuery(valuesParsed.lift(i).getOrElse("")) else None)
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
    

    def debug() = {
        val typeAndCode = queries.map(query => query.queryType.toString + "; \"" + query.queryCode.mkString(" ") + "\"; " + parseQuery(query)(0) + "; \"" + parseQuery(query)(1) + "\"; \"" + parseQuery(query)(2) + "\"")
        typeAndCode #> "parsedQueries.csv"
        val selectUnsafe = queries.filter(_.queryType==QueryType.SelectQuery).map(getUnsafeColumn(_)).flatten.dedup.l
        val insertUnsafe = queries.filter(q => q.queryType==QueryType.InsertQuery || q.queryType == QueryType.UpdateQuery).map(getUnsafeColumn(_)).flatten.dedup.l
        insertUnsafe.map(selctUnsafe.contains(_)).size
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