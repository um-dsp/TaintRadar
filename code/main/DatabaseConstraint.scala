import com.github.tototoshi.csv._

class DatabaseConstraint(val cpg: Cpg) {
    val sanitizationObject = new SanitizationFilter(cpg)
    implicit val vulnerabilityInst: sanitizationObject.vulnerabilityType = sanitizationObject.vulnerabilityType("XSS", Constants.san_functions_xss)
    val removeChars = Set(',', '"', '\\', '`', '\'')
    val calculationPattern = "\\s*([-+=/*><!])\\s*".r

    val queryObject = new Query(cpg)
    val databaseCalls: List[nodes.Call] = cpg.call.filter(x => Constants.sqli_sink.map(x.name.contains(_)).reduce((x,y) => x || y)).l
    val file_name = cpg.metaData.root.head.split("/").last
    val reader = CSVReader.open("navex_utils/code/db/" + file_name + "-database.csv")
    val reader_data: List[List[String]] = reader.all()
    val list_schema = reader_data.map(ls => List(ls(0), ls(1), ls(3))) 
    val db_schema = scala.collection.mutable.Map[String, Map[String, Boolean]]()
    reader_data.map(row => db_schema(row.head) = db_schema.get(row.head).getOrElse(Map()) + (row(1) -> row(3).toBooleanOption.getOrElse(false)))

    var getQueryMap = collection.mutable.Map[AstNode, queryObject.DBQuery]()
    def getQuery(node: AstNode, output: queryObject.DBQuery = queryObject.DBQuery(), depth: Int = 0): queryObject.DBQuery = {
        getQueryMap.get(node) match {
            case Some(queryData: queryObject.DBQuery) => queryData
            case None => {
                val newOutput: queryObject.DBQuery= output.dedup()
                val result: queryObject.DBQuery = if (depth > 15) newOutput
                else node match {
                    case function: nodes.Call => {
                        if (function.name == "<operator>.concat") {
                            // If concat operator already found
                            function +: function.argument.filterNot(x => x.isLiteral || x.isIdentifier || !x.isCallTo("<operator>.concat").isEmpty || !x.isCallTo("encaps").isEmpty).l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(queryObject.DBQuery()).dedup()
                        }
                        else if (function.name == "encaps") newOutput
                        else function.argument.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(queryObject.DBQuery()).dedup()
                    }
                    case identifier: Identifier => {
                        identifier.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(queryObject.DBQuery()).dedup() :+ identifier
                    }
                    case literal: Literal => newOutput :+ literal
                    case parameter: MethodParameterIn => newOutput
                    case constant: FieldIdentifier => {
                        if (queryObject.magic_constants.contains(constant) || queryObject.constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) newOutput
                        else queryObject.constantTable.get(constant.canonicalName).map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(queryObject.DBQuery()).dedup()
                    }
                    case block: Block => block.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(queryObject.DBQuery()).dedup()
                    case typeRef: TypeRef => newOutput
                    case _ => {
                        println(node)
                        newOutput
                    }
                }
                getQueryMap(node) = result
                result
            }
        }
    }

    def labelQuery(query: queryObject.DBQuery): queryObject.QueryLabel.Value = {
        // println(query)
        val tables: List[String] = db_schema.keys.toList
        query.getQueryType() match {
            case queryObject.QueryType.OtherQuery => queryObject.QueryLabel.SafeQuery
            case queryObject.QueryType.SelectQuery => {
                val queryCode = query.getQueryCode().map(_.filter(!removeChars.contains(_)))
                val queryScope = queryCode.dropWhile(_.toLowerCase() != "select").drop(1).takeWhile(_.toLowerCase() != "from")
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "from").drop(1).takeWhile(_.toLowerCase() != "where")
                val queryTableName = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).headOption.getOrElse("NA")
                if (queryTableName == "NA") {
                    // println(query)
                    queryObject.QueryLabel.UnsafeQuery
                }
                else {
                val queryColumns = db_schema(queryTableName) 
                val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                if (queryScope.map(scope => (scope == "*" && !unsafeColumns.isEmpty) || (!queryObject.safeSQLFunctions.exists(scope.contains(_)) && unsafeColumns.exists(scope.contains(_)))).contains(true))
                    queryObject.QueryLabel.UnsafeQuery
                else queryObject.QueryLabel.SafeQuery
                }
            }
            case queryObject.QueryType.InsertQuery => {
                val queryCode = query.getQueryCode().mkString(" ").replace("values(", "values ( ").split(" ")
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "into").drop(1).takeWhile(!_.toLowerCase().contains("values"))
                val queryValues = queryCode.dropWhile(!_.toLowerCase().contains("values")).drop(1).takeWhile(token => !token.toLowerCase().contains(";") && token.toLowerCase!="where")
                val queryTableNames = tables.map(x => queryTable.map(_.filter(!removeChars.contains(_))).exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).l
                if (queryTableNames.isEmpty) {
                    // Unable to find a matching table from the query
                    // println(query)
                    queryObject.QueryLabel.UnsafeQuery
                }
                else {
                    val queryTableName = {
                        if (queryTableNames.size == 1) queryTableNames(0)
                        else {
                            val tableColumns = queryTableNames.map(db_schema.get(_).get.keys)
                            // get most likely table
                            val mostLikelyIndex = tableColumns.map(_.toList.map(s => queryCode.exists({
                                val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                                regex.findFirstIn(_).isDefined}))).map(_.filter(_==true).size).zipWithIndex.maxBy(_._1)._2 
                            queryTableNames(mostLikelyIndex)
                        }
                    }
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
                        queryObject.QueryLabel.SafeQuery
                    else {
                        val valuesParsed =  calculationPattern.replaceAllIn(queryValues.mkString(" "), matchResult => "CALC_SPACE" + matchResult.group(1) + "CALC_SPACE").split(" ").filter(_.exists(_.isLetterOrDigit)).toList
                        if (valuesParsed.size < sortedColumns.size) queryObject.QueryLabel.UnsafeQuery
                        else {
                            val unsafeIndices = unsafeColumns.map(sortedColumns.indexOf(_))
                            val unsafeNodes = unsafeIndices.map(valuesParsed.lift(_).getOrElse("").replace("CALC_SPACE", " ")).map(query.searchNodeFromQuery(_)).filterNot(_==None)                         
                            if (unsafeNodes.map(sanitizationObject.isSanitized(_)).contains(false))
                                queryObject.QueryLabel.UnsafeQuery
                            else queryObject.QueryLabel.SafeQuery
                        }
                    }
                }
            }
            case queryObject.QueryType.UpdateQuery => {
                val queryCode = query.getQueryCode()
                val queryTable = queryCode.map(_.filter(!removeChars.contains(_))).dropWhile(_.toLowerCase() != "update").drop(1).takeWhile(_.toLowerCase() != "set")
                val queryValues = queryCode.dropWhile(_.toLowerCase() != "set").drop(1).takeWhile(token => !token.toLowerCase().contains(";") && token.toLowerCase!="where")
                val queryTableNames = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).l
                if (queryTableNames.isEmpty) {
                    // Unable to find a matching table from the query
                    // println(query)
                    queryObject.QueryLabel.UnsafeQuery
                }
                else {
                    val queryTableName = {
                        if (queryTableNames.size == 1) queryTableNames(0)
                        else {
                            val tableColumns = queryTableNames.map(db_schema.get(_).get.keys)
                            // get most likely table
                            val mostLikelyIndex = tableColumns.map(_.toList.map(s => queryCode.exists({
                                val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                                regex.findFirstIn(_).isDefined}))).map(_.filter(_==true).size).zipWithIndex.maxBy(_._1)._2 
                            queryTableNames(mostLikelyIndex)
                        }
                    }
                    val queryColumns = db_schema(queryTableName) 
                    val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                    val setValuesUnsafe = unsafeColumns.map(s => queryValues.exists({
                            val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                            regex.findFirstIn(_).isDefined}))
                    if (unsafeColumns.isEmpty || !setValuesUnsafe.contains(true))
                        queryObject.QueryLabel.SafeQuery
                    else {
                        val valuesParsed =  calculationPattern.replaceAllIn(queryValues.map(_.filter(!removeChars.contains(_))).filterNot(_.isEmpty).mkString(" "), matchResult => matchResult.group(1)).split(" ").filter(_.exists(_.isLetterOrDigit)).toList
                        val unsafeValues = valuesParsed.filter(token => unsafeColumns.contains(token.split("=")(0)))
                        val unsafeNodes = unsafeValues.map(_.split("=").lift(1).getOrElse("")).map(query.searchNodeFromQuery(_)) 
                        if (unsafeNodes.map(sanitizationObject.isSanitized(_)).contains(false))
                            queryObject.QueryLabel.UnsafeQuery
                        else queryObject.QueryLabel.SafeQuery
                    }
                }
            }
            case _ => {
                queryObject.QueryLabel.UnsafeQuery
            }
        }
    }

    def filterPath(path: List[AstNode]): Boolean = {
        val safeDbCalls: List[nodes.Call] = cpg.call.filter(x => Constants.sql_func.map(x.name.contains(_)).reduce((x,y) => x || y)).l.filterNot(element => databaseCalls.contains(element))
        val queries = path.filter(databaseCalls.contains).map(getQuery(_))
        queries.map(labelQuery(_)).contains(queryObject.QueryLabel.SafeQuery) || !path.filter(safeDbCalls.contains).isEmpty
    }

    val queries = databaseCalls.map(x => getQuery(x))
    queries.map(_.getQueryCode().mkString(" ")).size
    queries.map(_.getQueryCode().mkString(" ")).dedup.size
}