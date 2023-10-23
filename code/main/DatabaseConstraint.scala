import QueryClass._
import com.github.tototoshi.csv._

class DatabaseConstraint(val cpg: Cpg) {

    var getQueryMap = collection.mutable.Map[AstNode, DBQuery]()
    def getQuery(node: AstNode, output: DBQuery = DBQuery(), depth: Int = 0): DBQuery = {
        getQueryMap.get(node) match {
            case Some(queryData: DBQuery) => queryData
            case None => {
                val newOutput: DBQuery= output.dedup
                val result: DBQuery = if (depth > 15) newOutput
                else node match {
                    case function: nodes.Call => {
                        if (function.name == "<operator>.concat") {
                            // If concat operator already found
                            // if (newOutput.data.map(!_.isCallTo("<operator>.concat").isEmpty).contains(true)) newOutput
                            // else newOutput :+ function
                            function +: function.argument.filterNot(x => x.isLiteral || x.isIdentifier || !x.isCallTo("<operator>.concat").isEmpty || !x.isCallTo("encaps").isEmpty).l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
                        }
                        else if (function.name == "encaps") newOutput
                        else function.argument.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
                    }
                    case identifier: Identifier => {
                        identifier.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup :+ identifier
                    }
                    case literal: Literal => newOutput :+ literal
                    case parameter: MethodParameterIn => newOutput
                    case constant: FieldIdentifier => {
                    if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) newOutput
                    else constantTable.get(constant.canonicalName).map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
                    }
                    case block: Block => block.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
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

    def labelQuery(query: DBQuery, schema: scala.collection.mutable.Map[String, Map[String, Boolean]]): QueryLabel.Value = {
        val tables: List[String] = schema.keys.toList
        query.getQueryType() match {
            case QueryType.OtherQuery => QueryLabel.SafeQuery
            case QueryType.SelectQuery => {
                val queryCode = query.getQueryCode
                val queryScope = queryCode.dropWhile(_.toLowerCase() != "select").drop(1).takeWhile(_.toLowerCase() != "from")
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "from").drop(1).takeWhile(_.toLowerCase() != "where")
                val queryTableName = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).headOption.getOrElse("NA")
                if (queryTableName == "NA") {
                    println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                val queryColumns = schema(queryTableName) 
                val unsafeColumns = schema(queryTableName).filterNot(_._2).keys.toList
                // for (scope <- queryScope) {
                //     if (scope == "*") val unsafeScope = unsafeColumns
                //     else if (!safeSQLFunctions.exists(scope.contains(_)) && unsafeColumns.exists(scope.contains(_))) {
                //         val unsafeScope = unsafeColumns.map(scope.contains(_)).zipWithIndex.filter(_._1==true).map(_._2).collect(unsafeColumns(_))
                //     }
                // }
                if (queryScope.map(scope => (scope == "*" && !unsafeColumns.isEmpty) || (!safeSQLFunctions.exists(scope.contains(_)) && unsafeColumns.exists(scope.contains(_)))).contains(true))
                    QueryLabel.UnsafeQuery
                else QueryLabel.SafeQuery
                }
            }
            case QueryType.InsertQuery => {
                val queryCode = query.getQueryCode
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "into").drop(1).takeWhile(!_.toLowerCase().contains("values"))
                val queryValues = queryCode.dropWhile(!_.toLowerCase().contains("values")).drop(1).takeWhile(_.toLowerCase() != "where")
                val queryTableName = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).headOption.getOrElse("NA")
                if (queryTableName == "NA") {
                    println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                val queryColumns = schema(queryTableName) 
                val unsafeColumns = schema(queryTableName).filterNot(_._2).keys.toList
                if (unsafeColumns.isEmpty)
                    QueryLabel.SafeQuery
                else QueryLabel.UnsafeQuery
                }
            }
            case QueryType.UpdateQuery => {
                val queryCode = query.getQueryCode
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "update").drop(1).takeWhile(_.toLowerCase() != "set")
                val queryValues = queryCode.dropWhile(_.toLowerCase() != "set").drop(1).takeWhile(_.toLowerCase() != "where")
                val queryTableName = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).headOption.getOrElse("NA")
                if (queryTableName == "NA") {
                    println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                val queryColumns = schema(queryTableName) 
                val unsafeColumns = schema(queryTableName).filterNot(_._2).keys.toList
                if (unsafeColumns.isEmpty)
                    QueryLabel.SafeQuery
                else QueryLabel.UnsafeQuery
                }
            }
            case _ => {
                // println("Exception")
                QueryLabel.UnsafeQuery
            }
        }
    }

    val databaseCalls = cpg.call.filter(x => Constants.sqli_sink.map(x.name.contains(_)).reduce((x,y) => x || y)).l
    val queries = databaseCalls.map(getQuery(_))
    val sinkToQueries = Some((databaseCalls zip queries).toMap[nodes.Call, DBQuery]) 

    val reader = CSVReader.open("navex_utils/code/database.csv")
    val reader_data: List[List[String]] = reader.all()
    val db_schema = scala.collection.mutable.Map[String, Map[String, Boolean]]()
    reader_data.map(row => db_schema(row.head) = db_schema.get(row.head).getOrElse(Map()) + (row(1) -> row(3).toBooleanOption.getOrElse(false)))

    queries.map(labelQuery(_, db_schema))
}