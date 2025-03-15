import org.simmetrics.StringMetric
import org.simmetrics.metrics.StringMetrics

val sqlStartKeywords: Set[String] = Set("select", "insert", "update", "delete",
                    "create", "alter", "drop", "truncate",
                    "use", "show", "begin", "start transaction", "commit", "rollback")

val mainSqlKeywords: Set[String] = Set("select ", "select*", "insert into ", "insert ignore into ", "update ")

val removeChars = Set('"', '\\', '`', '\'')

val safeSQLFunctions = Set("count(", "sum(", "length(", "len(", "now(", "date(", 
                            "year(", "month(", "day(", "abs(", "round(", "ceil(", "ceiling(", "floor(", 
                            "if(", "rank(", "dense_rank(", "row_number(")

val metric: StringMetric = StringMetrics.levenshtein

val magic_constants: List[String] = Constants.magic_constants

val constants: List[String] = cpg.call(Constants.constant_definition_func).argument(1).code.l.map(_.replace("\"", "")).distinct
val values: List[List[AstNode]] = constants.map(constant => cpg.call(Constants.constant_definition_func).filter(_.argument(1).code.replace("\"", "") == constant).argument(2).l) 
val constantTable = Some((constants zip values).toMap[String, List[AstNode]]) 

object QueryType extends Enumeration {
    type QueryType = Value
    val SelectQuery = Value("SELECT")
    val InsertQuery = Value("INSERT")
    val UpdateQuery = Value("UPDATE")
    val OtherQuery = Value("OTHER")
}

object QueryLabel extends Enumeration {
    type QueryLabel = Value
    val SafeQuery = Value("SAFE")
    val UnsafeQuery = Value("UNSAFE")
}

def searchNode(queryRoot: AstNode, code: String, stringDist: Float): Option[AstNode] = {
    queryRoot match {
        case literal: Literal => {
            if (metric.compare(literal.code.toLowerCase(), code) > stringDist) Some(literal)
            else None
        }
        case identifier: Identifier => {
            if (metric.compare(identifier.code.toLowerCase(), code) > stringDist) Some(identifier)
            else None
        }
        case call: nodes.Call => {
            if (metric.compare(call.code.toLowerCase(), code) > stringDist) Some(call)
            else  call.argument.l.map(searchNode(_, code, stringDist)).filterNot(_ == None).headOption.getOrElse(None)
        }
        case constant: FieldIdentifier => {
            if (metric.compare(constant.code.toLowerCase(), code) > stringDist) Some(constant)
            else if (magic_constants.contains(constant.canonicalName) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) None
            else constantTable.get(constant.canonicalName).map(searchNode(_, code, stringDist)).filterNot(_ == None).headOption.getOrElse(None)
            }
        case _ => {
            None
        }
    }
}

def getCode(node: AstNode, output: String = ""): String = {
    node match {
        case literal: Literal => output + literal.code
        case identifier: Identifier => output + identifier.code
        case call: nodes.Call => {
            if (Constants.query_concat_func.contains(call.name)) call.argument.l.map(getCode(_, output)).mkString(" ")
            else if (call.name == "<operator>.fieldAccess") getCode(call.argument(2))
            else output + call.code
        }
        case constant: FieldIdentifier => {
            if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) output + constant.code
            else if (constantTable.get(constant.canonicalName).head.isCall) output + constantTable.get(constant.canonicalName).head.isCallTo(".*").argument.filterNot(_.isIdentifier).l.map(getCode(_)).mkString(" ")
            else output + getCode(constantTable.get(constant.canonicalName).head)
            }
        case _ => {
            println(node)
            " "
        }
    }
}

case class DBQuery(sqlCodeNode: nodes.Call) {
    // val sqlCodeNode: List[AstNode] = getSqlCodeNode(this.callNode)
    val queryType: QueryType.Value = this.getQueryType()
    val queryCode: Array[String] = this.getQueryCode()

    def ==(that: DBQuery): Boolean = this.sqlCodeNode == that.sqlCodeNode

    def getQueryCode(): Array[String] = {
        val rawCode = getCode(this.sqlCodeNode)
        val queryCode = rawCode.replaceAll("""(\w)\*""", "$1 *").split(" ").
                                map(_.replace("\\n", " ").replace("\\t", " ").replace(",", ", ")).flatMap(_.split(" ")).
                                flatMap(_.filterNot(removeChars.contains(_)).split(" ").filterNot(_.isEmpty))
        queryCode
    }

    def getQueryType(): QueryType.Value = {
        val queryCode = this.getQueryCode().map(_.toLowerCase()).map(_.filter(!removeChars.contains(_)))
        if (queryCode.contains("insert")) QueryType.InsertQuery
        else if (queryCode.contains("update")) QueryType.UpdateQuery
        else if (queryCode.contains("select")) QueryType.SelectQuery
        else QueryType.OtherQuery
    }
    
    def searchNodeFromQuery(code: String, stringDist: Float = 0.8): Option[AstNode] = {
        this.sqlCodeNode.map(searchNode(_, code, stringDist)).filterNot(_ == None).headOption.getOrElse(None)
    }
}