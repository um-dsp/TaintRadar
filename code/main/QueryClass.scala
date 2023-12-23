import org.simmetrics.StringMetric
import org.simmetrics.metrics.StringMetrics

val sqlStartKeywords: Set[String] = Set("select", "insert", "update", "delete",
                    "create", "alter", "drop", "truncate",
                    "use", "show", "begin", "start transaction", "commit", "rollback")

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
            println(queryRoot)
            None
            // cpg.method.ast.filter(_.code == code).map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
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
            if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) output
            else if (constantTable.get(constant.canonicalName).head.isCall) output + constantTable.get(constant.canonicalName).head.isCallTo(".*").argument.filterNot(_.isIdentifier).l.map(getCode(_)).mkString(" ")
            else output + getCode(constantTable.get(constant.canonicalName).head)
            }
        case _ => {
            println(node)
            " "
        }
    }
}

var dataFlowStepMap = collection.mutable.Map[AstNode, List[AstNode]]()
var removeObjects: List[AstNode] = List()
def dataFlowStep(node: AstNode): List[AstNode] = {
    dataFlowStepMap.get(node) match {
        case Some(queryData: List[AstNode]) => queryData
        case None => {
            val result = {
                node match {
                    case function: nodes.Call => {
                        if (function.dispatchType == "DYNAMIC_DISPATCH") {
                            removeObjects = removeObjects :+ function.argument(0)
                            function.argument.drop(1).dedup.l
                        }
                        else function.argument.dedup.l
                    }
                    case identifier: Identifier => {
                        identifier.ddgIn.dedup.l 
                    }
                    case literal: Literal => List(literal)
                    case parameter: MethodParameterIn => List()
                    case constant: FieldIdentifier => {
                        if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) List()
                        else constantTable.get(constant.canonicalName).dedup.l
                    }
                    case block: Block => block.ddgIn.dedup.l
                    case typeRef: TypeRef => List()
                    case _ => {
                        println(node)
                        List()
                    }
                }
            }
            dataFlowStepMap(node) = result.filterNot(removeObjects.contains(_))
            result.filterNot(removeObjects.contains(_))
        }
    }
}

def isSqlCode(node: AstNode): Boolean = {
    node match {
        case function: nodes.Call =>     
            if (Constants.query_concat_func.contains(function.name)) {
                sqlStartKeywords.map(function.code.toLowerCase.contains(_)).contains(true)
            }
            else false
        case _ => false
    }
}

def getSqlCodeNode(node: AstNode) : List[AstNode] = {
    var dataFlowNodes: List[AstNode] = dataFlowStep(node)
    var i = 0
    while (!dataFlowNodes.map(isSqlCode).contains(true) && i < 100) {
        dataFlowNodes = dataFlowNodes.map(dataFlowStep(_)).flatten.dedup.l
        i = i + 1
    }
    dataFlowNodes.filter(isSqlCode).dedup.l
}

case class DBQuery(callNode: nodes.Call) {
    val sqlCodeNode: List[AstNode] = getSqlCodeNode(this.callNode)
    val queryType: QueryType.Value = this.getQueryType()
    val queryCode: Array[String] = this.getQueryCode()

    def ++(that: DBQuery): List[AstNode] = this.sqlCodeNode ++ that.sqlCodeNode
    def ==(that: DBQuery): Boolean = this.sqlCodeNode == that.sqlCodeNode
    def dedup: List[AstNode] = this.sqlCodeNode.dedup.l
    def :+(that: AstNode): List[AstNode] = this.sqlCodeNode :+ that
    def +:(that: AstNode): List[AstNode] = that +: this.sqlCodeNode
    def order(): List[AstNode] = this.sqlCodeNode.sorted(Ordering.by[AstNode, Long](_.id))

    def getQueryCode(): Array[String] = {
        val rawCode = this.sqlCodeNode.filterNot(_.isIdentifier).map(getCode(_)).mkString(" ")
        val queryCode = rawCode.replaceAll("""(\w)\*""", "$1 *").split(" ").
                                map(_.replace("\\n", " ").replace("\\t", " ").replace(",", ", ")).flatMap(_.split(" ")).
                                flatMap(_.filterNot(removeChars.contains(_)).split(" ").filterNot(_.isEmpty))
        val queryIndices: Array[Int] = queryCode.zipWithIndex.collect(x => if (sqlStartKeywords.contains(x._1.toLowerCase().filter(!removeChars.contains(_)))) x._2 else -1).filter(_>=0)
        if (queryIndices.size >= 2) queryCode.slice(queryIndices.head, queryIndices.tail.head)
        else queryCode
    }

    def getQueryType(): QueryType.Value = {
        if (!Constants.sqli_sink.contains(callNode.name)) QueryType.OtherQuery
        else{
            val queryCode = this.getQueryCode().map(_.toLowerCase()).map(_.filter(!removeChars.contains(_)))
            if (queryCode.contains("insert")) QueryType.InsertQuery
            else if (queryCode.contains("update")) QueryType.UpdateQuery
            else if (queryCode.contains("select")) QueryType.SelectQuery
            else QueryType.OtherQuery
        }
    }
    
    def searchNodeFromQuery(code: String, stringDist: Float = 0.8): Option[AstNode] = {
        this.sqlCodeNode.map(searchNode(_, code, stringDist)).filterNot(_ == None).headOption.getOrElse(None)
    }
}