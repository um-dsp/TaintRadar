import org.simmetrics.StringMetric
import org.simmetrics.metrics.StringMetrics

val sqlStartKeywords: Set[String] = Set("select", "insert", "update", "delete",
                    "create", "alter", "drop", "truncate",
                    "use", "show", "begin", "start transaction", "commit", "rollback")

val removeChars = Set(',', '"', '\\', '`', '\'')

val safeSQLFunctions = Set("count(", "sum(", "max(", "min(", "min(", "length(", "len(", "now(", "date(", 
                            "year(", "month(", "day(", "abs(", "round(", "ceil(", "ceiling(", "floor(", 
                            "if(", "rank(", "dense_rank(", "row_number(")

val metric: StringMetric = StringMetrics.levenshtein

var getNodeDataMap = collection.mutable.Map[AstNode, List[AstNode]]()

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

def searchNode(queryRoot: AstNode, code: String): Option[AstNode] = {
    queryRoot match {
        case literal: Literal => {
            if (metric.compare(literal.code, code) > 0.8F) Some(literal)
            else None
        }
        case identifier: Identifier => {
            if (metric.compare(identifier.code, code) > 0.8F) Some(identifier)
            else None
        }
        case call: nodes.Call => {
            if (metric.compare(call.code, code) > 0.8F) Some(call)
            else  call.argument.l.map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
        }
        case constant: FieldIdentifier => {
            if (metric.compare(constant.code, code) > 0.8F) Some(constant)
            else if (magic_constants.contains(constant.canonicalName) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) None
            else constantTable.get(constant.canonicalName).map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
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
            else output + call.code
        }
        case constant: FieldIdentifier => {
            if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) output
            else output + getCode(constantTable.get(constant.canonicalName).head)
            }
        case _ => {
            println(node)
            " "
        }
    }
}

def getNodeData(node: AstNode, depth: Int = 0): List[AstNode] = {
    getNodeDataMap.get(node) match {
        case Some(queryData: List[AstNode]) => queryData
        case None => {
            val result: List[AstNode] = if (depth > 1000) List()
            else node match {
                case function: nodes.Call => {
                    if (function.name == "<operator>.concat" || function.name == "encaps") {
                        // If concat operator already found
                        List(function)
                    }
                    // else if (function.name == "encaps") newOutput
                    else function.argument.l.map(getNodeData(_, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(List()).dedup.l
                }
                case identifier: Identifier => {
                    identifier.ddgIn.l.map(getNodeData(_, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(List()).dedup.l 
                }
                case literal: Literal => List(literal)
                case parameter: MethodParameterIn => List()
                case constant: FieldIdentifier => {
                    if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) List()
                    else constantTable.get(constant.canonicalName).map(getNodeData(_, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(List()).dedup.l
                }
                case block: Block => block.ddgIn.l.map(getNodeData(_, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(List()).dedup.l
                case typeRef: TypeRef => List()
                case _ => {
                    println(node)
                    List()
                }
            }
            getNodeDataMap(node) = result
            result
        }
    }
}

case class DBQuery(callNode: nodes.Call) {
    val data: List[AstNode] = getNodeData(this.callNode)
    val queryType: QueryType.Value = this.getQueryType()
    val queryCode: Array[String] = this.getQueryCode()

    def ++(that: DBQuery): List[AstNode] = this.data ++ that.data
    def ==(that: DBQuery): Boolean = this.data == that.data
    def dedup: List[AstNode] = this.data.dedup.l
    def :+(that: AstNode): List[AstNode] = this.data :+ that
    def +:(that: AstNode): List[AstNode] = that +: this.data
    def order(): List[AstNode] = this.data.sorted(Ordering.by[AstNode, Long](_.id))

    def getQueryCode(): Array[String] = {
        val rawCode = this.data.filterNot(_.isIdentifier).map(getCode(_)).mkString(" ")
        val queryCode = rawCode.replaceAll("""(\w)\*""", "$1 *").split(" ").
                                map(_.replace("\\n", " ").replace("\\t", " ")).flatMap(_.split(" ")).flatMap(_.split(",")).
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
    
    def searchNodeFromQuery(code: String): Option[AstNode] = {
        this.data.map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
    }
}