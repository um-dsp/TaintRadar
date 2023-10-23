val sqlStartKeywords: Set[String] = Set("select", "insert", "update", "delete",
                    "create", "alter", "drop", "truncate",
                    "use", "show", "begin", "start transaction", "commit", "rollback")

val removeChars = Set(',', '"', '\\', '`')

val safeSQLFunctions = Set("count(", "sum(", "max(", "min(", "min(", "length(", "len(", "now(", "date(", 
                            "year(", "month(", "day(", "abs(", "round(", "ceil(", "ceiling(", "floor(", 
                            "if(", "rank(", "dense_rank(", "row_number(")

val magic_constants: List[String] = List("__LINE__, __FILE__, __DIR__, __FUNCTION__, __CLASS__, __TRAIT__, __METHOD__, __NAMESPACE__")
val constants: List[String] = cpg.call("define").argument(1).code.l.map(_.replace("\"", "")).distinct
val values: List[List[AstNode]] = constants.map(constant => cpg.call("define").filter(_.argument(1).code.replace("\"", "") == constant).argument(2).l) 
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

def getCode(node: AstNode, output: String = ""): String = {
    node match {
        case literal: Literal => output + literal.code
        case identifier: Identifier => output + identifier.code
        case call: nodes.Call => {
            if (call.name == "<operator>.concat" || call.name == "encaps") call.argument.l.map(getCode(_, output)).mkString(" ")
            else output + call.code
        }
        case constant: FieldIdentifier => {
            println("CONSTANT")
            if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) output
            else output + getCode(constantTable.get(constant.canonicalName).head)
            }
        case _ => {
            println(node)
            " "
        }
    }
}

case class DBQuery(data: List[AstNode] = List()) {
    def ++(that: DBQuery): DBQuery = DBQuery(data ++ that.data)
    def ==(that: DBQuery): Boolean = data == that.data
    def dedup(): DBQuery = DBQuery(data.dedup.l)
    def :+(that: AstNode): DBQuery = DBQuery(data :+ that)
    def +:(that: AstNode): DBQuery = DBQuery(that +: data)
    def order(): DBQuery = DBQuery(data.sorted(Ordering.by[AstNode, Long](_.id)) )

    def getQueryCode(): Array[String] = {
        val rawCode = this.data.filterNot(_.isIdentifier).map(getCode(_)).mkString(" ")
        val queryCode = rawCode.replaceAll("""(\w)\*""", "$1 *").split(" ").
                                map(_.replace("\\n", " ").replace("\\t", " ")).flatMap(_.split(" ")).flatMap(_.split(",")).
                                map(_.filter(!removeChars.contains(_))).filterNot(_.isEmpty).
                                mkString(" ").replace("encaps", encapsCode.mkString(" ")) .split(" ")
        val queryIndices: Array[Int] = queryCode.zipWithIndex.collect(x => if (sqlStartKeywords.contains(x._1.toLowerCase())) x._2 else -1).filter(_>=0)
        if (queryIndices.size >= 2) queryCode.slice(queryIndices.head, queryIndices.tail.head)
        else queryCode
    }

    def getQueryType(): QueryType.Value = {
        val queryCode = this.getQueryCode.map(_.toLowerCase()) 
        if (queryCode.contains("insert")) QueryType.InsertQuery
        else if (queryCode.contains("update")) QueryType.UpdateQuery
        else if (queryCode.contains("select")) QueryType.SelectQuery
        else QueryType.OtherQuery
    }
}