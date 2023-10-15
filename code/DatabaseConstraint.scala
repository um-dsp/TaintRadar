import com.github.tototoshi.csv._ 

class DatabaseConstraint(val cpg: Cpg) {
    implicit val resolver: ICallResolver = NoResolve
    val dbCalls = cpg.call.filter(x => Constants.sqli_sink.map(x.name.contains(_)).reduce((x,y) => x || y)).l

    def getQuery(node: AstNode, output: List[AstNode] = List(), depth: Int = 0): List[AstNode] = {
        val newOutput = output.dedup.l
        if (depth > 10) newOutput
        else node match {
            case function: nodes.Call => {
                if (function.name == "<operator>.concat") newOutput :+ function
                else function.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(List()).dedup.l
            }
            case identifier: Identifier => {
                identifier.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(List()).dedup.l
            }
            case literal: Literal => newOutput :+ literal
            case parameter: MethodParameterIn => newOutput
            case _ => {
                println(node)
                newOutput
            }
        }
    }

    def getQueryType(List[AstNode])

    val queries = Some((sinks zip sinks.map(getQuery(_))).toMap[Call, List[AstNode]]) 
    val reader = CSVReader.open(new File("navex_utils/code/database.csv"))
    val reader_data: List[List[String]] = reader.all()
    val db_schema = scala.collection.mutable.Map[String, Map[String, Boolean]]()
    reader_data.map(row => db_schema(row.head) = db_schema.get(row.head).getOrElse(Map()) + (row(1) -> row(3).toBooleanOption.getOrElse(false)))

}