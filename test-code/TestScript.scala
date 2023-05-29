import Constants._
import SanitizationFilter._

@main def exec(cpgFile: String, outFile: String) = {
    implicit val attack_san_functions: List[String] = Constants.san_functions_sql
    importCpg(cpgFile)
    SanitizationFilter.setCpg(cpg)
    cpg.method("<global>").ast.filter(SanitizationFilter.isSanitized(_)).newTagNodePair("SAN", "TRUE").store
    cpg.method("<global>").ast.filterNot(SanitizationFilter.isSanitized(_)).newTagNodePair("SAN", "FALSE").store
    run.commit
    cpg.method("<global>").ast.map(node => List(node.id, node.tag.name("SAN").value.head)).l |> outFile
    val dotAst: String = cpg.method("<global>").dotAst.head
    dotAst |> outFile
}


// sink.reachableByFlows(source).map(node => {
//     List(List(node.elements.head.file.name.l.head + ":" + node.elements.head.lineNumber.getOrElse(""), node.elements.head.code),
//     List(node.elements.last.file.name.l.head + ":" + node.elements.last.lineNumber.getOrElse(""), node.elements.last.code))
//  }).toJsonPretty |> "../test-apps/output" 