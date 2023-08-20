import Constants._
import SanitizationFilter._

@main def exec(cpgFile: String, fileMain: String) = { //, outFile: String) = {
    implicit val vuln: vulnerabilityType = vulnerabilityType("SQLi", Constants.san_functions_sql)
    importCpg(cpgFile)
    SanitizationFilter.setCpg(cpg)
    println(cpg.method.fullName.l)
    // val fileMain = "identifier_basic_san.php:<global>"
    // val fileMain = "identifier_basic_unsan.php:<global>"
    // val fileMain = "method.php:<global>"
    cpg.method.filter(_.fullName==fileMain).ast.filterNot(node => node.isInstanceOf[Modifier] || node.isInstanceOf[TypeDecl]).filter(SanitizationFilter.isSanitized(_)).newTagNodePair("SAN", "TRUE").store
    cpg.method.filter(_.fullName==fileMain).ast.filterNot(node => node.isInstanceOf[Modifier] || node.isInstanceOf[TypeDecl]).filterNot(SanitizationFilter.isSanitized(_)).newTagNodePair("SAN", "FALSE").store
    
    run.commit
    cpg.method.filter(_.fullName==fileMain).ast.filterNot(_.isInstanceOf[Modifier]).map(node => List(node.id, node.tag.name("SAN").value.head)).l |> "output_graph/tags.txt"
    val dotAst: String = cpg.method.filter(_.fullName==fileMain).dotAst.head
    dotAst |> "output_graph/output.dot"
}


// sink.reachableByFlows(source).map(node => {
//     List(List(node.elements.head.file.name.l.head + ":" + node.elements.head.lineNumber.getOrElse(""), node.elements.head.code),
//     List(node.elements.last.file.name.l.head + ":" + node.elements.last.lineNumber.getOrElse(""), node.elements.last.code))
//  }).toJsonPretty |> "../test-apps/output" 