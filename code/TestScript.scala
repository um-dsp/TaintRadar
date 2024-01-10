import Constants._

@main def exec(cpgFile: String, fileMain: String) = { //, outFile: String) = {
    importCpg(cpgFile)
    val s = new SanitizationFilter(cpg)
    implicit val vuln= s.vulnerabilityType("XSS", Constants.san_functions_xss)
    println(cpg.method.fullName.l)
    cpg.method.filter(_.fullName==fileMain).ast.filterNot(node => node.isInstanceOf[Modifier] || node.isInstanceOf[TypeDecl]).filter(s.isSanitized(_)).newTagNodePair("SAN", "TRUE").store
    cpg.method.filter(_.fullName==fileMain).ast.filterNot(node => node.isInstanceOf[Modifier] || node.isInstanceOf[TypeDecl]).filterNot(s.isSanitized(_)).newTagNodePair("SAN", "FALSE").store
    
    run.commit
    cpg.method.filter(_.fullName==fileMain).ast.filterNot(_.isInstanceOf[Modifier]).map(node => List(node.id, node.tag.name("SAN").value.head)).l |> "output_graph/tags.txt"
    val dotAst: String = cpg.method.filter(_.fullName==fileMain).dotAst.head
    dotAst |> "output_graph/output.dot"
}


def testSuite() = {
    val tn: Float = cpg.call("echo").filter(_.code.contains("tainted")).filterNot(_.lineNumber == Some(1)).filter(_.file.name.head.contains("unsafe/")).filter(_.tag.name("SAN_XSS").value.head=="FALSE").size.toFloat
    val tp: Float = cpg.call("echo").filter(_.code.contains("tainted")).filterNot(_.lineNumber == Some(1)).filterNot(_.file.name.head.contains("unsafe/")).filter(_.tag.name("SAN_XSS").value.head=="TRUE").size.toFloat

    val fp: Float = cpg.call("echo").filter(_.code.contains("tainted")).filterNot(_.lineNumber == Some(1)).filter(_.file.name.head.contains("unsafe/")).filter(_.tag.name("SAN_XSS").value.head=="TRUE").size.toFloat
    val fn: Float = cpg.call("echo").filter(_.code.contains("tainted")).filterNot(_.lineNumber == Some(1)).filterNot(_.file.name.head.contains("unsafe/")).filter(_.tag.name("SAN_XSS").value.head=="FALSE").size.toFloat
    
    println("Precision: " + tp/(tp+fp)*100 + "%")
    println("Recall/Sensitivity: " + tp/(tp+fn)*100 + "%")
    println("Specificity: " + tn/(tn+fp)*100 + "%")
}
