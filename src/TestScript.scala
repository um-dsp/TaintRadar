import Constants._

@main def exec(cpgFile: String, fileMain: String) = {
    val cpg = importCode(cpgFile)
    val s = new SanitizationFilter(cpg)
    implicit val attack_san_functions = Constants.san_functions_sql
    println(cpg.method.fullName.l)
    val nodes = cpg.method.filter(_.fullName==fileMain).ast.filterNot(node => node.isInstanceOf[Modifier] || node.isInstanceOf[TypeDecl] || node.isInstanceOf[Annotation]).filter(s.isSanitized(_)).l
    println(nodes.size)
    nodes.newTagNodePair("SAN", "TRUE").store()
    run.commit
    val tags = cpg.method.filter(_.fullName==fileMain).ast.filterNot(_.isInstanceOf[Modifier]).map(node => List(node.id, node.tag.name("SAN").value.headOption.getOrElse("FALSE"))).l
    tags.map(_.mkString(",") + "\n").mkString("") #> "output_graph/tags.txt"
    val dotAst: String = cpg.method.filter(_.fullName==fileMain).dotAst.head
    dotAst #> "output_graph/output.dot"
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
