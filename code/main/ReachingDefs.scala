def getReachingDef(node: CfgNode, varName: String): List[AstNode] = {
    // println(node.code)
    if (!node.assignment.filter(_.argument(1).code == varName).isEmpty) 
        List(node)
    else if (!node.isCallTo("<init>").isEmpty) {
        node.isCallTo("<init>").callee.methodReturn.l.flatMap(getReachingDef(_, "this." + varName.split('.').last))
    }
    else node.cfgPrev.l.flatMap(getReachingDef(_, varName))
}