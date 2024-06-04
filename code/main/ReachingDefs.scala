def isDefinition(node: CfgNode, varName: String): Boolean = {
    if (node.isCall && !node.assignment.filter(_.argument(1).code == varName).isEmpty) 
        true
    else false
}

def getReachingDef(node: CfgNode, varName: String): List[CfgNode] = {
    if (isDefinition(node, varName))
        List(node)
    else node.cfgPrev.l
}

def isInitCall(node: CfgNode, objectName: String): Boolean = {
    if (!node.isCallTo("<init>").filter(_.ddgIn.isIdentifier.name.headOption.getOrElse("") == objectName).isEmpty)
        true
    else false
}

def getReachingDefRec(node: CfgNode, varName: String, i: Int = 0, callStack: List[nodes.Call] = List(), varNames: List[String] = List()): List[nodes.Call] = {
    if (isDefinition(node, varName)) {
        println("Found definition")
        node.assignment.l
    }
    else if (node.isCall && isInitCall(node, varName.split('.').head)) {
        println("Found init call")
        node.isCallTo("<init>").callee.methodReturn.flatMap(getReachingDefRec(_, "this." + varName.split('.').last, i+1, callStack, varNames)).l
    }
    else if (node.isCall && !node.isCallTo(".*").
      filter(c => {
            (c.dispatchType == "DYNAMIC_DISPATCH") && 
            (c.argument.isIdentifier.name.headOption.getOrElse("") == varName.split('.').head) && (c.argument.isIdentifier.order.headOption.getOrElse(0) == 1)
            }).isEmpty) {
        println(node.isCallTo(".*").head.name)
        node.isCallTo(".*").callee.methodReturn.flatMap(getReachingDefRec(_, "this." + varName.split('.').last, i+1, node.isCallTo(".*").head +: callStack, varName +: varNames)).l
    }
    else if (node.isCall && !node.isCallTo(".*").callee.filter(_.code!= "<empty>").isEmpty && node.ddgIn.exists(_.code == varName.split('.').head)) {
            // val nbPara = node.isCallTo(".*").callee.parameter.size
            val idArg = node.isCallTo(".*").argument.filter(_.code == varName.split('.').head).order.headOption.getOrElse(-1)
            // val nbArg = node.isCallTo(".*").argument.size
            val varCd = varName.split('.').last
            val paramNode = node.isCallTo(".*").callee.parameter.filter(_.order == idArg - 1).name.headOption.getOrElse("")
            val newNames = s"$paramNode.$varCd"
            node.isCallTo(".*").callee.methodReturn.flatMap(getReachingDefRec(_, newNames, i+1, node.isCallTo(".*").head +: callStack, varName +: varNames)).l
    }
    else if (i > 200) {
        println("Reached max depth")
        List()
    }
    else if (node.cfgPrev.isEmpty) {
        println("Reached end of CFG")
        if (callStack.isEmpty)
            List()
        else
            callStack.head.cfgPrev.l.flatMap(getReachingDefRec(_, varNames.head, i+1, callStack.tail, varNames.tail))
    }
    else {
        println("Traversing CFG")
        node.cfgPrev.l.flatMap(getReachingDefRec(_, varName, i+1, callStack, varNames))
    }
}

def getReachingDefFieldIdentifier(usageNode: nodes.Call): List[CfgNode] = {
    var varName: String = usageNode.code
    val objectNode: Identifier = usageNode.argument.isIdentifier.head
    val attributeNode: FieldIdentifier = usageNode.argument.isFieldIdentifier.head
    var i: Int = 0
    var reachingDefs: List[CfgNode] = getReachingDef(usageNode, varName)
    while (i < 50 && !reachingDefs.filterNot(isDefinition(_, varName)).isEmpty) {
        i += 1
        // println("ReachingDefs: " + reachingDefs)
        reachingDefs = reachingDefs.flatMap(node => {
            val initCall = node.isCallTo("<init>").filter(_.ddgIn.isIdentifier.name.head == objectNode.name).l
            val dynamicCall = node.isCallTo(".*").filter(_.dispatchType == "DYNAMIC_DISPATCH").filter(c => {
                c.argument.head.order == 1 && c.argument.isIdentifier.head.name == objectNode.name && c.argument.isIdentifier.head.typeFullName == objectNode.typeFullName
            }).l
            if (!initCall.isEmpty) {
                varName = "this." + attributeNode.code
                initCall.callee.methodReturn.l
            }
            else if (!dynamicCall.isEmpty)
                dynamicCall.callee.methodReturn.l.flatMap(getReachingDef(_, varName))
            else
                getReachingDef(node, varName)
        }).dedup.l

    }
    return reachingDefs
}