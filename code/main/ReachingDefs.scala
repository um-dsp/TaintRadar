def isDefinition(node: CfgNode, varName: String): Boolean = {
    if (node.isCall && !node.assignment.filter(_.argument(1).code == varName).isEmpty) 
        true
    else false
}

def isInitCall(node: CfgNode, objectName: String): Boolean = {
    if (!node.isCallTo("<init>").filter(_.ddgIn.isIdentifier.name.headOption.getOrElse("") == objectName).isEmpty)
        true
    else false
}

// def getReachingDef(node: CfgNode, varName: String): List[CfgNode] = {
//     if (isDefinition(node, varName))
//         List(node)
//     else node.cfgPrev.l
// }
// def getReachingDefRec(node: CfgNode, varName: String, i: Int = 0, callStack: List[nodes.Call] = List(), varNames: List[String] = List()): List[nodes.Call] = {
//     if (isDefinition(node, varName)) {
//         println("Found definition")
//         println(node.productIterator.l)
//         node.assignment.l
//     }
//     else if (node.isCall && isInitCall(node, varName.split('.').head)) {
//         println("Found init call")
//         node.isCallTo("<init>").callee.methodReturn.flatMap(getReachingDefRec(_, "this." + varName.split('.').last, i+1, callStack, varNames)).l
//     }
//     else if (node.isCall && !node.isCallTo(".*").
//       filter(c => {
//             (c.dispatchType == "DYNAMIC_DISPATCH") && 
//             (c.argument.isIdentifier.name.headOption.getOrElse("") == varName.split('.').head) && (c.argument.isIdentifier.order.headOption.getOrElse(0) == 1)
//             }).isEmpty) {
//         println(node.isCallTo(".*").head.name)
//         node.isCallTo(".*").callee.methodReturn.flatMap(getReachingDefRec(_, "this." + varName.split('.').last, i+1, node.isCallTo(".*").head +: callStack, varName +: varNames)).l
//     }
//     else if (node.isCall && !node.isCallTo(".*").callee.filter(_.code!= "<empty>").isEmpty && node.ddgIn.exists(_.code == varName.split('.').head)) {
//             // val nbPara = node.isCallTo(".*").callee.parameter.size
//             val idArg = node.isCallTo(".*").argument.filter(_.code == varName.split('.').head).order.headOption.getOrElse(-1)
//             // val nbArg = node.isCallTo(".*").argument.size
//             val varCd = varName.split('.').last
//             val paramNode = node.isCallTo(".*").callee.parameter.filter(_.order == idArg - 1).name.headOption.getOrElse("")
//             val newNames = s"$paramNode.$varCd"
//             node.isCallTo(".*").callee.methodReturn.flatMap(getReachingDefRec(_, newNames, i+1, node.isCallTo(".*").head +: callStack, varName +: varNames)).l
//     }
//     else if (i > 200) {
//         println("Reached max depth")
//         List()
//     }
//     else if (node.cfgPrev.isEmpty) {
//         println("Reached end of CFG")
//         if (callStack.isEmpty)
//             List()
//         else
//             callStack.head.cfgPrev.flatMap(getReachingDefRec(_, varNames.head, i+1, callStack.tail, varNames.tail)).l
//     }
//     else {
//         println("Traversing CFG")
//         node.cfgPrev.flatMap(getReachingDefRec(_, varName, i+1, callStack, varNames)).l
//     }
// }

def getReachingDef(
    node: CfgNode, 
    varName: String, 
    i: Int = 0, 
    callStack: List[nodes.Call] = List(), 
    varNames: List[String] = List()
): (List[nodes.Call], List[nodes.Call], List[String]) = {

    if (isDefinition(node, varName)) {
        println("Found definition")
        println(node.productIterator.toList)
        (node.assignment.toList, callStack, varNames)
    } 
    else if (node.isCall && isInitCall(node, varName.split('.').head)) {
        println("Found init call")
        val results = node.isCallTo("<init>").callee.methodReturn.map(
            getReachingDefRec(_, "this." + varName.split('.').last, i + 1, callStack, varNames)
        )
        results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
            (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
        }
    } 
    else if (node.isCall && !node.isCallTo(".*").filter(c => {
            (c.dispatchType == "DYNAMIC_DISPATCH") && 
            (c.argument.isIdentifier.name.headOption.getOrElse("") == varName.split('.').head) && 
            (c.argument.isIdentifier.order.headOption.getOrElse(0) == 1)
        }).isEmpty) {
        println(node.isCallTo(".*").head.name)
        val results = node.isCallTo(".*").callee.methodReturn.map(
            getReachingDefRec(_, "this." + varName.split('.').last, i + 1, node.isCallTo(".*").head +: callStack, varName +: varNames)
        )
        results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
            (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
        }
    } 
    else if (node.isCall && !node.isCallTo(".*").callee.filter(_.code != "<empty>").isEmpty && node.ddgIn.exists(_.code == varName.split('.').head)) {
        val idArg = node.isCallTo(".*").argument.filter(_.code == varName.split('.').head).order.headOption.getOrElse(-1)
        val varCd = varName.split('.').last
        val paramNode = node.isCallTo(".*").callee.parameter.filter(_.order == idArg - 1).name.headOption.getOrElse("")
        val newNames = s"$paramNode.$varCd"
        val results = node.isCallTo(".*").callee.methodReturn.map(
            getReachingDefRec(_, newNames, i + 1, node.isCallTo(".*").head +: callStack, varName +: varNames)
        )
        results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
            (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
        }
    } 
    else if (i > 200) {
        println("Reached max depth")
        (List(), callStack, varNames)
    } 
    else if (node.cfgPrev.isEmpty) {
        println("Reached end of CFG")
        if (callStack.isEmpty) {
            (List(), callStack, varNames)
        } else {
            val results = callStack.head.cfgPrev.map(
                getReachingDefRec(_, varNames.head, i + 1, callStack.tail, varNames.tail)
            )
            results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
                (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
            }
        }
    } 
    else {
        println("Traversing CFG")
        val results = node.cfgPrev.map(
            getReachingDefRec(_, varName, i + 1, callStack, varNames)
        )
        results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
            (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
        }
    }
}