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

// def getReachingDef(
//     node: CfgNode, 
//     varName: String, 
//     i: Int = 0, 
//     callStack: List[nodes.Call] = List(), 
//     varNames: List[String] = List(),
//     visitedNodes: List[Long] = List()
// ): Map[nodes.Call, (List[nodes.Call], List[String])] = {
//     // node match {
//     //     case n: Expression => println(n.id.toString + ": " + n.code)
//     //     case _ => None
//     // }
//     println(node)
//     if (isDefinition(node, varName)) {
//         // println("Found definition")
//         // println(node.productIterator.toList)
//         Map(node.assignment.head -> (callStack, varNames))
//     } 
//     else if (node.isCall && isInitCall(node, varName.split('.').head)) {
//         // println("Found init call")
//         val results = node.isCallTo("<init>").callee.methodReturn.filterNot(n =>
//             visitedNodes.contains(n.id)).map(
//             getReachingDef(_, "this." + varName.split('.').last, i + 1, callStack, varNames, visitedNodes :+ node.id)
//         )
//         // results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
//         //     (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
//         // }
//         results.foldLeft(Map[nodes.Call, (List[nodes.Call], List[String])]()) { (acc, res) =>
//             acc ++ res
//         }
//     } 
//     else if (node.isCall && !node.isCallTo(".*").filter(c => {
//             (c.dispatchType == "DYNAMIC_DISPATCH") && 
//             (c.argument.isIdentifier.name.headOption.getOrElse("") == varName.split('.').head) && 
//             (c.argument.isIdentifier.order.headOption.getOrElse(0) == 1)
//         }).isEmpty) {
//         // println(node.isCallTo(".*").head.name)
//         val results = node.isCallTo(".*").callee.methodReturn.filterNot(n =>
//             visitedNodes.contains(n.id)).map(
//             getReachingDef(_, "this." + varName.split('.').last, i + 1, node.isCallTo(".*").head +: callStack, varName +: varNames, visitedNodes :+ node.id)
//         )
//         // results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
//         //     (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
//         // }
//         results.foldLeft(Map[nodes.Call, (List[nodes.Call], List[String])]()) { (acc, res) =>
//             acc ++ res
//         }
//     } 
//     else if (node.isCall && !node.isCallTo(".*").callee.filter(_.code != "<empty>").isEmpty && node.ddgIn.exists(_.code == varName.split('.').head)) {
//         val idArg = node.isCallTo(".*").argument.filter(_.code == varName.split('.').head).order.headOption.getOrElse(-1)
//         val varCd = varName.split('.').last
//         val paramNode = node.isCallTo(".*").callee.parameter.filter(_.order == idArg - 1).name.headOption.getOrElse("")
//         val newNames = s"$paramNode.$varCd"
//         val results = node.isCallTo(".*").callee.methodReturn.filterNot(n =>
//             visitedNodes.contains(n.id)).map(
//             getReachingDef(_, newNames, i + 1, node.isCallTo(".*").head +: callStack, varName +: varNames, visitedNodes :+ node.id)
//         )
//         // results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
//         //     (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
//         // }
//         results.foldLeft(Map[nodes.Call, (List[nodes.Call], List[String])]()) { (acc, res) =>
//             acc ++ res
//         }
//     } 
//     else if (i > 200) {
//         // println("Reached max depth")
//         // (List(), callStack, varNames)
//         Map()
//     } 
//     else if (node.cfgPrev.isEmpty) {
//         // println("Reached end of CFG")
//         if (callStack.isEmpty) {
//             // (List(), callStack, varNames)
//             Map()
//         } else {
//             val results = callStack.head.cfgPrev.filterNot(n =>
//             visitedNodes.contains(n.id)).map(
//                 getReachingDef(_, varNames.head, i + 1, callStack.tail, varNames.tail, visitedNodes :+ node.id)
//             )
//             // results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
//             //     (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
//             // }
//             results.foldLeft(Map[nodes.Call, (List[nodes.Call], List[String])]()) { (acc, res) =>
//             acc ++ res
//         }
//         }
//     } 
//     else {
//         // println("Traversing CFG")
//         val results = node.cfgPrev.filterNot(n =>
//             visitedNodes.contains(n.id)).map(
//             getReachingDef(_, varName, i + 1, callStack, varNames, visitedNodes :+ node.id)
//         )
//         // results.foldLeft((List[nodes.Call](), List[nodes.Call](), List[String]())) { (acc, res) =>
//         //     (acc._1 ++ res._1, acc._2 ++ res._2, acc._3 ++ res._3)
//         // }
//         results.foldLeft(Map[nodes.Call, (List[nodes.Call], List[String])]()) { (acc, res) =>
//             acc ++ res
//         }
//     }
// }

def getReachingDef(
    node: CfgNode,
    varName: String,
    i: Int = 0,
    callStack: List[nodes.Call] = List(),
    varNames: List[String] = List(),
    visitedNodes: Set[Long] = Set()
): Map[nodes.Call, (List[nodes.Call], List[String])] = {
    // println(node)
    if (visitedNodes.contains(node.id) || i > 200) {
        // Terminate recursion if node is already visited or depth exceeds limit
        Map()
    } else if (isDefinition(node, varName)) {
        // Found a definition
        Map(node.assignment.head -> (callStack, varNames))
    } else if (node.isCall && isInitCall(node, varName.split('.').head)) {
        // Handle initialization calls
        node.isCallTo("<init>").callee.methodReturn
            .filterNot(n => visitedNodes.contains(n.id))
            .flatMap(
                getReachingDef(_, s"this.${varName.split('.').last}", i + 1, callStack, varNames, visitedNodes + node.id)
            )
            .toMap
    } else if (node.isCall && !node.isCallTo(".*").filter(c => c.dispatchType == "DYNAMIC_DISPATCH").isEmpty) {
        // Handle dynamic dispatch calls
        val results = node.isCallTo(".*").callee.methodReturn
            .filterNot(n => visitedNodes.contains(n.id))
            .flatMap(
                getReachingDef(_, varName, i + 1, node.isCallTo(".*").head +: callStack, varName +: varNames, visitedNodes + node.id)
            )
        results.toMap
    } else if (node.cfgPrev.isEmpty) {
        // End of CFG
        if (callStack.nonEmpty) {
            val results = callStack.head.cfgPrev
                .filterNot(n => visitedNodes.contains(n.id))
                .flatMap(
                    getReachingDef(_, varNames.head, i + 1, callStack.tail, varNames.tail, visitedNodes + node.id)
                )
            results.toMap
        } else {
            Map()
        }
    } else {
        // Traverse previous CFG nodes
        node.cfgPrev
            .filterNot(n => visitedNodes.contains(n.id))
            .flatMap(
                getReachingDef(_, varName, i + 1, callStack, varNames, visitedNodes + node.id)
            )
            .toMap
    }
}