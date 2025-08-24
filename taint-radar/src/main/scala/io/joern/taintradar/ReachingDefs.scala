package io.joern.taintradar

import io.shiftleft.codepropertygraph.generated.nodes.{CfgNode, Call}
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*

implicit val resolver: ICallResolver = NoResolve

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

def getReachingDef(
    node: CfgNode,
    varName: String,
    i: Int = 0,
    callStack: List[Call] = List(),
    varNames: List[String] = List(),
    visitedNodes: Set[Long] = Set()
): Map[Call, (List[Call], List[String])] = {
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