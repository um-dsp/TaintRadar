var dfgInMap = collection.mutable.Map[AstNode, List[AstNode]]()
implicit val sanitizedParameters: List[String] = Constants.san_functions_sql

val s = SanitizationFilter(cpg)
val isSanitizedMap = s.isSanitizedMap
def isSanitized = s.isSanitized

def dfgIn(node: CfgNode): List[CfgNode] = {
    dfgInMap.get(node) match {
      case Some(result) => result
      case None => {
        val result: List[AstNode] = 
        try { 
            node match {
            case literal: Literal => {
               List(literal)
            }
            case function: nodes.Call => {
                // Define the method that the function calls
                val method: Method = {
                    // If function is dynamically dispatched with only one definition, the method is uniquely determined
                    if (function.dispatchType == "DYNAMIC_DISPATCH" && cpg.method(function.name).filter(_.code!="<empty>").size == 1) cpg.method(function.name).filter(_.code!="<empty>").head
                    // Otherwise get method definition (if dynamically dispatched will return a method node with empty code)
                    else cpg.callee.head
                }
                // If assignment only consider the last argument
                if (function.assignment.size == 1) method +: List(function.argument.last)
                // Otherwise consider all arguments
                else method +: function.argument.l
            }
            case identifier: Identifier => {
                // calculate the reaching definition of the identifier
                val dataFlowNodes = {
                    // identifier coming from a method parameter is unsanitized
                    if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                    identifier.method.parameter.name(identifier.name).l
                    // identifier used as argument of settype with a safe type will be sanitized
                    // function name to set type by reference: settype
                    else if (!identifier.astParent.isCallTo(Constants.type_cast_byref).isEmpty && Constants.safe_types.contains(identifier.astParent.isCallTo("settype").argument(2).code.head.replaceAll("\"","")) ){
                    identifier.astParent.isCallTo("settype").argument(2).l
                    }
                    // CfgNode assigning a variable will have ddgIn pointing to the value of the assignment
                    else if (identifier == identifier.astParent.assignment.argument(1).headOption.getOrElse(None)) {
                    identifier.astParent.assignment.argument(2).l
                    }
                    // identifier passed by reference to function
                    else if (identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l.map(p => p.evaluationStrategy == "BY_REFERENCE").lift(identifier.order-1) match {case None => false; case Some(b) => b}) {
                    isArgumentSanitized = identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].argument.l.map(node => {
                        var paramsByRef = node.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l.map(p => p.evaluationStrategy == "BY_REFERENCE")
                        if (!paramsByRef.isEmpty && paramsByRef(node.order-1)) 
                            isSanitized(node.ddgIn.l, sanitizedParameters)(vulnerabilityInst) 
                        else isSanitized(node, sanitizedParameters)(vulnerabilityInst)
                    })
                    identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.methodReturn.ddgIn.isIdentifier.name(identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l(identifier.order-1).name).l
                    }
                    // identifiers from included files            
                    // else if (identifier.ddgIn.isEmpty && !_cpg.isEmpty) {
                    //    val includeNodes = cpg.method("<global>").where(_.namespaceBlock.fullName.filter(_==identifier.file.namespaceBlock.fullName.head)).call("include|require").l
                    //    val argumentList = includeNodes.map(_.repeat(_.argument)(_.until(_.not(_.isCall))).l)
                    //    val literalList = argumentList.map(_.flatMap(node => if (node.isIdentifier && node.code!="<global>") node.repeat(_.ddgIn)(_.until(_.isLiteral)).l else node).distinct)
                    //    val directoryList = literalList.map(_.code.map(_.replaceAll("\"","")).l.reduce((a,b) => a+b))
                    //    val fileIdentifiers = directoryList.flatMap(fileName => cpg.method.where(_.namespaceBlock.fullName("("+cpg.metaData.root.head+"/)?"+fileName.replace("./","")+":<global>")).methodReturn.ddgIn.isIdentifier.name(identifier.name).l)
                    //    fileIdentifiers
                    // }
                    // used variable will have ddgIn periodically pointing to its last usage
                    else {
                    identifier.ddgIn.isIdentifier.name(identifier.name).l
                    // identifier.repeat(_.ddgIn.isIdentifier.name(identifier.name))(_.until(_.astParent.isCallTo("settype|<operator>.assignment").argument(1).isIdentifier.name(identifier.name)))
                    }
                  // println(node)
                  !definingNode.isEmpty && isSanitized(definingNode, isArgumentSanitized)(vulnerabilityInst)
               }
               dataFlowNodes
            }
            case constant: FieldIdentifier => {
               if (constantTable.getOrElse(Map()).get(constant.canonicalName).isEmpty) Constants.magic_constants.contains(constant.canonicalName)
               else isSanitized(constantTable.get.get(constant.canonicalName), sanitizedParameters)(vulnerabilityInst)
            }
            case metadata: MetaData => true
            case namespace: Namespace => true
            case namespaceblock: NamespaceBlock => true
            case typedec: TypeDecl => true
            case block: Block => true
            case file: File => true
            case local: Local => true
            case member: Member => true
            case method: Method => false
            // case method: Method => isMethodSanitized(method, method.parameter.l, List.fill(method.parameter.size)(false))(vulnerabilityInst)
            case methodReturn: MethodReturn => true
            case methodParamOut: MethodParameterOut => true
            case methodParam: MethodParameterIn => {
               if (sanitizedParameters.isEmpty) false
               else sanitizedParameters(methodParam.index-1)
            }
            case returnBlock: Return => isSanitized(returnBlock.astChildren, sanitizedParameters)(vulnerabilityInst)
            case declaredtype: Type => true
            case declaredtype: TypeRef => true
            case None => true
            case _ => {
               //println(node)
               false
            }
         } 
         } catch {
            case _ => {
               exceptions = exceptions + 1
               false
            }
         }
         isSanitizedMap(isSanitizedInput(node, sanitizedParameters, vulnerabilityInst)) = result
         result
      }
    }
}