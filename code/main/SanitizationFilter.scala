class SanitizationFilter(val cpg: Cpg) {
   /*
      Sanitization Filter object requires a vulnerabilityType object (attack name & sanitization functions list) as an implicit parameter
      Useful Methods:
         set(Cpg): sets the CPG variable for further use
         isMethodSanitized: outputs whether a function call is sanitized
         isSanitized: outputs whether a node is sanitized
   */
   implicit val resolver: ICallResolver = NoResolve
   var exceptions = 0
   // CONF: safe types in PHP
   val safe_types: List[String] = List("int", "integer", "bool", "boolean", "float", "double")
   // CONF: magic constants in PHP
   val magic_constants: List[String] = List("__LINE__, __FILE__, __DIR__, __FUNCTION__, __CLASS__, __TRAIT__, __METHOD__, __NAMESPACE__")

   case class vulnerabilityType(name: String, sanitization_functions: List[String])
   case class mapInput(id: Long, vulnerabilityName: String)
   var sanitizedNodesMap = collection.mutable.Map[mapInput, Boolean]()
   // stores isSanitized result in a Map for quicker lookup
   case class isSanitizedInput(node: Any, sanitizedParameters: List[Boolean] = List(), vulnerabilityInst: vulnerabilityType)   
   var isSanitizedMap = collection.mutable.Map[isSanitizedInput, Boolean]()

   // var constantTable = None: Option[collection.immutable.Map[String, List[Expression]]]
   val constants: List[String] = cpg.call("define").argument(1).code.l.map(_.replace("\"", "")).distinct
   val values: List[List[Expression]] = constants.map(constant => cpg.call("define").filter(_.argument(1).code.replace("\"", "") == constant).argument(2).l) 
   val constantTable = Some((constants zip values).toMap[String, List[Expression]]) 

   def isMethodSanitized(function: nodes.Call, arguments: List[Expression], sanitizedParameters: List[Boolean])(implicit vulnerabilityInst: vulnerabilityType): Boolean = {
      // if the function is dynamizally dispatched, search cpg for the first function that matches its name, otherwise go to callee
      val method: Method = {
         if (function.dispatchType != "DYNAMIC_DISPATCH") function.callee.head
         else cpg.method(function.name).filter(_.code!="<empty>").head
      }
      // map arguments for the function call on whether they're sanitized or not
      val isArgumentSanitized: List[Boolean] = arguments.map(isSanitized(_, sanitizedParameters)(vulnerabilityInst))
      // sanitization function returns a sanitized result
      if (Constants.san_functions_all.contains(method.name) || vulnerabilityInst.sanitization_functions.contains(method.name)) true
      // dynamic dispatch only supported if the function appears only once in the code
      else if (function.dispatchType == "DYNAMIC_DISPATCH" && cpg.method(function.name).filter(_.code!="<empty>").size > 1) false
      else if (function.name == "<operator>.cast") safe_types.contains(function.typeFullName)
      // an assignment function is sanitized if its second argument is sanitized
      else if (method.name == "<operator>.assignment") isArgumentSanitized(1)
      // CONF: known unsanitized function calls
      else if (method.name == "readline") false
      // if the function isn't user defined (e.g. <operator>.plus) assume it's sanitized only if all arguments are sanitized
      else if (method.code == "<empty>") !isArgumentSanitized.contains(false)
      // else check if return is sanitized given whether passed arguments are sanitized
      else {
         isSanitized(method.ast.isReturn, isArgumentSanitized)(vulnerabilityInst)
      }
   }

   // Check whether given CPG Node is sanitized, filter accordingly
   def isSanitized(node: Any, sanitizedParameters: List[Boolean] = List())(implicit vulnerabilityInst: vulnerabilityType): Boolean = 
      // check the Map to see if node was traversed or not
      isSanitizedMap.get(isSanitizedInput(node, sanitizedParameters, vulnerabilityInst)) match {
      case Some(result) => result
      case None => {
         var mapOut: Boolean = false
         val result: Boolean = 
         try { 
            node match {
            case Some(nodeOption) => isSanitized(nodeOption, sanitizedParameters)(vulnerabilityInst)
            case List() => true
            case traversal: overflowdb.traversal.Traversal[_] => isSanitized(traversal.l, sanitizedParameters)(vulnerabilityInst)
            case listOfNodes: List[_] => listOfNodes.map(isSanitized(_, sanitizedParameters)(vulnerabilityInst)).reduce((x,y) => x && y)
            case literal: Literal => {
               sanitizedNodesMap(mapInput(literal.id, vulnerabilityInst.name)) = true
               true
            }
            case function: nodes.Call => { 
               mapOut = isMethodSanitized(function, function.argument.l, sanitizedParameters)(vulnerabilityInst) 
               sanitizedNodesMap(mapInput(function.id, vulnerabilityInst.name)) = mapOut 
               mapOut
            }
            case identifier: Identifier => {
               // CONF: this & <global> identifiers are sanitized
               if (identifier.name == "<global>" || identifier.name == "this") mapOut = true
               else mapOut = {
                  var isArgumentSanitized = sanitizedParameters
                  // calculate the reaching definition of the identifier
                  val definingNode = {
                     // identifier coming from a method parameter is unsanitized
                     if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                        identifier.method.parameter.name(identifier.name).l
                     // identifier used as argument of settype with a safe type will be sanitized
                     // CONF: function name to set type by reference: settype
                     else if (!identifier.astParent.isCallTo("settype").isEmpty && safe_types.contains(identifier.astParent.isCallTo("settype").argument(2).code.head.replaceAll("\"","")) ){
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
                  }
                  // println(node)
                  !definingNode.isEmpty && isSanitized(definingNode, isArgumentSanitized)(vulnerabilityInst)
               }
               sanitizedNodesMap(mapInput(identifier.id, vulnerabilityInst.name)) = mapOut
               mapOut
            }
            case constant: FieldIdentifier => {
               if (constantTable.getOrElse(Map()).get(constant.canonicalName).isEmpty) magic_constants.contains(constant.canonicalName)
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

   def exceptionRate(): String = {
      (exceptions.toFloat/sanitizedNodesMap.size*100).toString + "%"
   }
   
   def printTestOutput() = {
      val t0 = System.nanoTime()
      val vulnerabilityInst = vulnerabilityType(name = "", sanitization_functions = List())
      val sanitized = cpg.identifier.filter(isSanitized(_)(vulnerabilityInst)).name.dedup.l.filter(!List("p1", "p2", "unsan11", "unsan14").contains(_))
      val unsanitized = cpg.identifier.filterNot(isSanitized(_)(vulnerabilityInst)).name.dedup.l.filter(!List("p1", "p2", "san12", "san6", "tmp", "_GET", "san14").contains(_))
      val sanitizedConstants = cpg.method.ast.isFieldIdentifier.filter(isSanitized(_)(vulnerabilityInst)).canonicalName.dedup.l
      val unsanitizedConstants = cpg.method.ast.isFieldIdentifier.filterNot(isSanitized(_)(vulnerabilityInst)).canonicalName.dedup.l
      // val sanitized = cpg.identifier.filter(isSanitized(_)(vulnerabilityInst)).name.dedup.l
      // val unsanitized = cpg.identifier.filterNot(isSanitized(_)(vulnerabilityInst)).name.dedup.l
      println("Sanitized Identifiers: " + (sanitized ::: sanitizedConstants))
      println("Unsanitized Identifiers: " + (unsanitized ::: unsanitizedConstants))
      val t1 = System.nanoTime()
      println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
   }
}