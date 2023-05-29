object SanitizationFilter {
   implicit val resolver: ICallResolver = NoResolve
   // implicit val attack_san_functions: List[String] = Constants.san_functions_sql
   val safe_types: List[String] = List("int", "integer", "bool", "boolean", "float", "double")

   var _cpg = None: Option[Cpg]
   def setCpg(cpgInput: Cpg) = {
      _cpg = Some(cpgInput)
      sanitizationMap = collection.mutable.Map[isSanitizedInput, Boolean]()
   }

   // stores isSanitized result for quicker lookup: decreasing analysis of sample-web-app from 0.1135 to 0.00767 seconds
   case class isSanitizedInput(node: Any, sanitizedParameters: List[Boolean] = List(), san_functions_specific: List[String])
   var sanitizationMap = collection.mutable.Map[isSanitizedInput, Boolean]()

   def isMethodSanitized(function: Method, arguments: List[Expression], sanitizedParameters: List[Boolean])(implicit san_functions_specific: List[String]): Boolean = {
      val isArgumentSanitized: List[Boolean] = arguments.map(isSanitized(_, sanitizedParameters)(san_functions_specific))
      // sanitization function returns a sanitized result
      if (Constants.san_functions_all.contains(function.name) || san_functions_specific.contains(function.name)) true
      else if (function.name == "<operator>.assignment") isArgumentSanitized(1)
      // if the function isn't user defined (e.g. <operator>.plus) assume it's sanitized only if all arguments are sanitized
      else if (function.code == "<empty>") !isArgumentSanitized.contains(false)
      // else given whether passed arguments are sanitized check if return is sanitized
      else {
         isSanitized(function.ast.isReturn, isArgumentSanitized)(san_functions_specific)
      }
   }

   // Check whether given CPG Node is sanitized, filter accordingly
   def isSanitized(node: Any, sanitizedParameters: List[Boolean] = List())(implicit san_functions_specific: List[String]): Boolean = 
      sanitizationMap.get(isSanitizedInput(node, sanitizedParameters, san_functions_specific)) match {
      case Some(result) => result
      case None => {
         val result: Boolean = 
         // try { 
            node match { 
            case traversal: overflowdb.traversal.Traversal[_] => isSanitized(traversal.l, sanitizedParameters)(san_functions_specific)
            case List() => true
            case listOfNodes: List[_] => listOfNodes.map(isSanitized(_, sanitizedParameters)(san_functions_specific)).reduce((x,y) => x && y)
            case literal: Literal => true
            case function: nodes.Call => (function.name == "<operator>.cast" && safe_types.contains(function.typeFullName)) ||
                                 isMethodSanitized(function.callee.head, function.argument.l, sanitizedParameters)(san_functions_specific)
            case identifier: Identifier => {
               var isArgumentSanitized = sanitizedParameters
               val definingNode = {
                  // identifier coming from method parameter is unsanitized
                  if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && identifier.astParent.assignment.argument(1).isIdentifier.name(identifier.name).isEmpty)
                     identifier.method.parameter.name(identifier.name).l
                  // identifier used as argument of settype with a safe type will be sanitized
                  else if (!identifier.astParent.isCallTo("settype").isEmpty && safe_types.contains(identifier.astParent.isCallTo("settype").argument(2).code.head.replaceAll("\"","")) ){
                     identifier.astParent.isCallTo("settype").argument(2).l
                  }
                  // CfgNode assigning a variable will have ddgIn pointing to the value of the assignment
                  else if (!identifier.astParent.assignment.argument(1).isIdentifier.name(identifier.name).isEmpty) {
                     identifier.astParent.assignment.argument(2).l
                  }
                  // identifier passed by reference to function
                  else if (identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l.map(p => p.evaluationStrategy == "BY_REFERENCE").lift(identifier.order-1) match {case None => false; case Some(b) => b}) {
                     isArgumentSanitized = identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].argument.l.map(node => {
                        var paramsByRef = node.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l.map(p => p.evaluationStrategy == "BY_REFERENCE")
                        if (!paramsByRef.isEmpty && paramsByRef(node.order-1)) 
                           isSanitized(node.ddgIn.l, sanitizedParameters)(san_functions_specific) 
                        else isSanitized(node, sanitizedParameters)(san_functions_specific)
                     })
                     identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.methodReturn.ddgIn.isIdentifier.name(identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l(identifier.order-1).name).l
                  }
                  // assigned but never used variables don't have ddgIn edge
                  else if (identifier.ddgIn.isEmpty && !identifier.astParent.assignment.argument(1).isIdentifier.name(identifier.name).isEmpty) {
                     identifier.astParent.assignment.argument(2).l
                  }
                  // add identifiers from included files            
                  else if (identifier.ddgIn.isEmpty && !_cpg.isEmpty) {
                     val includeFileNames = _cpg.get.method.fullName(identifier.file.namespaceBlock.fullName.head).call("include|require").argument.code.map(_.replaceAll("\"","")).l
                     val fileIdentifiers = includeFileNames.flatMap(fileName => _cpg.get.method.fullName(fileName+":<global>").methodReturn.ddgIn.isIdentifier.name(identifier.name).l)
                     fileIdentifiers
                  }
                  // used variable will have ddgIn periodically pointing to its last usage
                  else {
                     identifier.ddgIn.isIdentifier.name(identifier.name).l
                     // identifier.repeat(_.ddgIn.isIdentifier.name(identifier.name))(_.until(_.astParent.isCallTo("settype|<operator>.assignment").argument(1).isIdentifier.name(identifier.name)))
                  }
               }
               println(node)
               !definingNode.isEmpty && isSanitized(definingNode, isArgumentSanitized)(san_functions_specific)
            }
            case metadata: MetaData => true
            case namespace: Namespace => true
            case namespaceblock: NamespaceBlock => true
            case typedec: TypeDecl => true
            case block: Block => true
            case file: File => true
            case local: Local => true
            case identifier: Identifier => true
            case method: Method => false
            // case method: Method => isMethodSanitized(method, method.parameter.l.asInstanceOf[List[Expression]], List.fill(method.parameter.size)(false))(san_functions_specific)
            case methodParam: MethodParameterIn => {
               if (sanitizedParameters.isEmpty) false
               else sanitizedParameters(methodParam.index-1)
            }
            case returnBlock: Return => isSanitized(returnBlock.astChildren, sanitizedParameters)(san_functions_specific)
            case declaredtype: Type => true
            case declaredtype: TypeRef => true
            case _ => {
               println(node)
               false
            }
         } 
         // } catch {case _ => false}
         sanitizationMap(isSanitizedInput(node, sanitizedParameters, san_functions_specific)) = result
         result
   }
}

   // make sure to load the cpg of testCases.php into memory before running the command in the joern terminal
   // to run enter: SanitizationFilter.printTestOutput(cpgObject)
   def printTestOutput(cpg: Cpg)(implicit san_functions_specific: List[String] = List()) = {
      // empty map
      sanitizationMap = collection.mutable.Map[isSanitizedInput, Boolean]()
      val t0 = System.nanoTime()
      val san_functions = san_functions_specific
      SanitizationFilter.setCpg(cpg)
      val sanitized = cpg.identifier.filter(SanitizationFilter.isSanitized(_)(san_functions)).name.dedup.l.filter(!List("p1", "p2", "unsan11", "unsan14").contains(_)).sortWith((s1, s2) => s1.replaceAll("[A-Za-z]","").toInt < s2.replaceAll("[A-Za-z]","").toInt)
      val unsanitized = cpg.identifier.filterNot(SanitizationFilter.isSanitized(_)(san_functions)).name.dedup.l.filter(!List("p1", "p2", "san12", "san61", "tmp", "_GET", "san14").contains(_)).sortWith((s1, s2) => s1.replaceAll("[A-Za-z]","").toInt < s2.replaceAll("[A-Za-z]","").toInt)
      // val sanitized = cpg.identifier.filter(SanitizationFilter.isSanitized(_)(san_functions)).name.dedup.l
      // val unsanitized = cpg.identifier.filterNot(SanitizationFilter.isSanitized(_)(san_functions)).name.dedup.l
      println("Sanitized Identifiers: " + sanitized)
      println("Unsanitized Identifiers: " + unsanitized)
      val t1 = System.nanoTime()
      println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
   }
}