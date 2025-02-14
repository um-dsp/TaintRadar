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
   
   case class vulnerabilityType(name: String, sanitization_functions: List[String])
   case class mapInput(id: Long, vulnerabilityName: String)
   // var sanitizedNodesMap = collection.mutable.Map[mapInput, Boolean]()
   // stores isSanitized result in a Map for quicker lookup
   case class isSanitizedInput(node: Any, sanitizedParameters: List[Boolean] = List(), sanitization_functions: List[String])   
   var isSanitizedMap = collection.mutable.Map[isSanitizedInput, Boolean]()

   // var constantTable = None: Option[collection.immutable.Map[String, List[Expression]]]
   val constants: List[String] = cpg.call(Constants.constant_definition_func).argument(1).code.l.map(_.replace("\"", "")).distinct
   val values: List[List[Expression]] = constants.map(constant => cpg.call(Constants.constant_definition_func).filter(_.argument(1).code.replace("\"", "") == constant).argument(2).l) 
   val constantTable = Some((constants zip values).toMap[String, List[Expression]]) 

   def isMethodSanitized(function: nodes.Call, arguments: List[Expression], sanitizedParameters: List[Boolean])(implicit sanitization_functions: List[String]): Boolean = {
      // if the function is dynamically dispatched, search cpg for the first function that matches its name, otherwise go to callee
      val method: Method = {
         if (function.dispatchType != "DYNAMIC_DISPATCH") function.callee.head
         else if (cpg.method(function.name).filter(_.code!="<empty>").size == 0) cpg.method(function.name).head
         else cpg.method(function.name).filter(_.code!="<empty>").head
      }
      // get the object accessed if the method is class specific (not global)
      // val isObjSan: Boolean = Constants.safe_object_types.exists(objectAccess.typeFullName.headOption.getOrElse("").contains(_)) || isSanitized(objectAccess, sanitizedParameters)(sanitization_functions)
      val objectAccessIdentifier: Option[Identifier] = arguments.isIdentifier.filter(p => function.methodFullName.startsWith(p.typeFullName) && function.methodFullName.contains(":")).headOption
      val objectAccessCall: Option[nodes.Call] = arguments.isCall.filter(p => function.methodFullName.startsWith(p.typeFullName) && function.methodFullName.contains(":")).headOption
      val objectAccess: Option[Expression] = if (objectAccessIdentifier != None) objectAccessIdentifier else objectAccessCall
      val isObjSan: Boolean = {
         if (objectAccessIdentifier == None) {
            !Constants.unsafe_object_types.exists(objectAccessCall.typeFullName.headOption.getOrElse("").contains(_))
         }
         else !Constants.unsafe_object_types.exists(objectAccessIdentifier.typeFullName.headOption.getOrElse("").contains(_))
      }
      // map arguments for the function call on whether they're sanitized or not
      val isArgumentSanitized: List[Boolean] = if (function.name == "<operator>.fieldAccess") arguments.map(x => true) else arguments.map(isSanitized(_, sanitizedParameters)(sanitization_functions))
      // val isArgumentSanitized: List[Boolean] = {
      //    if (objectAccess == None) isArgumentSanitizedRaw
      //    else isObjSan +: isArgumentSanitizedRaw.slice(1, isArgumentSanitizedRaw.size)
      // }
      // sanitization function returns a sanitized result
      if (Constants.san_functions_all.contains(function.name) || sanitization_functions.contains(function.name)) true
      // dynamic dispatch only supported if the function appears only once in the code
      else if (function.dispatchType == "DYNAMIC_DISPATCH" && cpg.method(function.name).filter(_.code!="<empty>").size > 1) false
      // safe return type
      else if (Constants.safe_types.contains(function.typeFullName)) true
      // an assignment function is sanitized if its second argument is sanitized
      else if (function.name == "<operator>.assignment") isArgumentSanitized(1)
      // if the function is a constructor (new), check if the object is sanitized (joern doesn't provide built-in DDG edges in that case)
      else if (function.name == "<operator>.alloc" && function.argument.l.isEmpty) {
         isSanitized(cpg.call("<init>").filter(_.id == function.id + 1).l, sanitizedParameters)(sanitization_functions)
      }
      // for field access, check if the attribute's reaching definitions are sanitized
      else if (function.name == "<operator>.fieldAccess") {
         // val defMaps = getReachingDef(function, function.code)
         // // println(defMaps)
         // if (defMaps.keys.l.isEmpty) false
         // else isSanitized(defMaps.keys.l, sanitizedParameters)(sanitization_functions)
         false
      }
      // known unsanitized function calls
      else if (Constants.attacker_input.contains(function.name) || Constants.attacker_object_types.map(t => function.typeFullName.contains(t)).contains(true)) false
      // if the function implicitly casts the type (e.g. unsan + 0)
      else if (Constants.implicit_cast.contains(function.name)) {
         if (function.argument.size != 2) !isArgumentSanitized.contains(false)
         else {
            val argumentTypes = function.argument.map(arg => {
               if (arg.isInstanceOf[Literal]) arg.asInstanceOf[Literal].typeFullName
               else if (arg.isInstanceOf[Identifier]) arg.asInstanceOf[Identifier].typeFullName
               else if (arg.isInstanceOf[nodes.Call]) arg.asInstanceOf[nodes.Call].typeFullName
               else "NA"
            }).l
            Constants.safe_types.exists(argumentTypes.contains(_)) || !isArgumentSanitized.contains(false)
         }
      }
      // if the function isn't user defined (e.g., <operator>.plus) assume it's sanitized only if all arguments are sanitized
      else if (method.code == "<empty>") !isArgumentSanitized.contains(false)
      // else check if return is sanitized given whether passed arguments are sanitized
      else {
         isSanitized(method.ast.isReturn, isArgumentSanitized)(sanitization_functions)
      }
   } 
   // println(n.id.toString + ": " + n.code)
// 
   // Check whether given CPG Node is sanitized, filter accordingly
   def isSanitized(node: Any, sanitizedParameters: List[Boolean] = List())(implicit sanitization_functions: List[String]): Boolean = 
      // check the Map to see if node was traversed or not
      node match {
         case n: Expression => if (n.id%100==0) None else None
         case _ => None
      }
      isSanitizedMap.get(isSanitizedInput(node, sanitizedParameters, sanitization_functions)) match {
      case Some(result) => result
      case None => {
         isSanitizedMap(isSanitizedInput(node, sanitizedParameters, sanitization_functions)) = true
         var mapOut: Boolean = false
         val result: Boolean = 
         try { 
            node match {
            case Some(nodeOption) => isSanitized(nodeOption, sanitizedParameters)(sanitization_functions)
            case List() => true
            case traversal: overflowdb.traversal.Traversal[_] => isSanitized(traversal.l, sanitizedParameters)(sanitization_functions)
            case listOfNodes: List[_] => listOfNodes.map(isSanitized(_, sanitizedParameters)(sanitization_functions)).reduce((x,y) => x && y)
            case literal: Literal => {
               // sanitizedNodesMap(mapInput(literal.id, vulnerabilityInst.name)) = true
               true
            }
            case function: nodes.Call => { 
               mapOut = isMethodSanitized(function, function.argument.l, sanitizedParameters)(sanitization_functions) 
               // sanitizedNodesMap(mapInput(function.id, vulnerabilityInst.name)) = mapOut 
               mapOut
            }
            case identifier: Identifier => {
               // this & <global> identifiers are sanitized
               if (Constants.safe_types.contains(identifier.typeFullName) || Constants.san_identifiers.contains(identifier.name)) mapOut = true
               else if (Constants.attacker_object_types.map(t => identifier.typeFullName.contains(t)).contains(true)) mapOut = false
               else mapOut = {
                  var isArgumentSanitized = sanitizedParameters
                  // calculate the reaching definition of the identifier
                  val definingNode = {
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
                              isSanitized(node.ddgIn.l, sanitizedParameters)(sanitization_functions) 
                           else isSanitized(node, sanitizedParameters)(sanitization_functions)
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
                  // !definingNode.isEmpty && isSanitized(definingNode, isArgumentSanitized)(sanitization_functions)
                  isSanitized(definingNode, isArgumentSanitized)(sanitization_functions)
               }
               // sanitizedNodesMap(mapInput(identifier.id, vulnerabilityInst.name)) = mapOut
               mapOut
            }
            case constant: FieldIdentifier => {
               if (constantTable.getOrElse(Map()).get(constant.canonicalName).isEmpty) Constants.magic_constants.contains(constant.canonicalName) || isSanitized(constant.ddgIn.l, sanitizedParameters)(sanitization_functions)
               else isSanitized(constantTable.get.get(constant.canonicalName), sanitizedParameters)(sanitization_functions)
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
            // case method: Method => isMethodSanitized(method, method.parameter.l, List.fill(method.parameter.size)(false))(sanitization_functions)
            case methodReturn: MethodReturn => true
            case methodParamOut: MethodParameterOut => true
            case methodParam: MethodParameterIn => {
               if (sanitizedParameters.isEmpty) Constants.safe_types.contains(methodParam.typeFullName)
               else sanitizedParameters(methodParam.index-1)
            }
            case returnBlock: Return => isSanitized(returnBlock.astChildren, sanitizedParameters)(sanitization_functions)
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
         isSanitizedMap(isSanitizedInput(node, sanitizedParameters, sanitization_functions)) = result
         node match {
            case function: nodes.Call => {
               if (function.name == "<operator>.fieldAccess") 
                  isSanitizedMap.-=(isSanitizedInput(node, sanitizedParameters, sanitization_functions))
               else None
            }
            case _ => None
         }
         result
      }
   }
   
   def printTestOutput() = {
      val t0 = System.nanoTime()
      val sanitization_functions = List()
      val vulnerabilityInst = vulnerabilityType(name = "", sanitization_functions)
      val sanitized = cpg.identifier.filter(isSanitized(_)(sanitization_functions)).name.dedup.l.filter(!List("p1", "p2", "unsan11", "unsan14").contains(_))
      val unsanitized = cpg.identifier.filterNot(isSanitized(_)(sanitization_functions)).name.dedup.l.filter(!List("p1", "p2", "san12", "san6", "tmp", "_GET", "san14").contains(_))
      val sanitizedConstants = cpg.method.ast.isFieldIdentifier.filter(isSanitized(_)(sanitization_functions)).canonicalName.dedup.l
      val unsanitizedConstants = cpg.method.ast.isFieldIdentifier.filterNot(isSanitized(_)(sanitization_functions)).canonicalName.dedup.l
      // val sanitized = cpg.identifier.filter(isSanitized(_)(sanitization_functions)).name.dedup.l
      // val unsanitized = cpg.identifier.filterNot(isSanitized(_)(sanitization_functions)).name.dedup.l
      println("Sanitized Identifiers: " + (sanitized ::: sanitizedConstants))
      println("Unsanitized Identifiers: " + (unsanitized ::: unsanitizedConstants))
      val t1 = System.nanoTime()
      println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
   }
}
