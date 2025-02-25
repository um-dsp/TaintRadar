object Utils {
    // val vulnerabilities: List[String] = List("Code Injection", "Command Execution", "File Inclusion", "Session Fixation", "File Access", "SQL Injection", "XSS") //, "Stored XSS")
    val vulnerabilities: List[String] = List("SQL Injection", "XSS")
    val sanitizationObject = new SanitizationFilter(cpg)
    val db = new DatabaseConstraint(cpg)

    val constants: List[String] = cpg.call(Constants.constant_definition_func).argument(1).code.l.map(_.replace("\"", "")).distinct
    val values: List[List[AstNode]] = constants.map(constant => cpg.call(Constants.constant_definition_func).filter(_.argument(1).code.replace("\"", "") == constant).argument(2).l) 
    val constantTable = Some((constants zip values).toMap[String, List[AstNode]])

    def indicesOfElements[T](elements: Set[T], list: List[T]): List[Int] = {
        list.zipWithIndex.collect { case (element, index) if elements.contains(element) => index }
    }

    def getSinks(vulnerability: String) = {
        // outputs the corresponding sink functions of the vulnerability
        vulnerability.replaceAll("[^a-zA-Z]", "").toLowerCase() match {
            case "codeinjection" | "codeinj" => {
                Constants.codeinj_sink
            }
            case "commandexec" | "commandexecution" => {
                Constants.commandexec_sink
            }
            case "fileinclusion" | "fileinc" => {
                Constants.fileinc_sink
            }
            case "sqli" | "sqlinjection" => {
                Constants.sqli_sink
            }
            case "xss" | "crosssitescripting" => {
                Constants.xss_sink
            }
            case "storedxss" => {
                Constants.stored_xss_func
            }
            case "fileaccess" => {
                Constants.fileaccess_sink
            }
            case "sessionfixation" => {
                Constants.sessionfixation_sink
            }
            case _ => List()
        }
    }

    def getSanitization(vulnerability: String) = {
        // outputs the corresponding sanitization functions of the vulnerability
        vulnerability.replaceAll("[^a-zA-Z]", "").toLowerCase() match {
            case "codeinjection" | "codeinj" => {
                Constants.san_functions_code
            }
            case "commandexec" | "commandexecution" => {
                Constants.san_functions_os_command
            }
            case "fileinclusion" | "fileinc" => {
                Constants.san_functions_file
            }
            case "sqli" | "sqlinjection" => {
                Constants.san_functions_sql
            }
            case "xss" | "crosssitescripting" => {
                Constants.san_functions_xss
            }
            case "storedxss" => {
                Constants.san_functions_xss
            }
            case "fileaccess" => {
                List()
            }
            case "sessionfixation" => {
                List()
            }
            case _ => List()
        }
    }

    var dataFlowStepMap = collection.mutable.Map[AstNode, List[AstNode]]()
    // reachibilityArgs maps the first field access call node of backward data flow to a map of definitions and their scope
    // FieldAccess Call (Sink) -> { Definition Node -> Scope: (CallStack, VarStack) }
    var reachabilityArgs = collection.mutable.Map[nodes.Call, collection.mutable.Map[nodes.Call, (List[nodes.Call], List[String])]]()
    def dataFlowStep(node: AstNode, goToCallIn: Boolean = true)(implicit resolver: (Option[nodes.Call], Option[nodes.Call])): List[AstNode] = {
        dataFlowStepMap.get(node) match {
            case Some(queryData: List[AstNode]) => queryData
            case None => {
                val result = {
                    node match {
                        // For a call node: traverse its arguments and method definition node
                        case call: nodes.Call => {
                            val method = {
                                if (call.callee.filter(_.code != "<empty>").isEmpty) cpg.method.filter(_.name == call.name).filter(_.code != "<empty>")
                                else if (call.dispatchType == "DYNAMIC_DISPATCH") cpg.method.filter(_.fullName == call.methodFullName)
                                else call.callee
                            }
                            val arguments = {
                                if (call.name == "<operator>.alloc" && call.argument.l.isEmpty) {
                                    cpg.call("<init>").filter(_.id == call.id + 1).l
                                }
                                else if (call.name == "<operator>.assignment") List(call.argument(2))
                                else call.argument.dedup.l
                            }
                            if (call.name == "<operator>.fieldAccess") {
                                val startNode = resolver._1.getOrElse(call)
                                if (!reachabilityArgs.contains(startNode)) {
                                    reachabilityArgs(startNode) = collection.mutable.Map[nodes.Call, (List[nodes.Call], List[String])]()
                                }
                                val scope = resolver._2
                                    .map(lastAssignment =>
                                        reachabilityArgs(startNode).getOrElse(lastAssignment, (List(), List()))
                                    )
                                    .getOrElse((List(), List()))
                                val defMaps = getReachingDef(call, call.code, 0, scope._1, scope._2, Set(call.id))
                                reachabilityArgs(startNode) ++= defMaps
                                defMaps.keys.toList
                            }
                            else method.filterNot(_.code == "<empty>").l ++ arguments
                            // method.filterNot(_.code == "<empty>").l ++ arguments
                        }
                        // For an identifier: if it points to a method parameter, traverse this parameter, otherwise follow the data dependency edges
                        case identifier: Identifier => {
                            if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                            identifier.method.parameter.name(identifier.name).l
                            else identifier.ddgIn.l
                        }
                        // For a literal: output the literal
                        case literal: Literal => List(literal)
                        // For a method parameter: potentially go to all method callers and output their corresponding argument (same index as the parameter)
                        // This is intended to be performed only if the path started within the method node itself, otherwise don't output anything
                        case parameter: MethodParameterIn => {
                            if (goToCallIn)
                                cpg.call(parameter.method.name).filter(_.methodFullName == parameter.method.fullName).map(_.argument.l).map(_.lift(parameter.index)).filterNot(_ == None).map(_.get).l
                            else List()
                        }
                        // For a constant, try resolving it statically by checking the "define" function calls
                        case constant: FieldIdentifier => {
                            if (Constants.magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) List()
                            else constantTable.get(constant.canonicalName).dedup.l
                        }
                        // For a method node, traverse its return block (after traversing it make sure not to try resolving the parameters)
                        case method: Method => {
                            if (method.name ==  "<init>") method.ast.filter(_.isInstanceOf[MethodReturn]).l
                            else method.ast.isReturn.l
                        }
                        case returnNode: Return => returnNode.ddgIn.l
                        case block: Block => block.ddgIn.dedup.l
                        case typeRef: TypeRef => List()
                        case _ => {
                            // println(node)
                            List()
                        }
                    }
                }
                dataFlowStepMap(node) = result
                node match {
                    case function: nodes.Call => {
                        if (function.name == "<operator>.fieldAccess") 
                            dataFlowStepMap.-=(node)
                        else None
                    }
                    case _ => None
                }
                result
            }
        }
    }

    // Checks whether the node is reachable by any element of sinks
    def isReachableBy(node: AstNode, sinks: List[AstNode]): Boolean = {
        var i = 0
        var dataFlowNodes: List[AstNode] = sinks
        var found: Boolean = false
        while (i < 100 && !found) {
            if (dataFlowNodes.contains(node)) found = true
            dataFlowNodes = dataFlowNodes.flatMap(n => dataFlowStep(n)(None, None)).dedup.l
            i = i + 1
        }
        found
    }
    

    def getReachingDefs(paths: List[List[AstNode]], source: List[AstNode], tagName: String): List[AstNode] = {
    try {
        var output = List[List[AstNode]]()
        val visitedNodes = paths.flatten.dedup.l
        val result = paths.map( path => {
            // println(path.map(_.code).mkString(", ") + " " + !path.last.isMethod)
            val reachingDefs = dataFlowStep(path.last, !path.last.isMethod)(path.isCallTo("<operator>.fieldAccess").headOption, path.isCall.assignment.lastOption).filterNot(node => visitedNodes.contains(node) || node.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE")
            if (reachingDefs.isEmpty) (output = output :+ path)
            else reachingDefs.map(reachingDef => output = output :+ (path :+ reachingDef))
        })
        val sourceInPaths: Int = output.map(_.exists(source.contains)).indexOf(true) 
        // if source reached return the path
        if (sourceInPaths >= 0) output(sourceInPaths)
        // if the calculated path is the same as the previous one, return the list of paths
        else if (paths.flatten.size == output.flatten.size) List()
        // otherwise add the next reaching definitions to the paths
        else if (paths.flatten.dedup.size > 500) {
            // println("Wooh! that's a lot of paths")
            List()
        }
        else getReachingDefs(output, source, tagName) 
    }
    catch {
        case _ => {
            // println(source.toString + paths.map(_.last).dedup.l.mkString(", "))
            List()
        }
    }
    }

    def reachableBySource(sink: AstNode, sources: List[AstNode] = List(), tagName: String): List[List[AstNode]] = {
        val paths: List[List[AstNode]] = sources.map(source => getReachingDefs(List(List(sink)), List(source), tagName).reverse).filterNot(_.isEmpty)
        paths
    }

    def getNodesFromID(path: List[Long]): List[AstNode] = {
        path.map(cpg.method.ast.id(_).head)
    }

    def getMethodName(node: AstNode) = {
        node match {
            case identifier: Identifier => identifier.method.name
            case call: nodes.Call => call.method.name
            case param: MethodParameterIn => param.method.name
            case _ => "" 
        }
    }

    def getTagName(vulnerability: String) = {
        "SAN_" + vulnerability.replace(" ", "_")
    }

    def isRelevantType(node: AstNode): Boolean = {
        node.isInstanceOf[nodes.Call] || 
        node.isInstanceOf[Identifier] || 
        node.isInstanceOf[Literal] || 
        node.isInstanceOf[MethodParameterIn] ||
        node.isInstanceOf[FieldIdentifier] ||
        node.isInstanceOf[Return]
    }

    def augmentWithSanTag() = {
        // get all sink functions for the given vulnerability
        vulnerabilities.map(vulnerability => {
            val attack_san_functions = getSanitization(vulnerability)
            // implicit val vulnerabilityInst: sanitizationObject.vulnerabilityType = sanitizationObject.vulnerabilityType(vulnerability, attack_san_functions)
            // extend the cpg with the sanitization tags
            val tagName = getTagName(vulnerability)
            cpg.method.ast.filter(isRelevantType).filter(sanitizationObject.isSanitized(_)(attack_san_functions)).newTagNodePair(tagName, "TRUE").store()
            cpg.method.ast.filter(isRelevantType).filterNot(sanitizationObject.isSanitized(_)(attack_san_functions)).newTagNodePair(tagName, "FALSE").store()
            run.commit
            "Success"
        })
    }

    // make sure to run this after augmenting with Sanitization tags first (function above)
    def augmentWithQueryTag() = {
        db.augmentDbCalls()
    }

    def debugDatabaseParsing() = {
        db.debug()
    }

    def exceptionRate() = {
        sanitizationObject.exceptions.toFloat / (sanitizationObject.isSanitizedMap.map(_(0).node).dedup.size * vulnerabilities.size)
    }

    def iteratorToJson(it: Iterator[StoredNode]) = {
        it.map(x => {
                (x.productElementNames.l.zip(x.productIterator.l).toMap ++ x.tag.map(y => (y.name, y.value)).toMap + ("file" -> x.file.name.headOption.getOrElse("None")))
            }).toJsonPretty
    }
    
    def cpgToJson() = {
        iteratorToJson(cpg.all.filterNot(_.isInstanceOf[Tag])) #> "cpg.json"
    }

    def relevantCpgToJson() = {
        iteratorToJson(cpg.method.ast.filter(isRelevantType)) #> "cpg.json"
    }
}