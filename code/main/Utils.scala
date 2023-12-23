object Utils {
    val vulnerabilities: List[String] = List("Code Injection", "Command Execution", "File Inclusion", "Session Fixation", "File Access", "SQL Injection", "XSS")
    // val vulnerabilities: List[String] = List("Command Execution")
    val sanitizationObject = new SanitizationFilter(cpg)
    val db = new DatabaseConstraint(cpg)

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
            case "fileaccess" => {
                List()
            }
            case "sessionfixation" => {
                List()
            }
            case _ => List()
        }
    }

    def getReachingDefs(paths: List[List[AstNode]], source: List[nodes.Call] = List(), tagName: String): List[AstNode] = {
        var output = List[List[AstNode]]()
        val visitedNodes = paths.flatten.dedup.l
        val result = paths.map(path => {
            val lastNode: AstNode = path.last
            // println(path.size)
            val reachingDefs: List[AstNode] = (lastNode match {
                case identifier: Identifier => {
                    if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                    identifier.method.parameter.name(identifier.name).l
                    else identifier.ddgIn.filterNot(_.isLiteral).l
                }
                case call: nodes.Call => {
                    call.ddgIn.filterNot(_.isLiteral).l
                }
                case literal: Literal => List()
                case block: Block => List()
                case parameter: MethodParameterIn => parameter.method.callIn.argument(parameter.index).filterNot(_.isLiteral).l
                case _ => {
                    println(lastNode)
                    List()
                }
            }).filterNot(node => visitedNodes.contains(node) || node.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE")
            if (reachingDefs.isEmpty) (output = output :+ path)
            else reachingDefs.map(reachingDef => output = output :+ (path :+ reachingDef))
            })
        val sourceInPaths: Int = output.map(_.exists(source.contains)).indexOf(true) 
        // if source reached return the path
        if (sourceInPaths >= 0) output(sourceInPaths)
        // if the calculated path is the same as the previous one, return the list of paths
        else if (paths.flatten.size == output.flatten.size) List()
        // otherwise add the next reaching definitions to the paths
        else if (paths.size > 1000) {
            println("Wooh! that's a lot of paths")
            List()
        }
        else getReachingDefs(output, source, tagName) 
    }

    def reachableBySource(sink: AstNode, sources: List[nodes.Call] = List(), tagName: String): List[List[AstNode]] = {
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

    def augmentWithSanTag() = {
        // get all sink functions for the given vulnerability
        vulnerabilities.map(vulnerability => {
            val attack_san_functions = getSanitization(vulnerability)
            // implicit val vulnerabilityInst: sanitizationObject.vulnerabilityType = sanitizationObject.vulnerabilityType(vulnerability, attack_san_functions)
            // extend the cpg with the sanitization tags
            val tagName = "SAN_" + vulnerability.replace(" ", "_")
            cpg.method.ast.filterNot(node => node.isInstanceOf[Modifier] || node.isInstanceOf[TypeDecl]).filter(sanitizationObject.isSanitized(_)(attack_san_functions)).newTagNodePair(tagName, "TRUE").store()
            cpg.method.ast.filterNot(node => node.isInstanceOf[Modifier] || node.isInstanceOf[TypeDecl]).filterNot(sanitizationObject.isSanitized(_)(attack_san_functions)).newTagNodePair(tagName, "FALSE").store()
            run.commit
            "Success"
        })
    }

    // make sure to run this after augmenting with Sanitization tags first (function above)
    def augmentWithQueryTag() = {
        db.augmentDbCalls()
    }
    

    def exceptionRate() = {
        sanitizationObject.exceptions.toFloat / (sanitizationObject.isSanitizedMap.map(_(0).node).dedup.size * vulnerabilities.size)
    }
}
