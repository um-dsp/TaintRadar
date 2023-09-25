class NavexMain(val cpg: Cpg) {
    val vulnerabilities: List[String] = List("Code Injection", "Command Execution", "File Inclusion", "Session Fixation", "File Access", "SQL Injection", "XSS")
    // val vulnerabilities: List[String] = List("Command Execution")
    val sanitizationObject = new SanitizationFilter(cpg)

    def getSinks(vulnerability: String) = {
        // outputs the corresponding sanitization functions and sinks of the vulnerability
        vulnerability.replaceAll("[^a-zA-Z]", "").toLowerCase() match {
            case "codeinjection" | "codeinj" => {
                (Constants.san_functions_code, Constants.codeinj_sink)
            }
            case "commandexec" | "commandexecution" => {
                (Constants.san_functions_os_command, Constants.commandexec_sink)
            }
            case "fileinclusion" | "fileinc" => {
                (Constants.san_functions_file, Constants.fileinc_sink)
            }
            case "sqli" | "sqlinjection" => {
                (Constants.san_functions_sql, Constants.sqli_sink)
            }
            case "xss" | "crosssitescripting" => {
                (Constants.san_functions_xss, Constants.xss_sink)
            }
            case "fileaccess" => {
                (List(), Constants.fileaccess_sink)
            }
            case "sessionfixation" => {
                (List(), Constants.sessionfixation_sink)
            }
            case _ => (List(), List())
        }
    }
    // case class getReachingDefsInput(paths: List[List[AstNode]], sourceIDs: List[Long] = List())
    // var getReachingDefsMap = collection.mutable.Map[getReachingDefsInput, Boolean]()

    // def getReachingDefsOptimized(paths: List[List[AstNode]], source: List[AstNode] = List()): List[List[AstNode]] = {
    //     var output = List[List[AstNode]]()
    //     for (path <- paths) {
    //         val lastNode: AstNode = path.last
    //         val lastMethod = lastNode match {
    //             case identifier: Identifier => identifier.method
    //             case call: Call => call.method
    //             case parameter: MethodParameterIn => parameter.method
    //         }
    //         output = if (lastMethod.name == "<global>") path ++ lastNode.reachableByFlows(source).map(_.elements).l
    //         else {
    //             val pathToParameters = lastNode match {
    //                 case identifier: Identifier => {
    //                     if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
    //                         identifier.method.parameter.name(identifier.name).l
    //                     List(identifier).reachableByFlows(lastMethod.parameter).map(_.elements).l
    //                 } 
    //                 // case call: Call => call.method
    //                 // case parameter: MethodParameterIn => parameter.method
    //             }
    //         }
    //         }
    //         output = output :+  {
    //             if (lastNode.method.name == "<global>") path ++ lastNode.reachableByFlows(source).map(_.elements).l
    //             else if (!lastNode.reachableByFlows(lastNode.method.parameter).isEmpty)
    //                 for (param <- lastNode.method.parameter.l) {
    //                 val reachableByParam = lastNode.reachableByFlows(param).map(_.elements).l
    //                 if (!reachableByParam.isEmpty) {
    //                     val passedArg = param.method.callIn(NoResolve).argument(param.index).filterNot(_.isLiteral).l
    //                     for (arg <- passedArg) {
    //                         output = output :+ (path ++ reachableByParam :+ arg)
    //                     }
    //                 }
    //             }
    //             else path
    //         }
    //     }
    //     if (paths.reduce((x,y) => x ++ y).size == output.reduce((x,y) => x ++ y).size) output
    //     else getReachingDefsOptimized(output, source)
    // }

    def getReachingDefs(paths: List[List[Long]], sourceIDs: List[Long] = List()): List[List[Long]] = {
        var output = List[List[Long]]()
        paths.map(path => {
            val lastNode: AstNode = cpg.method.ast.id(path.last).head
            // println(path.size)
            val reachingDefs: List[Long] = (lastNode match {
                case identifier: Identifier => {
                    if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                    identifier.method.parameter.name(identifier.name).id.l
                    else if (!List(identifier).reachableByFlows(getNodesFromID(sourceIDs)).isEmpty) {
                        output = output :+ (path ++ List(identifier).reachableByFlows(getNodesFromID(sourceIDs)).map(_.elements.map(_.id)).head.reverse)
                        List()
                    }
                    else identifier.ddgIn.filterNot(_.isLiteral).id.l
                }
                case call: Call => {
                    if (!List(call).reachableByFlows(getNodesFromID(sourceIDs)).isEmpty) {
                        output = output :+ (path ++ List(call).reachableByFlows(getNodesFromID(sourceIDs)).map(_.elements.map(_.id)).head.reverse)
                        List()
                    }
                    else call.ddgIn.filterNot(_.isLiteral).id.l
                }
                case literal: Literal => List()
                case block: Block => List()
                case parameter: MethodParameterIn => parameter.method.callIn(NoResolve).argument(parameter.index).filterNot(_.isLiteral).id.l
                case _ => {
                    println(lastNode)
                    List()
                }
            }).filterNot(node => path.contains(node))
            if (reachingDefs.isEmpty) (output = output :+ path)
            else reachingDefs.map(reachingDef => {
                // if (!getNodesFromID(List(reachingDef)).head.reachableByFlows(getNodesFromID(sourceIDs)).isEmpty) output = output :+ (path :+ reachingDef.reachableByFlows(getNodesFromID(sourceIDs)).map(_.elements.map(_.id)).l.reverse)
                output = output :+ (path :+ reachingDef)
            })
        })
        val sourceInPaths: Int = paths.map(_.exists(sourceIDs.contains)).indexOf(true) 
        // if the calculated path is the same as the previous one, return the list of paths
        if (paths.reduce((x,y) => x ++ y).size == output.reduce((x,y) => x ++ y).size) output
        // if source reached return the path
        else if (sourceInPaths >= 0) List(paths(sourceInPaths))
        // otherwise add the next reaching definitions to the paths
        else if (paths.size > 100) output
        else getReachingDefs(output, sourceIDs) 
    }

    def reachableBySource(sink: AstNode, sourceIDs: List[Long] = List()): List[Long] = {
        val paths: List[List[Long]] = getReachingDefs(List(List(sink.id)), sourceIDs)
        val sourceInPaths: Int = paths.map(_.exists(sourceIDs.contains)).indexOf(true)
        if (sourceInPaths >= 0) paths(sourceInPaths).reverse else List()
    }

    def getNodesFromID(path: List[Long]): List[AstNode] = {
        path.map(cpg.method.ast.id(_).head)
    }

    def getPaths(vulnerability: String) = {
        println(vulnerability)
        // get all sink functions for the given vulnerability
        val (attack_san_functions, sinkFunctions) = getSinks(vulnerability)
        implicit val vulnerabilityInst = sanitizationObject.vulnerabilityType(vulnerability, attack_san_functions)
        // source of the attack vector: assignment nodes whose code contain defined attacker_input
        val source = cpg.call.filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).filterNot(sanitizationObject.isSanitized(_)(vulnerabilityInst)).l //.groupBy(_.lineNumber).map(x => x._2.head).l 
        // sink of the atack vector: unsanitized arguments of sink call nodes
        val sinks = (cpg.call.filter(x => sinkFunctions.map(x.name.contains(_)).reduce((x,y) => x || y)).argument.filterNot(sanitizationObject.isSanitized(_)(vulnerabilityInst))).l        // intra-procedural path from source to sink
        // intra-procedural path from source to sink
        val globalPaths: List[List[Long]] = sinks.reachableByFlows(source).map(_.elements.map(_.id)).l
        // inter-procedural path from source to sink
        var paths: List[List[Long]] = List()
        val functionSinks = sinks.filterNot(_.method.name == "<global>").filterNot(x => globalPaths.map(_.head).contains(x.id))
        println(functionSinks.size)
        functionSinks.map(sink => {
            val path = reachableBySource(sink, source.map(_.id))
            if (!path.isEmpty) paths = paths :+ path
        })
        val totalPaths = globalPaths ++ paths
        totalPaths.groupBy(_.head).map(_._2.head)
    }
    
    def getAllPaths(debug:Boolean = true) = {
        // map every vulnerability in the list to its list of possible paths
        val t0 = System.nanoTime()
        val result = (vulnerabilities zip vulnerabilities.map(getPaths)).toMap
        val t1 = System.nanoTime()
        if (debug) println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
        if (debug) println("Sanitization exception rate: " + sanitizationObject.exceptionRate())
        if (debug) println(result.transform{(k,v) => v.size})
        result
    }

    def getStats() = {
        val result = getAllPaths(true)
        result.transform{(k,v) => v.size}
    }

    def outputPaths(debug:Boolean = true) = {
        val results = getAllPaths(debug)
        results.transform{(k,v) => v.map(getNodesFromID(_)).map(_.map(x => k + "; " + x.code + "; " + x.file.name.headOption.getOrElse("") + ":" + x.lineNumber.getOrElse("")).mkString("\n", "\n", "\n")).mkString("\n")}.values.filter(!_.isEmpty)
    }

}