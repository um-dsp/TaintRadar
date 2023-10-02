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

    def getReachingDefs(paths: List[List[AstNode]], source: List[Call] = List(), vulnerabilityInst: sanitizationObject.vulnerabilityType): List[List[AstNode]] = {
        var output = List[List[AstNode]]()
        val result = paths.map(path => {
            val lastNode: AstNode = path.last
            // println(path.size)
            val reachingDefs: List[AstNode] = (lastNode match {
                case identifier: Identifier => {
                    if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                    identifier.method.parameter.name(identifier.name).l
                    else if (!List(identifier).reachableByFlows(source).isEmpty) {
                        output = output :+ (path ++ List(identifier).reachableByFlows(source).map(_.elements).head.reverse)
                        List()
                    }
                    else identifier.ddgIn.filterNot(_.isLiteral).l
                }
                case call: Call => {
                    if (!List(call).reachableByFlows(source).isEmpty) {
                        output = output :+ (path ++ List(call).reachableByFlows(source).map(_.elements).head.reverse)
                        List()
                    }
                    else call.ddgIn.filterNot(_.isLiteral).l
                }
                case literal: Literal => List()
                case block: Block => List()
                case parameter: MethodParameterIn => parameter.method.callIn(NoResolve).argument(parameter.index).filterNot(_.isLiteral).l
                case _ => {
                    println(lastNode)
                    List()
                }
            }).filterNot(node => path.contains(node) || sanitizationObject.isSanitized(node)(vulnerabilityInst))
            if (reachingDefs.isEmpty) (output = output :+ path)
            else reachingDefs.map(reachingDef => output = output :+ (path :+ reachingDef))
            })
        val sourceInPaths: Int = paths.map(_.exists(source.contains)).indexOf(true) 
        // if the calculated path is the same as the previous one, return the list of paths
        if (paths.reduce((x,y) => x ++ y).size == output.reduce((x,y) => x ++ y).size) output
        // if source reached return the path
        else if (sourceInPaths >= 0) List(paths(sourceInPaths))
        // otherwise add the next reaching definitions to the paths
        else if (paths.size > 100) output
        else getReachingDefs(output, source, vulnerabilityInst) 
    }

    def reachableBySource(sink: AstNode, source: List[Call] = List(),  vulnerabilityInst: sanitizationObject.vulnerabilityType): List[AstNode] = {
        val paths: List[List[AstNode]] = getReachingDefs(List(List(sink)), source, vulnerabilityInst)
        val sourceInPaths: Int = paths.map(_.exists(source.contains)).indexOf(true)
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
        val globalPaths: List[List[AstNode]] = sinks.reachableByFlows(source).map(_.elements).l
        // inter-procedural path from source to sink
        var paths: List[List[AstNode]] = List()
        val functionSinks = sinks.filterNot(_.method.name == "<global>").filterNot(x => globalPaths.map(_.head).contains(x))
        println(functionSinks.size)
        functionSinks.map(sink => {
            val path = reachableBySource(sink, source, vulnerabilityInst)
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
        val output: String = results.transform{(k,v) => 
        v.map(path => {
            val pathID = v.toSeq.indexOf(path) + 1
            path.map(x => 
                "{\n\t\"pathid\": " + pathID + ",\n" + 
                "\t\"vulnerability\": \"" + k + "\",\n" + 
                "\t\"nodeid\": " + x.id + ",\n" +
                "\t\"filename\": \"" + x.file.name.headOption.getOrElse("").replace("\"", "\\\"") + "\",\n" +
                "\t\"linenumber\": " + x.lineNumber.getOrElse("") + ",\n" +
                "\t\"code\": \"" + x.code.replace("\\", "\\\\").replace("\"", "\\\"") + "\"\n},"
            ).mkString("\n")}).mkString("[", "\n", "]")}.values.filter(!_.isEmpty).mkString("").replace("[]", "").replace("},]", "}]").replace("][", ",")
        output |> "paths/output.json"
    }

}