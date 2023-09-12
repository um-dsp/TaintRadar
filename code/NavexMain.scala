import scala.collection.mutable.ListBuffer

class NavexMain(val cpg: Cpg) {
    val vulnerabilities: List[String] = List("Code Injection", "Command Execution", "File Inclusion", "Session Fixation", "File Access", "SQL Injection", "XSS")
    var attack_san_functions: List[String] = List()
    val sanitizationObject = new SanitizationFilter(cpg)

    def getSinks(vulnerability: String) = {
        // outputs the corresponding sanitization functions and sinks of the vulnerability
        val sinkFunctions: List[String] = vulnerability.replaceAll("[^a-zA-Z]", "").toLowerCase() match {
            case "codeinjection" | "codeinj" => {
                attack_san_functions = Constants.san_functions_code
                Constants.codeinj_sink
            }
            case "commandexec" | "commandexecution" => {
                attack_san_functions = Constants.san_functions_os_command
                Constants.commandexec_sink
            }
            case "fileinclusion" | "fileinc" => {
                attack_san_functions = Constants.san_functions_file
                Constants.fileinc_sink 
            }
            case "sqli" | "sqlinjection" => {
                attack_san_functions = Constants.san_functions_sql
                Constants.sqli_sink
            }
            case "xss" | "crosssitescripting" => {
                attack_san_functions = Constants.san_functions_xss
                Constants.xss_sink
            }
            case "fileaccess" => {
                attack_san_functions = List()
                Constants.fileaccess_sink
            }
            case "sessionfixation" => {
                attack_san_functions = List()
                Constants.sessionfixation_sink
            }
            case _ => List()
        }
        sinkFunctions
    }
    // case class getReachingDefsInput(paths: List[List[AstNode]], sourceIDs: List[Long] = List())
    // var getReachingDefsMap = collection.mutable.Map[getReachingDefsInput, Boolean]()

    def getReachingDefs(paths: List[List[AstNode]]): List[List[AstNode]] = {
        var output = List[List[AstNode]]()
        for (path <- paths) {
            val reachingDefs = (path.last match {
                case identifier: Identifier => {
                    if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                    identifier.method.parameter.name(identifier.name).l
                    else identifier.ddgIn.l
                }
                case call: Call => call.ddgIn.l
                case literal: Literal => literal.ddgIn.l
                case parameter: MethodParameterIn => parameter.method.callIn(NoResolve).argument(parameter.index).l
                case _ => {
                    println(path.last)
                    List()
                }
            }).filterNot(node => path.map(_.id).contains(node.id))
            if (reachingDefs.isEmpty) (output = output :+ path)
            else for (reachingDef <- reachingDefs) {
                output = output :+ (path :+ reachingDef)
            }
        }
        // if the calculated path is the same as the previous one, return the list of paths
        if (paths.reduce((x,y) => x ++ y).size == output.reduce((x,y) => x ++ y).size) output
        // otherwise add the next reaching definitions to the paths
        else getReachingDefs(output) 
    }

    def reachableBySource(sink: AstNode, sourceIDs: List[Long] = List()): List[AstNode] = {
        val paths: List[List[AstNode]] = getReachingDefs(List(List(sink)))
        val sourceInPaths: Int = paths.map(_.map(_.id)).map(_.exists(sourceIDs.contains)).indexOf(true)
        if (sourceInPaths >= 0) paths(sourceInPaths) else List()
    }

    def getPaths(vulnerability: String) = {
        println(vulnerability)
        // get all sink functions for the given vulnerability
        val sinkFunctions = getSinks(vulnerability)
        // source of the attack vector: assignment nodes whose code contain defined attacker_input
        val source = cpg.call.filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).filterNot(sanitizationObject.isSanitized(_)(sanitizationObject.vulnerabilityType(vulnerability, attack_san_functions))).l //.groupBy(_.lineNumber).map(x => x._2.head).l 
        // sink of the atack vector: unsanitized arguments of sink call nodes
        val sinks = (cpg.call.filter(node => sinkFunctions.contains(node.name)).argument.filterNot(sanitizationObject.isSanitized(_)(sanitizationObject.vulnerabilityType(vulnerability, attack_san_functions)))).l
        // intra-procedural path from source to sink
        var paths: List[List[AstNode]] = List()
        for (sink <- sinks) {
            println(sink)
            val path = reachableBySource(sink, source.map(_.id))
            if (!path.isEmpty) paths = paths :+ path
        }
        paths
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
}