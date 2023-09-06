object NavexMain {
    import SanitizationFilter._

    val vulnerabilities: List[String] = List("Code Injection", "Command Execution", "File Inclusion", "Session Fixation", "File Access", "SQL Injection", "XSS")
    var attack_san_functions: List[String] = List()

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

    def getPaths(vulnerability: String) = {
        println(vulnerability)
        // source of the attack vector: assignment nodes whose code contain defined attacker_input
        val source = SanitizationFilter._cpg.get.assignment.argument.filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).l
        // sink of the atack vector: unsanitized arguments of sink call nodes
        val sinks = (SanitizationFilter._cpg.get.call.filter(node => getSinks(vulnerability).contains(node.name)).argument.filterNot(SanitizationFilter.isSanitized(_)(SanitizationFilter.vulnerabilityType(vulnerability, attack_san_functions)))).l
        // intra-procedural path from source to sink
        val paths = sinks.reachableByFlows(source)
        // inter-procedural path from source to sink
        var depth = 0
        val pathsFun = sinks.repeat(sink => sink.method.callIn(NoResolve).filterNot(node=>(node.method.callIn(NoResolve).id.l.contains(node.id))).argument.filterNot(SanitizationFilter.isSanitized(_)(SanitizationFilter.vulnerabilityType(vulnerability, attack_san_functions))))(_.until(_.reachableByFlows(source)))        
        // display code and file name of first and last node in the attack vector's path
        val r1 = paths.map(_.elements).map(path => List(path.head.code, path.head.file.name.head, path.last.code, path.last.file.name.head)).dedup.l
        val r2 = pathsFun.map(path => List(path.head.code, path.head.file.name.head, path.last.code, path.last.file.name.head)).dedup.l
        r1 ++ r2
    }
    
    def getAllPaths(cpg: Cpg, debug:Boolean = true) = {
        // map every vulnerability in the list to its list of possible paths
        SanitizationFilter.setCpg(cpg)
        val t0 = System.nanoTime()
        val result = (vulnerabilities zip vulnerabilities.map(getPaths)).toMap
        val t1 = System.nanoTime()
        if (debug) println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
        if (debug) println("Sanitization exception rate: " + SanitizationFilter.exceptionRate())
        if (debug) println(result.transform{(k,v) => v.size})
        result
    }

    def getStats(cpg: Cpg, debug:Boolean = false) = {
        val result = getAllPaths(cpg, debug)
        result.transform{(k,v) => v.size}
    }
}