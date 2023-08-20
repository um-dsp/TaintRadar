object NavexMain {
    import SanitizationFilter._

    val vulnerabilities: List[String] = List("file-access") //"code-injection", "command-exec", "file-inc", "sqli", "xss", "file-access", "session-fixation")
    var attack_san_functions: List[String] = List()

    def getSinks(vulnerability: String) = {
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
        val source = SanitizationFilter._cpg.get.assignment.argument.filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).l

        val sinks = (SanitizationFilter._cpg.get.call.filter(node => getSinks(vulnerability).contains(node.name)).argument.filterNot(SanitizationFilter.isSanitized(_)(SanitizationFilter.vulnerabilityType(vulnerability, attack_san_functions)))).l
        
        val paths = sinks.reachableByFlows(source)
        val r1 = paths.map(_.elements).map(path => List(path.head.code, path.head.file.name.head, path.last.code, path.last.file.name.head)).dedup.l

        val pathsFun = sinks.repeat(_.method.callIn(NoResolve).argument.filterNot(SanitizationFilter.isSanitized(_)(SanitizationFilter.vulnerabilityType(vulnerability, attack_san_functions))))(_.until(_.reachableByFlows(source)))
        val r2= pathsFun.map(path => List(path.head.code, path.head.file.name.head, path.last.code, path.last.file.name.head)).dedup.l

        r1 ++ r2

    }
    
    def getAllPaths(cpg: Cpg) = {
        SanitizationFilter.setCpg(cpg)
        // vulnerabilities.map(getPaths)
        val t0 = System.nanoTime()
        val result = (vulnerabilities zip vulnerabilities.map(getPaths)).toMap
        val t1 = System.nanoTime()
        println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
        println(result.transform{(k,v) => v.size})
        result
    }

    def getStats(cpg: Cpg) = {
        SanitizationFilter.setCpg(cpg)
        // vulnerabilities.map(getPaths)
        val t0 = System.nanoTime()
        val result = (vulnerabilities zip vulnerabilities.map(getPaths)).toMap
        val t1 = System.nanoTime()
        println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
        result.transform{(k,v) => v.size}
    }
}