class NavexMain(val cpg: Cpg) {

    Utils.augmentWithSanTag()
    Utils.augmentWithQueryTag()

    def getPaths(vulnerability: String) = {
        println(vulnerability)
        val tagName = "SAN_" + vulnerability.replace(" ", "_")
        // get all sink functions for the given vulnerability
        val sinkFunctions = Utils.getSinks(vulnerability)
        // source of the attack vector: assignment nodes whose code contain defined attacker_input
        val sources = cpg.call("<operator>.indexAccess").filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).filterNot(_.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE").l
        // sink of the atack vector: unsanitized arguments of sink call nodes
        val sinks = cpg.call.filter(x => sinkFunctions.map(_ == x.name).reduce((x,y) => x || y)).filterNot(_.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE").l        // intra-procedural path from source to sink
        // intra and inter-procedural path from source to sink
        val paths: List[List[AstNode]] = sinks.flatMap(Utils.reachableBySource(_, sources, tagName))
        
        val withoutDbCalls = paths.filterNot(p => p.dropRight(1).map(Utils.db.databaseCalls.contains(_)).contains(true))

        val cpgDatabasePaths: List[List[AstNode]] = {
            if (vulnerability=="SQL Injection") List()
            else {
                val insertQuerySinks = cpg.call.filter(c => List("INSERT", "UPDATE").contains(c.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA"))).filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE").l
                val m1: Map[nodes.Call, List[List[AstNode]]] = ( insertQuerySinks zip insertQuerySinks.map(Utils.reachableBySource(_, sources, tagName)) ).toMap
                
                val selectQuerySources = cpg.call.filter(_.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA")=="SELECT").filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE").l
                val selectToSink = sinks.flatMap(Utils.reachableBySource(_, selectQuerySources, tagName))
                val m2: Map[nodes.Call, List[List[AstNode]]] = ( selectQuerySources zip selectQuerySources.map(q => selectToSink.filter(_.head == q)) ).toMap

                val insertCols = insertQuerySinks.map(_.tag.name("QUERY_COLUMNS").value.headOption.getOrElse("NA").split(", ").toList)
                val selectCols = selectQuerySources.map(_.tag.name("QUERY_COLUMNS").value.headOption.getOrElse("NA").split(", ").toList)

                val columnMatching: Map[Int, List[Int]] = ( insertCols.indices zip insertCols.map(_.flatMap(queryCol => selectCols.filter(_.contains(queryCol))).toSet).map(Utils.indicesOfElements(_, selectCols)) ).toMap
                val interQueryPaths: List[List[AstNode]] = columnMatching.keySet.toList.map(insertIndex => {
                        val insertQuery = insertQuerySinks(insertIndex)
                        val insertPaths = m1(insertQuery)
                        val selectQuery = columnMatching(insertIndex).map(selectQuerySources(_))
                        val selectPaths = selectQuery.map(m2(_)).filterNot(_.isEmpty)
                        val queryPaths = for { x <- insertPaths; y <- selectPaths.flatten } yield (x++y)
                        queryPaths
                    }).filterNot(_.isEmpty).flatten
                interQueryPaths
            }
        }

        val totalPaths = (withoutDbCalls ++ cpgDatabasePaths).filterNot(_.map(_.tag.name(tagName).value.head == "TRUE").contains(true))

        // if methodParamIn depends on a sanitized node: the path is sanitized
        val unsanPaths = totalPaths.filterNot(path => path.dropRight(1).zip(path.drop(1)).map(
            (r,c) => (r.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE") && (c.isInstanceOf[MethodParameterIn])
            ).contains(true))
        unsanPaths
        // val dedupPaths = unsanPaths.groupBy(path => List(path.head, path.last)).map(_._2.head)
        // dedupPaths
    }
    
    def getAllPaths(debug:Boolean = true) = {
        // map every vulnerability in the list to its list of possible paths
        val t0 = System.nanoTime()
        val result = (Utils.vulnerabilities zip Utils.vulnerabilities.map(getPaths)).toMap
        val t1 = System.nanoTime()
        if (debug) println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
        if (debug) println("Sanitization exception rate: " + Utils.exceptionRate())
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
            path.map(x => {
                        val tagName = "SAN_" + k.replace(" ", "_")
                        val sinkFunctions = Utils.getSinks(k)
                        "{\n\t\"pathid\": " + pathID + ",\n" + 
                        "\t\"vulnerability\": \"" + k + "\",\n" + 
                        "\t\"nodeid\": " + x.id + ",\n" +
                        "\t\"methodname\": \"" + Utils.getMethodName(x) + "\",\n" +
                        "\t\"filename\": \"" + cpg.metaData.root.head.split("/").last + "/" + x.file.name.headOption.getOrElse("").replace("\"", "\\\"") + "\",\n" +
                        "\t\"linenumber\": " + x.lineNumber.getOrElse("") + ",\n" +
                        "\t\"code\": \"" + x.code.replace("\\", "\\\\").replace("\"", "\\\"") + "\",\n" +
                        "\t\"sanitized\": \"" + x.tag.name(tagName).value.headOption.getOrElse("NA") + "\"\n},"
    }).mkString("\n")}).mkString("[", "\n", "]")}.values.filter(!_.isEmpty).mkString("").replace("[]", "").replace("},]", "}]").replace("][", ",")
        output #> ("navex_utils/paths/" + cpg.metaData.root.head.split("/").last.replaceAll("[^a-zA-Z]", "").toLowerCase + "-output.json")
    }

}