package org.codeminers.standalone

import io.shiftleft.codepropertygraph.generated.{Cpg, NodeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, MethodParameterIn}
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*

import org.codeminers.standalone.Constants.ConstantsFactory
import org.codeminers.standalone.Utils

import java.nio.file.{Files, Paths, StandardOpenOption}

class NavexMain(val cpg: Cpg,val shouldAugment: Boolean) {

    val CpgUtils = Utils(cpg)
    val Constants = ConstantsFactory.getConstants(cpg.metaData.head.language)
    val cpgSize = cpg.all.size
    if (shouldAugment){
        CpgUtils.augmentWithSanTag()
        CpgUtils.augmentWithQueryTag()
        CpgUtils.debugDatabaseParsing()
    }


    var logger: List[String] = List()

    def getSinkCalls(vulnerability: String, tagName: String, debug: Boolean = false) = {
        // get all sink function names for the given vulnerability
        val sinkFunctions: List[String] = CpgUtils.getSinks(vulnerability)
        // sink of the attack vector: unsanitized calls to sensitive functions
        val totalSinks: List[Call] = cpg.call.filter(x => sinkFunctions.exists(_ == x.name)).l
        if (debug) {
            println("Sensitive sink functions size: " + totalSinks.size)
            logger ++= List(totalSinks.size.toString)
        }
        // val unsanSinks: List[Call] = totalSinks.filterNot(_.argument.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE").l
        val unsanSinks: List[Call] = totalSinks.filter(_.argument.tag.name(tagName).value.contains("FALSE")).l
        if (debug) {
            println("Sensitive unsanitized sink functions size: " + unsanSinks.size)
            logger ++= List(unsanSinks.size.toString)
        }

        unsanSinks
    }

    // source of the attack vector: HTTP request parameters, e.g. $_GET[], $_POST[], ...
    val sources = cpg.call("<operator>.indexAccess").filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).l
    // val sources = cpg.call.filter(node => Constants.attacker_input.contains(node.name) || Constants.attacker_input.contains(node.code)).l  ++ cpg.parameter("args").filter(_.method.name=="main").l
    // val sources = cpg.call.filter(f => Constants.attacker_object_types.map(f.typeFullName.contains(_)).contains(true)).l
    println("Sources size: " + sources.size)
    
    val databaseCalls = getSinkCalls("Stored XSS", CpgUtils.getTagName("XSS"), false)

    val insertStatements = CpgUtils.db.queryStatements.filter(c => List("INSERT", "UPDATE").contains(c.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA"))).filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE")
    val vulnerableInsert = if (insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)).size > 0) insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)) else insertStatements
    // val vulnerableInsert = insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls))
    val dbCallsPerInsert = vulnerableInsert.map(q => databaseCalls.filter(dbcall => CpgUtils.isReachableBy(q, List(dbcall))))
    val dbCallsToSource = dbCallsPerInsert.map(dbcall => sources.map(s => CpgUtils.getReachingDefs(dbcall.map(List(_)), List(s), "SAN_XSS").reverse).filterNot(_.isEmpty))
    val m1: Map[AstNode, List[List[AstNode]]] = (vulnerableInsert zip  dbCallsToSource).toMap


    val selectStatements = CpgUtils.db.queryStatements.filter(_.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA")=="SELECT").filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE").l
    val vulnerableSelect = if (selectStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)).size > 0) selectStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)) else selectStatements
    val dbCallsPerSelect = vulnerableSelect.map(q => databaseCalls.filter(dbcall => CpgUtils.isReachableBy(q, List(dbcall))))
    
    // val vulnerableSelect = selectStatements.filter(CpgUtils.isReachableBy(_, databaseCalls))
        
    def getPaths(vulnerability: String, debug: Boolean = false) = {
        println(vulnerability)
        val tagName: String = CpgUtils.getTagName(vulnerability)
        val sinks = getSinkCalls(vulnerability, tagName, debug).argument.l
        // intra and inter-procedural path from source to sink
        // paths considering every source node separately (one or no path per source node)
        val paths: List[List[AstNode]] = sinks.flatMap(sink => CpgUtils.reachableBySource(sink, sources, tagName))
        // paths considering all source nodes together (one or no path per list of sources)
        // val paths: List[List[AstNode]] = sinks.map(sink => CpgUtils.getReachingDefs(List(List(sink)), sources, tagName).reverse).filterNot(_.isEmpty)
        if (debug) println("Number of paths within CPG: " + paths.size)
        logger ++= List(paths.size.toString)

        // val databaseCalls = getSinkCalls("SQL Injection", tagName, false)
        // remove any paths that depend on a database call
        val withoutDbCalls = paths.filterNot(p => p.dropRight(1).exists(databaseCalls.contains(_)))
        // val withoutDbCalls = paths.filterNot(p => p.dropRight(1).exists(n => databaseCalls.code.exists(n.code.contains(_))))
        if (debug) println("Number of paths not containing database calls within CPG: " + withoutDbCalls.size)

        val cpgDatabasePaths: List[List[AstNode]] = {
            if (vulnerability=="SQL Injection" || sinks.isEmpty) List()
            else {
                // Get unsafe query statements that are of type INSERT or UPDATE 
                // val insertStatements = CpgUtils.db.queryStatements.filter(c => List("INSERT", "UPDATE").contains(c.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA"))).filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE")
                // val vulnerableInsert = if (insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)).size < insertStatements.size/2) insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)) else insertStatements
                
                // val selectStatements = CpgUtils.db.queryStatements.filter(_.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA")=="SELECT").filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE").l
                // val vulnerableSelect = if (selectStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)).size < selectStatements.size/2) selectStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)) else selectStatements

                if (debug) println("Number of insert statements: " + insertStatements.size)
                if (debug) println("Number of insert statements as sink: " + vulnerableInsert.size)
                if (debug) println("Number of select statements: " + selectStatements.size)
                if (debug) println("Number of select statements as source: " + vulnerableSelect.size)
                
                if (vulnerableInsert.size == 0 || vulnerableSelect.size == 0) List()
                else {
                    // val m1: Map[AstNode, List[List[AstNode]]] = ( vulnerableInsert zip vulnerableInsert.map(CpgUtils.reachableBySource(_, sources, tagName)) ).toMap
                    val dbCallsToSink = dbCallsPerSelect.map(dbcall => sinks.flatMap(s => CpgUtils.reachableBySource(s, dbcall, tagName)))

                    val selectToSink = sinks.flatMap(CpgUtils.reachableBySource(_, dbCallsPerSelect.flatten.dedup.l, tagName))
                    val m2: Map[AstNode, List[List[AstNode]]] = ( vulnerableSelect zip dbCallsToSink ).toMap
                    
                    val insertCols = vulnerableInsert.map(_.tag.name("QUERY_COLUMNS").value.headOption.getOrElse("NA").split(", ").toList)
                    val selectCols = vulnerableSelect.map(_.tag.name("QUERY_COLUMNS").value.headOption.getOrElse("NA").split(", ").toList)

                    val columnMatching: Map[Int, List[Int]] = ( insertCols.indices zip insertCols.map(_.flatMap(queryCol => selectCols.filter(_.contains(queryCol))).toSet).map(CpgUtils.indicesOfElements(_, selectCols)) ).toMap
                    val interQueryPaths: List[List[AstNode]] = columnMatching.keySet.toList.map(insertIndex => {
                            val insertQuery = vulnerableInsert(insertIndex)
                            val insertPaths = m1(insertQuery)
                            val selectQuery = columnMatching(insertIndex).map(vulnerableSelect(_))
                            val selectPaths = selectQuery.map(m2(_)).filterNot(_.isEmpty)
                            val queryPaths = for { x <- insertPaths; y <- selectPaths.flatten } yield (x++y)
                            queryPaths
                        }).filterNot(_.isEmpty).flatten
                    interQueryPaths
                }
            }
        }
        if (debug) println("Number of paths across the CPG and database: " + cpgDatabasePaths.size)
        logger ++= List(cpgDatabasePaths.size.toString)

        val totalPaths = (withoutDbCalls ++ cpgDatabasePaths)
        if (debug) println("Total paths: " + totalPaths.size)
        logger ++= List(totalPaths.size.toString)

        // if methodParamIn depends on a sanitized node: the path is sanitized
        val unsanPaths = totalPaths.filterNot(path => path.dropRight(1).zip(path.drop(1)).map(
            (r,c) => (r.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE") && (c.isInstanceOf[MethodParameterIn])
            ).contains(true)).filterNot(_.map(_.tag.name(tagName).value.headOption.getOrElse("NA") == "TRUE").contains(true))
        if (debug) println("Total unsanitized paths: " + unsanPaths.size)
        val dedupPaths = unsanPaths.groupBy(path => List(path.head, path.last)).map(_._2.head)
        if (debug) println("Total deduplicated unsanitized paths: " + dedupPaths.size)
        logger ++= List(dedupPaths.size.toString)
        if (debug) println()
        dedupPaths
    }
    
    def getAllPaths(debug:Boolean = true) = {
        // map every vulnerability in the list to its list of possible paths
        val t0 = System.nanoTime()
        logger ++= List(cpg.metaData.root.head.split("/").last)
        logger ++= List(cpgSize.toString)

        if (debug) println("Attacker-controlled sources size: " + sources.size + "\n")
        logger ++= List(sources.size.toString)
        logger ++= List(vulnerableInsert.size.toString)
        logger ++= List(vulnerableSelect.size.toString)

        val result = (CpgUtils.vulnerabilities zip CpgUtils.vulnerabilities.map(getPaths(_, true))).toMap
        val t1 = System.nanoTime()
        if (debug) println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
        logger ++= List(((t1 - t0)*1e-9).toString)

        if (debug) println("Sanitization exception rate: " + CpgUtils.exceptionRate())
        logger ++= List(CpgUtils.exceptionRate().toString)

        if (debug) println(result.transform{(k,v) => v.size})
        result
    }

    def getStats() = {
        val result = getAllPaths(true)
        result.transform{(k,v) => v.size}
    }

    def outputPaths(debug: Boolean = true) = {
        val results = getAllPaths(debug)
        val output: String = results.transform{(k,v) => 
            v.map(path => {
                val pathID = v.toSeq.indexOf(path) + 1
                path.map(x => {
                    val tagName = CpgUtils.getTagName(k)
                    val sinkFunctions = CpgUtils.getSinks(k)
                    "{\n\t\"pathid\": " + pathID + ",\n" + 
                    "\t\"vulnerability\": \"" + k + "\",\n" + 
                    "\t\"nodeid\": " + x.id + ",\n" +
                    "\t\"methodname\": \"" + CpgUtils.getMethodName(x) + "\",\n" +
                    "\t\"filename\": \"" + cpg.metaData.root.head.split("/").last + "/" + x.file.name.headOption.getOrElse("").replace("\"", "\\\"") + "\",\n" +
                    "\t\"linenumber\": " + x.lineNumber.getOrElse("") + ",\n" +
                    "\t\"code\": \"" + x.code.replace("\\", "\\\\").replace("\"", "\\\"") + "\",\n" +
                    "\t\"sanitized\": \"" + x.tag.name(tagName).value.headOption.getOrElse("NA") + "\"\n},"
                }).mkString("\n")
            }).mkString("[", "\n", "]")
        }.values.filter(!_.isEmpty).mkString("").replace("[]", "").replace("},]", "}]").replace("][", ",")
        
        // Write JSON output
        val jsonPath = Paths.get("output/paths/" + 
            cpg.metaData.root.head.split("/").last.split('.').head.replaceAll("[^a-zA-Z]", "").toLowerCase + "-output.json")
        Files.createDirectories(jsonPath.getParent)
        Files.write(jsonPath, output.getBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)
        
        // Append stats to CSV
        val csvPath = Paths.get("output/stats.csv")
        Files.createDirectories(csvPath.getParent)
        Files.write(csvPath, (logger.mkString(",") + "\n").getBytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND)

        "Successfully written vulnerability paths to " + jsonPath.toString + " and appended metrics to " + csvPath.toString
    }

}