package org.codeminers.standalone

import io.shiftleft.codepropertygraph.generated.{Cpg, NodeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, MethodParameterIn}
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*
import scala.math.Ordering.Implicits.seqOrdering

import org.codeminers.standalone.Constants.ConstantsFactory
import org.codeminers.standalone.Utils

import java.nio.file.{Files, Paths, StandardOpenOption}

object NavexMain {
    def augment(utils: Utils, module: Module, verbose: Boolean = false): Unit = {
        if (module.includes(Module.Sanitization)) {
            if (verbose) println("Applying sanitization augmentation...")
            utils.augmentWithSanTag()
            if (verbose) println("Sanitization augmentation completed")
        }
        if (module.includes(Module.Database)) {
            if (verbose) println("Applying database queries augmentation...")
            utils.augmentWithQueryTag()
            if (verbose) println("Database queries augmentation completed with the following output:")
            utils.debugDatabaseParsing()
        }
    }
}

class NavexMain(val cpg: Cpg, val shouldAugment: Boolean, val module: Module = Module.Database) {

    val CpgUtils = Utils(cpg)
    val Constants = ConstantsFactory.getConstants(cpg.metaData.head.language)
    val cpgSize = cpg.all.size
    if (shouldAugment) NavexMain.augment(CpgUtils, module)


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
        val unsanSinks: List[Call] = {
            if (module.includes(Module.Sanitization)) totalSinks.filter(_.argument.tag.name(tagName).value.contains("FALSE")).l
            else totalSinks
        }
        if (debug) {
            println("Sensitive unsanitized sink functions size: " + unsanSinks.size)
            logger ++= List(unsanSinks.size.toString)
        }

        unsanSinks
    }

    // Three shapes of attacker input in PHP.
    //
    // A superglobal is an identifier, and it is the source whether it is subscripted
    // ($_GET["x"]) or read whole ($tainted = $_POST), so the identifier is what we anchor
    // on: matching the index access instead misses every whole-array read.
    val superglobalSources: List[AstNode] =
        cpg.identifier.filter(node => Constants.attacker_input.contains(node.name) || Constants.attacker_input.contains(node.code)).l

    // An index access is still needed for a superglobal that is not an identifier, as in
    // $GLOBALS["_GET"]["x"], where the name is a string key.
    val indexAccessCandidates: List[Call] =
        cpg.call("<operator>.indexAccess").filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).l
    private val candidateIds: Set[Long] = (superglobalSources.map(_.id) ++ indexAccessCandidates.map(_.id)).toSet
    val indexAccessSources: List[AstNode] =
        indexAccessCandidates.filterNot(node => node.ast.exists(child => child.id != node.id && candidateIds.contains(child.id)))

    // filter_input(INPUT_GET, ...) and filter_input_array(INPUT_GET, ...) name the input
    // in the INPUT_* argument, which reaches the CPG as a field access, and
    // getallheaders() names it in the call itself.
    val callSources: List[AstNode] =
        cpg.call.filter(node => Constants.attacker_input.contains(node.name) || Constants.attacker_input.contains(node.code)).l

    val sources: List[AstNode] = superglobalSources ++ indexAccessSources ++ callSources
    // val sources = cpg.call.filter(f => Constants.attacker_object_types.map(f.typeFullName.contains(_)).contains(true)).l
    println("Sources size: " + sources.size)
    
    val databaseCalls = getSinkCalls("Stored XSS", CpgUtils.getTagName("XSS"), false)

    // The read side of a second-order flow, used only to link a SELECT to the sinks it
    // feeds. getSinkCalls keeps a call only when one of its arguments is labelled unsanitized
    val databaseReads: List[Call] = {
        val readFunctions = CpgUtils.getSinks("Stored XSS")
        cpg.call.filter(node => readFunctions.contains(node.name)).l
    }

    val insertStatements = CpgUtils.db.queryStatements.filter(c => List("INSERT", "UPDATE").contains(c.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA"))).filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE")
    val vulnerableInsert = if (insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)).size > 0) insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls)) else insertStatements
    // val vulnerableInsert = insertStatements.filter(CpgUtils.isReachableBy(_, databaseCalls))
    val dbCallsPerInsert = vulnerableInsert.map(q => databaseCalls.filter(dbcall => CpgUtils.isReachableBy(q, List(dbcall))))
    val dbCallsToSource = dbCallsPerInsert.map(dbcall => sources.map(s => CpgUtils.getReachingDefs(dbcall.map(List(_)), List(s), "SAN_XSS").reverse).filterNot(_.isEmpty))
    val m1: Map[AstNode, List[List[AstNode]]] = (vulnerableInsert zip  dbCallsToSource).toMap


    val selectStatements = CpgUtils.db.queryStatements.filter(_.tag.name("QUERY_TYPE").value.headOption.getOrElse("NA")=="SELECT").filter(_.tag.name("QUERY_LABEL").value.headOption.getOrElse("NA")=="UNSAFE").l
    val vulnerableSelect = if (selectStatements.filter(CpgUtils.isReachableBy(_, databaseReads)).size > 0) selectStatements.filter(CpgUtils.isReachableBy(_, databaseReads)) else selectStatements
    val dbCallsPerSelect = vulnerableSelect.map(q => databaseReads.filter(dbcall => CpgUtils.isReachableBy(q, List(dbcall))))
    
    // val vulnerableSelect = selectStatements.filter(CpgUtils.isReachableBy(_, databaseCalls))
        
    def getPaths(vulnerability: String, debug: Boolean = false): Iterable[List[AstNode]] = {
        println(vulnerability)
        val tagName: String = CpgUtils.getTagName(vulnerability)
        if (module == Module.VanillaJoern) getJoernPaths(vulnerability, tagName, debug)
        else getTaintRadarPaths(vulnerability, tagName, debug)
    }

    // Paths found by Joern's data flow engine, from the sink calls back to the sources
    private def getJoernPaths(vulnerability: String, tagName: String, debug: Boolean): Iterable[List[AstNode]] = {
        val sinks: List[Call] = getSinkCalls(vulnerability, tagName, debug)
        val paths: List[List[AstNode]] = CpgUtils.getJoernPaths(sinks, sources)
        if (debug) println("Number of paths within CPG: " + paths.size)
        logger ++= List(paths.size.toString)

        val withoutDbCalls = paths.filterNot(p => p.dropRight(1).exists(databaseCalls.contains(_)))
        // no paths across the database
        logger ++= List("0")
        logger ++= List(paths.size.toString)

        val dedupPaths = withoutDbCalls.groupBy(path => List(path.last)).map(_._2.head).toList.sortBy(_.map(_.id))
        if (debug) println("Total deduplicated unsanitized paths: " + dedupPaths.size)
        logger ++= List(dedupPaths.size.toString)
        if (debug) println()
        dedupPaths
    }

    private def getTaintRadarPaths(vulnerability: String, tagName: String, debug: Boolean): Iterable[List[AstNode]] = {
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
            if (!module.includes(Module.Database) || vulnerability=="SQL Injection" || sinks.isEmpty) List()
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
                    val dbCallsToSink = dbCallsPerSelect.map(dbcall => sinks.flatMap(s => CpgUtils.reachableBySource(s, dbcall, tagName, false)))

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
        def isSanitizedPath(path: List[AstNode]): Boolean =
            path.dropRight(1).zip(path.drop(1)).map(
                (r,c) => (r.tag.name(tagName).value.headOption.getOrElse("NA")=="TRUE") && (c.isInstanceOf[MethodParameterIn])
                ).contains(true) ||
            path.map(_.tag.name(tagName).value.headOption.getOrElse("NA") == "TRUE").contains(true)

        // A path that crosses the database is assembled from two legs that were each
        // checked already: the source-to-INSERT leg stopped at any sanitized node, and the
        // sink of the SELECT-to-sink leg is unsanitized by construction. Checking it again
        // node by node would discard it over the query handle of the SELECT, so only the
        // paths found within the CPG are filtered here.
        val unsanPaths = withoutDbCalls.filterNot(isSanitizedPath) ++ cpgDatabasePaths
        if (debug) println("Total unsanitized paths: " + unsanPaths.size)
        val dedupPaths = unsanPaths.groupBy(path => List(path.head, path.last)).map(_._2.head).toList.sortBy(_.map(_.id))
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

        val result = (CpgUtils.vulnerabilities zip CpgUtils.vulnerabilities.map(vulnerability =>
            if (CpgUtils.selectedVulnerabilities.contains(vulnerability)) getPaths(vulnerability, true)
            else {
                if (debug) println(vulnerability + ": skipped (TAINTRADAR_VULNS)\n")
                logger ++= List.fill(6)("0")
                List()
            }
        )).toMap
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
        
        // Append stats to CSV, starting with a header row when the file is new
        val csvPath = Paths.get("output/stats.csv")
        Files.createDirectories(csvPath.getParent)
        if (!Files.exists(csvPath) || Files.size(csvPath) == 0) {
            val vulnerabilityColumns = List("Sinks", "Unsanitized Sinks", "CPG Paths", "Inter Database paths", "Total Paths", "Total Deduplicated Paths")
            val header = List("Approach", "Language", "Web Application", "CPG Size", "Sources", "Insert Sinks", "Select Sources") ++
                CpgUtils.vulnerabilities.flatMap(v => vulnerabilityColumns.map(v + " " + _)) ++
                List("Time", "Sanitization Exception Rate")
            Files.write(csvPath, (header.mkString(",") + "\n").getBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)
        }
        val row = List(module.label, cpg.metaData.head.language.toUpperCase) ++ logger
        Files.write(csvPath, (row.mkString(",") + "\n").getBytes, StandardOpenOption.CREATE, StandardOpenOption.APPEND)

        "Successfully written vulnerability paths to " + jsonPath.toString + " and appended " + module.label + " metrics to " + csvPath.toString
    }

}