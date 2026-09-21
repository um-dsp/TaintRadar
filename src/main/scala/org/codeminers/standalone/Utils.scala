package org.codeminers.standalone

import io.shiftleft.passes.CpgPass
import io.shiftleft.codepropertygraph.generated.{Cpg, NodeTypes, DiffGraphBuilder}
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Identifier, Literal, FieldIdentifier, Method, Call, MethodParameterIn, Return, Block, StoredNode, TypeRef, MethodReturn, Tag, File}
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import java.nio.file.{Files, Paths, StandardOpenOption}

import org.codeminers.standalone.Constants.ConstantsFactory

class Utils(cpg: Cpg) {
    val vulnerabilities: List[String] = {
        if (cpg.metaData.head.language == "java") List("SQL Injection", "XSS")
        else List("Code Injection", "Command Execution", "File Inclusion", "Session Fixation", "File Access", "SQL Injection", "XSS")
    }
    // TAINTRADAR_VULNS restricts a run to part of the list above: a comma-separated list of
    // names, matched on letters only e.g. "XSS", "xss" and "SQL_Injection".
    val selectedVulnerabilities: List[String] = {
        def key(name: String) = name.replaceAll("[^a-zA-Z]", "").toLowerCase
        val requested = sys.env.getOrElse("TAINTRADAR_VULNS", "").split(",").toList.map(key).filter(_.nonEmpty)
        if (requested.isEmpty) vulnerabilities
        else {
            val unknown = requested.filterNot(r => vulnerabilities.map(key).contains(r))
            if (unknown.nonEmpty)
                throw new IllegalArgumentException(
                    "TAINTRADAR_VULNS: unknown vulnerability " + unknown.mkString(", ") +
                    ". Known for this language: " + vulnerabilities.mkString(", "))
            vulnerabilities.filter(v => requested.contains(key(v)))
        }
    }

    val Constants = ConstantsFactory.getConstants(cpg.metaData.head.language)
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

    def getFilesFromInclude(call: Call): List[File] = {
        if (call.isCallTo("include|include_once|require|require_once").isEmpty) {
            List()
        }
        else {
            val file_names = call.argument.filter(_.isInstanceOf[Literal]).code.map(_.replaceAll("\"", "")).l
            cpg.file.filter(f => file_names.contains(f.name)).l
        }
    }

    def callsTo(method: Method): List[Call] =
        cpg.call.nameExact(method.name).filter(c => c.methodFullName == method.fullName || c.methodFullName == method.name).l

    def argumentAt(call: Call, index: Int): Option[AstNode] =
        call.argument.l.find(_.argumentIndex == index)

    def byReferenceDefinitions(identifier: Identifier): List[AstNode] =
        List(identifier.astParent).collect { case call: Call => call }.flatMap(call =>
            call.callee.filter(_.code != "<empty>").l.flatMap(method =>
                method.parameter.l
                    .filter(parameter => parameter.index == identifier.argumentIndex && parameter.evaluationStrategy == "BY_REFERENCE")
                    .flatMap(parameter => method.methodReturn.ddgIn.collectAll[Identifier].nameExact(parameter.name).l)
            )
        )

    var dataFlowStepMap = collection.mutable.Map[AstNode, List[AstNode]]()
    // reachibilityArgs maps the first field access call node of backward data flow to a map of definitions and their scope
    // FieldAccess Call (Sink) -> { Definition Node -> Scope: (CallStack, VarStack) }
    var reachabilityArgs = collection.mutable.Map[Call, collection.mutable.Map[Call, (List[Call], List[String])]]()

    // getReachingDef is pure, so it can be cached on its whole input. dataFlowStepMap cannot
    // hold it: that map is keyed on the node alone, which is why field accesses are evicted below.
    private val fieldAccessDefs =
        collection.mutable.Map[(Call, List[Call], List[String]), Map[Call, (List[Call], List[String])]]()

    // Per-node facts behind the two resolver arguments. `assignment` walks the node's whole AST
    // subtree and isCallTo compiles a regex, so both are memoized and folded by Frontier below.
    private val assignmentsUnder = collection.mutable.Map[AstNode, List[Call]]()
    private def assignmentsIn(node: AstNode): List[Call] =
        assignmentsUnder.getOrElseUpdate(node, List(node).isCall.assignment.l)

    private val fieldAccessOf = collection.mutable.Map[AstNode, Option[Call]]()
    private def asFieldAccess(node: AstNode): Option[Call] =
        fieldAccessOf.getOrElseUpdate(node, List(node).isCallTo("<operator>.fieldAccess").headOption)

    // A partial path, newest node first so extending it and reading its head are O(1). The two
    // resolver facts are folds over the path in order: first field access wins, last assignment wins.
    private final case class Frontier(nodes: List[AstNode],
                                      firstFieldAccess: Option[Call],
                                      lastAssignment: Option[Call]) {
        def node: AstNode = nodes.head
        def sinkFirst: List[AstNode] = nodes.reverse
        def extend(next: AstNode): Frontier = Frontier(
            next :: nodes,
            firstFieldAccess.orElse(asFieldAccess(next)),
            assignmentsIn(next).lastOption.orElse(lastAssignment))
    }

    private def frontierOf(path: List[AstNode]): Frontier =
        path.foldLeft(Frontier(List(), None, None))((frontier, node) => frontier.extend(node))

    def dataFlowStep(node: AstNode, goToCallIn: Boolean = true)(implicit resolver: (Option[Call], Option[Call])): List[AstNode] = {
        dataFlowStepMap.get(node) match {
            case Some(queryData: List[AstNode]) => queryData
            case None => {
                val result = {
                    node match {
                        // For a call node: traverse its arguments and method definition node
                        case call: Call => {
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
                                    reachabilityArgs(startNode) = collection.mutable.Map[Call, (List[Call], List[String])]()
                                }
                                val scope = resolver._2
                                    .map(lastAssignment =>
                                        reachabilityArgs(startNode).getOrElse(lastAssignment, (List(), List()))
                                    )
                                    .getOrElse((List(), List()))
                                val defMaps = fieldAccessDefs.getOrElseUpdate(
                                    (call, scope._1, scope._2),
                                    getReachingDef(call, call.code, 0, scope._1, scope._2, Set(call.id)))
                                reachabilityArgs(startNode) ++= defMaps
                                if (defMaps.keys.nonEmpty) defMaps.keys.toList
                                else call.argument.l.collect { case field: FieldIdentifier => field }
                            }
                            else method.filterNot(_.code == "<empty>").l ++ arguments
                            // method.filterNot(_.code == "<empty>").l ++ arguments
                        }
                        // For an identifier: if it points to a method parameter, traverse this parameter, otherwise follow the data dependency edges
                        case identifier: Identifier => {
                            if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None))) {
                                identifier.method.parameter.name(identifier.name).l
                            } else if (byReferenceDefinitions(identifier).nonEmpty) {
                                byReferenceDefinitions(identifier)
                            } else {
                                if (identifier.ddgIn.l.isEmpty) {
                                    val files = identifier.file.head.ast.isCallTo("include|include_once|require|require_once").flatMap(getFilesFromInclude)
                                    files.method.filter(_.name == "<global>").methodReturn.ddgIn.filter(_.isIdentifier).asInstanceOf[Iterator[Identifier]].filter(_.name == identifier.name).l
                                }
                                else identifier.ddgIn.l
                            }
                        }
                        // For a literal: output the literal
                        case literal: Literal => List(literal)
                        // For a method parameter: potentially go to all method callers and output their corresponding argument (same index as the parameter)
                        // This is intended to be performed only if the path started within the method node itself, otherwise don't output anything
                        case parameter: MethodParameterIn => {
                            if (goToCallIn) callsTo(parameter.method).flatMap(argumentAt(_, parameter.index))
                            else List()
                        }
                        // For a constant, try resolving it statically by checking the "define" function calls
                        case constant: FieldIdentifier => {
                            if (Constants.magic_constants.contains(constant.canonicalName) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) List()
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
                    case function: Call => {
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

    // Everything the backward walk from `sinks` reaches within the round budget. The walk reads
    // only `sinks`, so it is run once per sink list and shared by every node asked about it.
    private val reachableFromCache = collection.mutable.Map[List[AstNode], Set[AstNode]]()

    private def reachableFrom(sinks: List[AstNode]): Set[AstNode] =
        reachableFromCache.getOrElseUpdate(sinks, {
            var seen = Set[AstNode]()
            var frontier = sinks
            var i = 0
            while (i < 100 && frontier.nonEmpty) {
                seen = seen ++ frontier
                frontier = frontier.flatMap(n => dataFlowStep(n)(None, None)).dedup.l.filterNot(seen.contains)
                i = i + 1
            }
            seen
        })

    // Checks whether the node is reachable by any element of sinks
    def isReachableBy(node: AstNode, sinks: List[AstNode]): Boolean = reachableFrom(sinks).contains(node)
    
    private def expandFrontiers(frontiers: List[Frontier], visited: Set[AstNode], tagName: String,
                                stopAtSanitized: Boolean): (List[Frontier], Boolean) = {
        val output = collection.mutable.ListBuffer[Frontier]()
        var extended = false
        frontiers.foreach { frontier =>
            val node = frontier.node
            val reachingDefs = dataFlowStep(node, !node.isMethod)(frontier.firstFieldAccess, frontier.lastAssignment)
                .filterNot(d => visited.contains(d) ||
                    (stopAtSanitized && d.tag.name(tagName).value.headOption.getOrElse("NA") == "TRUE"))
            if (reachingDefs.isEmpty) output += frontier
            else {
                extended = true
                reachingDefs.foreach(d => output += frontier.extend(d))
            }
        }
        (output.toList, extended)
    }

    // stopAtSanitized drops a reaching definition that is labelled sanitized, which ends the walk there
    def getReachingDefs(paths: List[List[AstNode]], source: List[AstNode], tagName: String, stopAtSanitized: Boolean = true): List[AstNode] = {
        val targets = source.toSet
        var frontiers = paths.map(frontierOf)
        var result: List[AstNode] = List()
        var running = true
        try {
            while (running) {
                // doubles as the node budget below, charged against the round's input as before
                val visited = frontiers.iterator.flatMap(_.nodes).toSet
                val (output, extended) = expandFrontiers(frontiers, visited, tagName, stopAtSanitized)
                val found = output.find(_.nodes.exists(targets.contains))
                if (found.nonEmpty) { result = found.get.sinkFirst; running = false }
                else if (!extended) running = false
                else if (visited.size > 500) running = false
                else frontiers = output
            }
        }
        catch {
            case _ => result = List()
        }
        result
    }

    // One walk that resolves every source, instead of one walk per source.
    def getReachingDefsMulti(paths: List[List[AstNode]], sources: List[AstNode], tagName: String,
                             stopAtSanitized: Boolean = true): collection.Map[AstNode, List[AstNode]] = {
        val resolved = collection.mutable.HashMap[AstNode, List[AstNode]]()
        // no sources means no walk at all, as mapping over an empty list did
        if (sources.isEmpty) return resolved
        var pending = sources.toSet
        var frontiers = paths.map(frontierOf)
        var running = true
        try {
            while (running) {
                val visited = frontiers.iterator.flatMap(_.nodes).toSet
                val (output, extended) = expandFrontiers(frontiers, visited, tagName, stopAtSanitized)
                if (pending.nonEmpty) {
                    // first path holding each outstanding source. Sources are answered
                    // independently, so two of them may share a path.
                    val firstPath = collection.mutable.HashMap[AstNode, Frontier]()
                    output.foreach(frontier => frontier.nodes.foreach(node =>
                        if (pending.contains(node) && !firstPath.contains(node)) firstPath(node) = frontier))
                    pending.foreach(source => firstPath.get(source).foreach(f => resolved(source) = f.sinkFirst))
                    pending = pending.filterNot(resolved.contains)
                }
                if (!extended) running = false
                else if (visited.size > 500) running = false
                else frontiers = output
            }
        }
        catch {
            // the per-source walk lost only the source it was on; ones answered in earlier
            // rounds had already returned, so they are kept here too
            case _ => ()
        }
        resolved
    }

    // TAINTRADAR_VERIFY_MULTI=1 runs the per-source walk alongside the batched one and reports
    // disagreements. A mismatch detector as running both doubles reachabilityArgs writes.
    private val verifyMulti = sys.env.get("TAINTRADAR_VERIFY_MULTI").contains("1")

    def reachableBySource(sink: AstNode, sources: List[AstNode] = List(), tagName: String, stopAtSanitized: Boolean = true): List[List[AstNode]] = {
        val resolved = getReachingDefsMulti(List(List(sink)), sources, tagName, stopAtSanitized)
        // the caller's source order, and a source listed twice is answered twice
        val paths: List[List[AstNode]] = sources.flatMap(source => resolved.get(source).map(_.reverse))
        if (verifyMulti) {
            val reference = sources.map(source =>
                getReachingDefs(List(List(sink)), List(source), tagName, stopAtSanitized).reverse).filterNot(_.isEmpty)
            if (reference != paths)
                println("VERIFY_MULTI mismatch at sink " + sink.id +
                    ": per-source found " + reference.size + " paths, batched found " + paths.size)
        }
        paths
    }

    // paths found by Joern's own data flow engine, from the sinks back to the sources
    // the engine solves its tasks in parallel, so the paths are sorted to keep runs reproducible
    def getJoernPaths(sinks: List[Call], sources: List[AstNode] = List()): List[List[AstNode]] = {
        implicit val engineContext: EngineContext = EngineContext()
        import scala.math.Ordering.Implicits.seqOrdering
        sinks.reachableByFlows(sources).map(_.elements).l.sortBy(_.map(_.id))
    }

    def getNodesFromID(path: List[Long]): List[AstNode] = {
        path.map(cpg.method.ast.id(_).head)
    }

    def getMethodName(node: AstNode) = {
        node match {
            case identifier: Identifier => identifier.method.name
            case call: Call => call.method.name
            case param: MethodParameterIn => param.method.name
            case _ => "" 
        }
    }

    def getTagName(vulnerability: String) = {
        "SAN_" + vulnerability.replace(" ", "_")
    }

    def isRelevantType(node: AstNode): Boolean = {
        node.isInstanceOf[Call] || 
        node.isInstanceOf[Identifier] || 
        node.isInstanceOf[Literal] || 
        node.isInstanceOf[MethodParameterIn] ||
        node.isInstanceOf[FieldIdentifier] || 
        node.isInstanceOf[Return]
    }

    def augmentWithSanTag() = {
        // get all sink functions for the given vulnerability
        selectedVulnerabilities.map(vulnerability => {
            val attack_san_functions = getSanitization(vulnerability)
            val tagName = getTagName(vulnerability)
            
            val pass = new CpgPass(cpg) {
                override val name = "SanitizationTagger"
                
                override def run(builder: DiffGraphBuilder): Unit = {
                    implicit val diffGraph: DiffGraphBuilder = builder
                    
                    cpg.method.ast.filter(isRelevantType)
                        .filter(sanitizationObject.isSanitized(_)(attack_san_functions))
                        .newTagNodePair(tagName, "TRUE")
                        .store()
                        
                    cpg.method.ast.filter(isRelevantType)
                        .filterNot(sanitizationObject.isSanitized(_)(attack_san_functions))
                        .newTagNodePair(tagName, "FALSE")
                        .store()
                }
            }
            pass.createAndApply()
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
        val objects = it.map(x => {
                (x.productElementNames.l.zip(x.productIterator.l).toMap ++ x.tag.map(y => (y.name, y.value)).toMap + ("file" -> x.file.name.headOption.getOrElse("None")))
            }).toList
        
        def quoteJsonString(s: String): String =
            "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\""

        def valueToJsonString(value: Any): String = value match {
            case null => "null"
            case None => "null"
            case Some(v) => valueToJsonString(v)
            case s: String => quoteJsonString(s)
            case b: Boolean => b.toString
            case n: (Int | Long | Short | Byte | Float | Double) => n.toString
            case seq: IndexedSeq[_] => quoteJsonString(seq.mkString(""))
            case other => quoteJsonString(other.toString)
        }

        def mapToJsonString(map: Map[String, Any]): String = {
            val pairs = map.map { case (key, value) => quoteJsonString(key) + ":" + valueToJsonString(value) }
            "{" + pairs.mkString(",") + "}"
        }
        
        val jsonObjects = objects.map(mapToJsonString)
        "[" + jsonObjects.mkString(",\n") + "]"
    }
    
    def cpgToJson(fileName: String = "cpg.json") = {
        val outputPath = Paths.get("output/" + fileName)
        Files.createDirectories(outputPath.getParent)
        Files.write(outputPath, iteratorToJson(cpg.all.filterNot(_.isInstanceOf[Tag])).getBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)
        // iteratorToJson(cpg.all.filterNot(_.isInstanceOf[Tag])) #> "cpg.json"
    }

    def relevantCpgToJson(fileName: String = "relevant-cpg.json") = {
        val outputPath = Paths.get("output/" + fileName)
        Files.createDirectories(outputPath.getParent)
        Files.write(outputPath, iteratorToJson(cpg.method.ast.filter(isRelevantType)).getBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)
        // iteratorToJson(cpg.method.ast.filter(isRelevantType)) #> "relevant-cpg.json"
    }
}