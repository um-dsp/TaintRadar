object Constants {

  val attacker_input = List("_GET", "_POST", "_COOKIE", "_REQUEST", "_ENV", "HTTP_.*", "QUERY_STRING", "_FILES")

  val sql_func: List[String] = List("mysql_", "mysqli_", "pg_", "sqlite_")

  val sqli_sink: List[String] = List(
    // MySQLi Functions
    "mysqli_query",
    "mysqli_multi_query",
    "mysqli_real_query",
    "mysqli_fetch_assoc",
    "mysqli_fetch_array",
    "mysqli_fetch_object",
    "mysqli_fetch_row",
    // mysql_ Functions (Deprecated)
    "mysql_query",
    "mysql_fetch_assoc",
    "mysql_fetch_array",
    "mysql_fetch_object",
    "mysql_fetch_row",
    // PostgreSQL Functions
    "pg_query",
    "pg_query_params",
    "pg_fetch_array",
    "pg_fetch_assoc",
    "pg_fetch_object",
    "pg_fetch_row",
    // SQLite Functions
    "sqlite_query",
    "sqlite_exec",
    "sqlite_fetch_array",
    "sqlite_fetch_single",
    "sqlite_fetch_string",
    "sqlite_fetch_all",
    "sqlite_single_query"
  )

  val commandexec_sink = List("shell_exec", "exec", "system", "mail", "popen", "expect_popen", "passthru", "pcntl_exec", "proc_open")
  
  val codeinj_sink = List("eval", "assert")

  val fileinc_sink = List("include", "require", "include_once", "require_once")

  val xss_sink = List("print", "echo", "printf")

  val fileaccess_sink = List("fopen")

  val sessionfixation_sink = List("setcookie")

  val san_functions_sql = List( 
    "addslashes",
    "dbx_escape_string",
    "db2_escape_string",
    "ingres_escape_string",
    "maxdb_escape_string",
    "maxdb_real_escape_string",
    "mysql_escape_string",
    "mysql_real_escape_string",
    "mysqli_escape_string",
    "mysqli_real_escape_string",
    "pg_escape_string", 
    "pg_escape_bytea",
    "sqlite_escape_string",
    "sqlite_udf_encode_binary",
    "cubrid_real_escape_string")

  val san_functions_xss = List("htmlentities",
    "htmlspecialchars",
    "sanitize")

  val san_functions_all = List(
    "isset",
    "intval",
    "floatval",
    "doubleval",
    "filter_input",
    "urlencode",
    "rawurlencode",
    "round",
    "floor",
    "strlen",
    "strrpos",
    "strpos",
    "strftime",
    "strtotime",
    "md5",
    "md5_file",
    "sha1",
    "sha1_file",
    "crypt",
    "crc32",
    "hash",
    "mhash",
    "hash_hmac",
    "password_hash",
    "mcrypt_encrypt",
    "mcrypt_generic",
    "base64_encode",
    "ord",
    "sizeof",
    "count",
    "bin2hex",
    "levenshtein",
    "abs",
    "bindec",
    "decbin",
    "dechex",
    "decoct",
    "hexdec",
    "rand",
    "max",
    "min",
    "metaphone",
    "tempnam",
    "soundex",
    "money_format",
    "number_format",
    "date_format",
    "filetype",
    "nl_langinfo",
    "bzcompress",
    "convert_uuencode",
    "gzdeflate",
    "gzencode",
    "gzcompress",
    "http_build_query",
    "lzf_compress",
    "zlib_encode",
    "imap_binary",
    "iconv_mime_encode",
    "bson_encode",
    "sqlite_udf_encode_binary",
    "session_name",
    "readlink",
    "getservbyport",
    "getprotobynumber",
    "gethostname",
    "gethostbynamel",
    "gethostbyname",
    "date", "ctype_digit")
  
  val san_functions_code = List()

  val san_functions_os_command  = List("escapeshellarg",
    "escapeshellcmd")
  
  val san_functions_file= List("basename",
    "dirname",
    "pathinfo")
}

class SanitizationFilter(val cpg: Cpg) {
   /*
      Sanitization Filter object requires a vulnerabilityType object (attack name & sanitization functions list) as an implicit parameter
      Useful Methods:
         set(Cpg): sets the CPG variable for further use
         isMethodSanitized: outputs whether a function call is sanitized
         isSanitized: outputs whether a node is sanitized
   */
   implicit val resolver: ICallResolver = NoResolve
   var exceptions = 0
   // CONF: safe types in PHP
   val safe_types: List[String] = List("int", "integer", "bool", "boolean", "float", "double")
   // CONF: magic constants in PHP
   val magic_constants: List[String] = List("__LINE__, __FILE__, __DIR__, __FUNCTION__, __CLASS__, __TRAIT__, __METHOD__, __NAMESPACE__")

   case class vulnerabilityType(name: String, sanitization_functions: List[String])
   case class mapInput(id: Long, vulnerabilityName: String)
   var sanitizedNodesMap = collection.mutable.Map[mapInput, Boolean]()
   // stores isSanitized result in a Map for quicker lookup
   case class isSanitizedInput(node: Any, sanitizedParameters: List[Boolean] = List(), vulnerabilityInst: vulnerabilityType)   
   var isSanitizedMap = collection.mutable.Map[isSanitizedInput, Boolean]()

   // var constantTable = None: Option[collection.immutable.Map[String, List[Expression]]]
   val constants: List[String] = cpg.call("define").argument(1).code.l.map(_.replace("\"", "")).distinct
   val values: List[List[Expression]] = constants.map(constant => cpg.call("define").filter(_.argument(1).code.replace("\"", "") == constant).argument(2).l) 
   val constantTable = Some((constants zip values).toMap[String, List[Expression]]) 

   def isMethodSanitized(function: nodes.Call, arguments: List[Expression], sanitizedParameters: List[Boolean])(implicit vulnerabilityInst: vulnerabilityType): Boolean = {
      // if the function is dynamizally dispatched, search cpg for the first function that matches its name, otherwise go to callee
      val method: Method = {
         if (function.dispatchType != "DYNAMIC_DISPATCH") function.callee.head
         else cpg.method(function.name).filter(_.code!="<empty>").head
      }
      // map arguments for the function call on whether they're sanitized or not
      val isArgumentSanitized: List[Boolean] = arguments.map(isSanitized(_, sanitizedParameters)(vulnerabilityInst))
      // sanitization function returns a sanitized result
      if (Constants.san_functions_all.contains(method.name) || vulnerabilityInst.sanitization_functions.contains(method.name)) true
      // dynamic dispatch only supported if the function appears only once in the code
      else if (function.dispatchType == "DYNAMIC_DISPATCH" && cpg.method(function.name).filter(_.code!="<empty>").size > 1) false
      else if (function.name == "<operator>.cast") safe_types.contains(function.typeFullName)
      // an assignment function is sanitized if its second argument is sanitized
      else if (method.name == "<operator>.assignment") isArgumentSanitized(1)
      // CONF: known unsanitized function calls
      else if (method.name == "readline") false
      // if the function isn't user defined (e.g. <operator>.plus) assume it's sanitized only if all arguments are sanitized
      else if (method.code == "<empty>") !isArgumentSanitized.contains(false)
      // else check if return is sanitized given whether passed arguments are sanitized
      else {
         isSanitized(method.ast.isReturn, isArgumentSanitized)(vulnerabilityInst)
      }
   }

   // Check whether given CPG Node is sanitized, filter accordingly
   def isSanitized(node: Any, sanitizedParameters: List[Boolean] = List())(implicit vulnerabilityInst: vulnerabilityType): Boolean = 
      // check the Map to see if node was traversed or not
      isSanitizedMap.get(isSanitizedInput(node, sanitizedParameters, vulnerabilityInst)) match {
      case Some(result) => result
      case None => {
         var mapOut: Boolean = false
         val result: Boolean = 
         try { 
            node match {
            case Some(nodeOption) => isSanitized(nodeOption, sanitizedParameters)(vulnerabilityInst)
            case List() => true
            case traversal: overflowdb.traversal.Traversal[_] => isSanitized(traversal.l, sanitizedParameters)(vulnerabilityInst)
            case listOfNodes: List[_] => listOfNodes.map(isSanitized(_, sanitizedParameters)(vulnerabilityInst)).reduce((x,y) => x && y)
            case literal: Literal => {
               sanitizedNodesMap(mapInput(literal.id, vulnerabilityInst.name)) = true
               true
            }
            case function: nodes.Call => { 
               mapOut = isMethodSanitized(function, function.argument.l, sanitizedParameters)(vulnerabilityInst) 
               sanitizedNodesMap(mapInput(function.id, vulnerabilityInst.name)) = mapOut 
               mapOut
            }
            case identifier: Identifier => {
               // CONF: this & <global> identifiers are sanitized
               if (identifier.name == "<global>" || identifier.name == "this") mapOut = true
               else mapOut = {
                  var isArgumentSanitized = sanitizedParameters
                  // calculate the reaching definition of the identifier
                  val definingNode = {
                     // identifier coming from a method parameter is unsanitized
                     if (identifier.method.parameter.name.l.contains(identifier.name) && identifier.ddgIn.isIdentifier.name(identifier.name).l.isEmpty && (identifier != identifier.astParent.assignment.argument(1).headOption.getOrElse(None)))
                        identifier.method.parameter.name(identifier.name).l
                     // identifier used as argument of settype with a safe type will be sanitized
                     // CONF: function name to set type by reference: settype
                     else if (!identifier.astParent.isCallTo("settype").isEmpty && safe_types.contains(identifier.astParent.isCallTo("settype").argument(2).code.head.replaceAll("\"","")) ){
                        identifier.astParent.isCallTo("settype").argument(2).l
                     }
                     // CfgNode assigning a variable will have ddgIn pointing to the value of the assignment
                     else if (identifier == identifier.astParent.assignment.argument(1).headOption.getOrElse(None)) {
                        identifier.astParent.assignment.argument(2).l
                     }
                     // identifier passed by reference to function
                     else if (identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l.map(p => p.evaluationStrategy == "BY_REFERENCE").lift(identifier.order-1) match {case None => false; case Some(b) => b}) {
                        isArgumentSanitized = identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].argument.l.map(node => {
                           var paramsByRef = node.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l.map(p => p.evaluationStrategy == "BY_REFERENCE")
                           if (!paramsByRef.isEmpty && paramsByRef(node.order-1)) 
                              isSanitized(node.ddgIn.l, sanitizedParameters)(vulnerabilityInst) 
                           else isSanitized(node, sanitizedParameters)(vulnerabilityInst)
                        })
                        identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.methodReturn.ddgIn.isIdentifier.name(identifier.astParent.filter(_.isCall).l.asInstanceOf[List[nodes.Call]].callee.parameter.l(identifier.order-1).name).l
                     }
                     // identifiers from included files            
                     // else if (identifier.ddgIn.isEmpty && !_cpg.isEmpty) {
                     //    val includeNodes = cpg.method("<global>").where(_.namespaceBlock.fullName.filter(_==identifier.file.namespaceBlock.fullName.head)).call("include|require").l
                     //    val argumentList = includeNodes.map(_.repeat(_.argument)(_.until(_.not(_.isCall))).l)
                     //    val literalList = argumentList.map(_.flatMap(node => if (node.isIdentifier && node.code!="<global>") node.repeat(_.ddgIn)(_.until(_.isLiteral)).l else node).distinct)
                     //    val directoryList = literalList.map(_.code.map(_.replaceAll("\"","")).l.reduce((a,b) => a+b))
                     //    val fileIdentifiers = directoryList.flatMap(fileName => cpg.method.where(_.namespaceBlock.fullName("("+cpg.metaData.root.head+"/)?"+fileName.replace("./","")+":<global>")).methodReturn.ddgIn.isIdentifier.name(identifier.name).l)
                     //    fileIdentifiers
                     // }
                     // used variable will have ddgIn periodically pointing to its last usage
                     else {
                        identifier.ddgIn.isIdentifier.name(identifier.name).l
                        // identifier.repeat(_.ddgIn.isIdentifier.name(identifier.name))(_.until(_.astParent.isCallTo("settype|<operator>.assignment").argument(1).isIdentifier.name(identifier.name)))
                     }
                  }
                  // println(node)
                  !definingNode.isEmpty && isSanitized(definingNode, isArgumentSanitized)(vulnerabilityInst)
               }
               sanitizedNodesMap(mapInput(identifier.id, vulnerabilityInst.name)) = mapOut
               mapOut
            }
            case constant: FieldIdentifier => {
               if (constantTable.getOrElse(Map()).get(constant.canonicalName).isEmpty) magic_constants.contains(constant.canonicalName)
               else isSanitized(constantTable.get.get(constant.canonicalName), sanitizedParameters)(vulnerabilityInst)
            }
            case metadata: MetaData => true
            case namespace: Namespace => true
            case namespaceblock: NamespaceBlock => true
            case typedec: TypeDecl => true
            case block: Block => true
            case file: File => true
            case local: Local => true
            case member: Member => true
            case method: Method => false
            // case method: Method => isMethodSanitized(method, method.parameter.l, List.fill(method.parameter.size)(false))(vulnerabilityInst)
            case methodReturn: MethodReturn => true
            case methodParamOut: MethodParameterOut => true
            case methodParam: MethodParameterIn => {
               if (sanitizedParameters.isEmpty) false
               else sanitizedParameters(methodParam.index-1)
            }
            case returnBlock: Return => isSanitized(returnBlock.astChildren, sanitizedParameters)(vulnerabilityInst)
            case declaredtype: Type => true
            case declaredtype: TypeRef => true
            case None => true
            case _ => {
               //println(node)
               false
            }
         } 
         } catch {
            case _ => {
               exceptions = exceptions + 1
               false
            }
         }
         isSanitizedMap(isSanitizedInput(node, sanitizedParameters, vulnerabilityInst)) = result
         result
        }
    }

   def exceptionRate(): String = {
      (exceptions.toFloat/sanitizedNodesMap.size*100).toString + "%"
   }
   
   def printTestOutput() = {
      val t0 = System.nanoTime()
      val vulnerabilityInst = vulnerabilityType(name = "", sanitization_functions = List())
      val sanitized = cpg.identifier.filter(isSanitized(_)(vulnerabilityInst)).name.dedup.l.filter(!List("p1", "p2", "unsan11", "unsan14").contains(_))
      val unsanitized = cpg.identifier.filterNot(isSanitized(_)(vulnerabilityInst)).name.dedup.l.filter(!List("p1", "p2", "san12", "san6", "tmp", "_GET", "san14").contains(_))
      val sanitizedConstants = cpg.method.ast.isFieldIdentifier.filter(isSanitized(_)(vulnerabilityInst)).canonicalName.dedup.l
      val unsanitizedConstants = cpg.method.ast.isFieldIdentifier.filterNot(isSanitized(_)(vulnerabilityInst)).canonicalName.dedup.l
      // val sanitized = cpg.identifier.filter(isSanitized(_)(vulnerabilityInst)).name.dedup.l
      // val unsanitized = cpg.identifier.filterNot(isSanitized(_)(vulnerabilityInst)).name.dedup.l
      println("Sanitized Identifiers: " + (sanitized ::: sanitizedConstants))
      println("Unsanitized Identifiers: " + (unsanitized ::: unsanitizedConstants))
      val t1 = System.nanoTime()
      println("Elapsed time: " + (t1 - t0)*1e-9 + " seconds")
   }
}

import org.simmetrics.StringMetric
import org.simmetrics.metrics.StringMetrics

val sqlStartKeywords: Set[String] = Set("select", "insert", "update", "delete",
                    "create", "alter", "drop", "truncate",
                    "use", "show", "begin", "start transaction", "commit", "rollback")

val removeChars = Set(',', '"', '\\', '`')

val safeSQLFunctions = Set("count(", "sum(", "max(", "min(", "min(", "length(", "len(", "now(", "date(", 
                            "year(", "month(", "day(", "abs(", "round(", "ceil(", "ceiling(", "floor(", 
                            "if(", "rank(", "dense_rank(", "row_number(")

val metric: StringMetric = StringMetrics.levenshtein

val magic_constants: List[String] = List("__LINE__, __FILE__, __DIR__, __FUNCTION__, __CLASS__, __TRAIT__, __METHOD__, __NAMESPACE__")
val constants: List[String] = cpg.call("define").argument(1).code.l.map(_.replace("\"", "")).distinct
val values: List[List[AstNode]] = constants.map(constant => cpg.call("define").filter(_.argument(1).code.replace("\"", "") == constant).argument(2).l) 
val constantTable = Some((constants zip values).toMap[String, List[AstNode]]) 

object QueryType extends Enumeration {
    type QueryType = Value
    val SelectQuery = Value("SELECT")
    val InsertQuery = Value("INSERT")
    val UpdateQuery = Value("UPDATE")
    val OtherQuery = Value("OTHER")
}

object QueryLabel extends Enumeration {
    type QueryLabel = Value
    val SafeQuery = Value("SAFE")
    val UnsafeQuery = Value("UNSAFE")
}

def searchNode(queryRoot: AstNode, code: String): Option[AstNode] = {
    queryRoot match {
        case literal: Literal => {
            if (metric.compare(literal.code, code) > 0.8F) Some(literal)
            else None
        }
        case identifier: Identifier => {
            if (metric.compare(identifier.code, code) > 0.8F) Some(identifier)
            else None
        }
        case call: nodes.Call => {
            if (metric.compare(call.code, code) > 0.8F) Some(call)
            else  call.argument.l.map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
        }
        case constant: FieldIdentifier => {
            if (metric.compare(constant.code, code) > 0.8F) Some(constant)
            else if (magic_constants.contains(constant.canonicalName) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) None
            else constantTable.get(constant.canonicalName).map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
            }
        case _ => {
            println(queryRoot)
            None
            // cpg.method.ast.filter(_.code == code).map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
        }
    }
}

def getCode(node: AstNode, output: String = ""): String = {
    node match {
        case literal: Literal => output + literal.code
        case identifier: Identifier => output + identifier.code
        case call: nodes.Call => {
            if (call.name == "<operator>.concat" || call.name == "encaps") call.argument.l.map(getCode(_, output)).mkString(" ")
            else output + call.code
        }
        case constant: FieldIdentifier => {
            if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) output
            else output + getCode(constantTable.get(constant.canonicalName).head)
            }
        case _ => {
            println(node)
            " "
        }
    }
}

case class DBQuery(data: List[AstNode] = List()) {
    def ++(that: DBQuery): DBQuery = DBQuery(data ++ that.data)
    def ==(that: DBQuery): Boolean = data == that.data
    def dedup(): DBQuery = DBQuery(data.dedup.l)
    def :+(that: AstNode): DBQuery = DBQuery(data :+ that)
    def +:(that: AstNode): DBQuery = DBQuery(that +: data)
    def order(): DBQuery = DBQuery(data.sorted(Ordering.by[AstNode, Long](_.id)) )

    def getQueryCode(): Array[String] = {
        val rawCode = this.data.filterNot(_.isIdentifier).map(getCode(_)).mkString(" ")
        val queryCode = rawCode.replaceAll("""(\w)\*""", "$1 *").split(" ").
                                map(_.replace("\\n", " ").replace("\\t", " ")).flatMap(_.split(" ")).flatMap(_.split(",")).
                                map(token => if ("[\\\"]".r.replaceAllIn(token, "").size==0) "" else token).filterNot(_.isEmpty) 
        val queryIndices: Array[Int] = queryCode.zipWithIndex.collect(x => if (sqlStartKeywords.contains(x._1.toLowerCase().filter(!removeChars.contains(_)))) x._2 else -1).filter(_>=0)
        if (queryIndices.size >= 2) queryCode.slice(queryIndices.head, queryIndices.tail.head)
        else queryCode
    }

    def getQueryType(): QueryType.Value = {
        val queryCode = this.getQueryCode.map(_.toLowerCase()).map(_.filter(!removeChars.contains(_)))
        if (queryCode.contains("insert")) QueryType.InsertQuery
        else if (queryCode.contains("update")) QueryType.UpdateQuery
        else if (queryCode.contains("select")) QueryType.SelectQuery
        else QueryType.OtherQuery
    }
    
    def searchNodeFromQuery(code: String): Option[AstNode] = {
        this.data.map(searchNode(_, code)).filterNot(_ == None).headOption.getOrElse(None)
    }
}

import com.github.tototoshi.csv._

class DatabaseConstraint(val cpg: Cpg) {
    val sanitizationObject = new SanitizationFilter(cpg)
    implicit val vulnerabilityInst: sanitizationObject.vulnerabilityType = sanitizationObject.vulnerabilityType("XSS", Constants.san_functions_xss)
    val removeChars = Set(',', '"', '\\', '`', '\'')
    val calculationPattern = "\\s*([-+=/*><!])\\s*".r

    val databaseCalls = cpg.call.filter(x => Constants.sqli_sink.map(x.name.contains(_)).reduce((x,y) => x || y)).l
    val file_name = cpg.metaData.root.head.split("/").last
    val reader = CSVReader.open("navex_utils/code/db/" + file_name + "-database.csv")
    val reader_data: List[List[String]] = reader.all()
    val list_schema = reader_data.map(ls => List(ls(0), ls(1), ls(3))) 
    val db_schema = scala.collection.mutable.Map[String, Map[String, Boolean]]()
    reader_data.map(row => db_schema(row.head) = db_schema.get(row.head).getOrElse(Map()) + (row(1) -> row(3).toBooleanOption.getOrElse(false)))

    var getQueryMap = collection.mutable.Map[AstNode, DBQuery]()
    def getQuery(node: AstNode, output: DBQuery = DBQuery(), depth: Int = 0): DBQuery = {
        getQueryMap.get(node) match {
            case Some(queryData: DBQuery) => queryData
            case None => {
                val newOutput: DBQuery= output.dedup
                val result: DBQuery = if (depth > 15) newOutput
                else node match {
                    case function: nodes.Call => {
                        if (function.name == "<operator>.concat") {
                            // If concat operator already found
                            function +: function.argument.filterNot(x => x.isLiteral || x.isIdentifier || !x.isCallTo("<operator>.concat").isEmpty || !x.isCallTo("encaps").isEmpty).l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
                        }
                        else if (function.name == "encaps") newOutput
                        else function.argument.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
                    }
                    case identifier: Identifier => {
                        identifier.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup :+ identifier
                    }
                    case literal: Literal => newOutput :+ literal
                    case parameter: MethodParameterIn => newOutput
                    case constant: FieldIdentifier => {
                        if (magic_constants.contains(constant) || constantTable.get.getOrElse(constant.canonicalName, List()).isEmpty) newOutput
                        else constantTable.get(constant.canonicalName).map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
                    }
                    case block: Block => block.ddgIn.l.map(getQuery(_, newOutput, depth+1)).reduceOption((x,y) => x ++ y).getOrElse(DBQuery()).dedup
                    case typeRef: TypeRef => newOutput
                    case _ => {
                        println(node)
                        newOutput
                    }
                }
                getQueryMap(node) = result
                result
            }
        }
    }

    def labelQuery(query: DBQuery): QueryLabel.Value = {
        // println(query)
        val tables: List[String] = db_schema.keys.toList
        query.getQueryType() match {
            case QueryType.OtherQuery => QueryLabel.SafeQuery
            case QueryType.SelectQuery => {
                val queryCode = query.getQueryCode.map(_.filter(!removeChars.contains(_)))
                val queryScope = queryCode.dropWhile(_.toLowerCase() != "select").drop(1).takeWhile(_.toLowerCase() != "from")
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "from").drop(1).takeWhile(_.toLowerCase() != "where")
                val queryTableName = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).headOption.getOrElse("NA")
                if (queryTableName == "NA") {
                    // println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                val queryColumns = db_schema(queryTableName) 
                val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                if (queryScope.map(scope => (scope == "*" && !unsafeColumns.isEmpty) || (!safeSQLFunctions.exists(scope.contains(_)) && unsafeColumns.exists(scope.contains(_)))).contains(true))
                    QueryLabel.UnsafeQuery
                else QueryLabel.SafeQuery
                }
            }
            case QueryType.InsertQuery => {
                val queryCode = query.getQueryCode.mkString(" ").replace("values(", "values ( ").split(" ")
                val queryTable = queryCode.dropWhile(_.toLowerCase() != "into").drop(1).takeWhile(!_.toLowerCase().contains("values"))
                val queryValues = queryCode.dropWhile(!_.toLowerCase().contains("values")).drop(1).takeWhile(token => !token.toLowerCase().contains(";") && token.toLowerCase!="where")
                val queryTableNames = tables.map(x => queryTable.map(_.filter(!removeChars.contains(_))).exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).l
                if (queryTableNames.isEmpty) {
                    // Unable to find a matching table from the query
                    // println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                    val queryTableName = {
                        if (queryTableNames.size == 1) queryTableNames(0)
                        else {
                            val tableColumns = queryTableNames.map(db_schema.get(_).get.keys)
                            // get most likely table
                            val mostLikelyIndex = tableColumns.map(_.toList.map(s => queryCode.exists({
                                val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                                regex.findFirstIn(_).isDefined}))).map(_.filter(_==true).size).zipWithIndex.maxBy(_._1)._2 
                            queryTableNames(mostLikelyIndex)
                        }
                    }
                    val sortedColumns: List[String] = {
                        if (queryTable.mkString(" ").contains("("))
                            queryTable.dropWhile(!_.contains("(")).drop(0).toList.map(_.replace("(", "").replace(")", ""))
                        else list_schema.filter(_(0) == queryTableName).map(_(1))
                        } 
                    val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                    val insertValuesUnsafe = unsafeColumns.map(s => sortedColumns.exists({
                            val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                            regex.findFirstIn(_).isDefined}))
                    if (unsafeColumns.isEmpty || !insertValuesUnsafe.contains(true))
                        QueryLabel.SafeQuery
                    else {
                        val valuesParsed =  calculationPattern.replaceAllIn(queryValues.mkString(" "), matchResult => "CALC_SPACE" + matchResult.group(1) + "CALC_SPACE").split(" ").filter(_.exists(_.isLetterOrDigit)).toList
                        if (valuesParsed.size < sortedColumns.size) QueryLabel.UnsafeQuery
                        else {
                            val unsafeIndices = unsafeColumns.map(sortedColumns.indexOf(_))
                            val unsafeNodes = unsafeIndices.map(valuesParsed.lift(_).getOrElse("").replace("CALC_SPACE", " ")).map(query.searchNodeFromQuery(_)).filterNot(_==None)                         
                            if (unsafeNodes.map(sanitizationObject.isSanitized(_)).contains(false))
                                QueryLabel.UnsafeQuery
                            else QueryLabel.SafeQuery
                        }
                    }
                }
            }
            case QueryType.UpdateQuery => {
                val queryCode = query.getQueryCode
                val queryTable = queryCode.map(_.filter(!removeChars.contains(_))).dropWhile(_.toLowerCase() != "update").drop(1).takeWhile(_.toLowerCase() != "set")
                val queryValues = queryCode.dropWhile(_.toLowerCase() != "set").drop(1).takeWhile(token => !token.toLowerCase().contains(";") && token.toLowerCase!="where")
                val queryTableNames = tables.map(x => queryTable.exists(x.contains)).zipWithIndex.filter(_._1==true).map(_._2).collect(tables(_)).l
                if (queryTableNames.isEmpty) {
                    // Unable to find a matching table from the query
                    // println(query)
                    QueryLabel.UnsafeQuery
                }
                else {
                    val queryTableName = {
                        if (queryTableNames.size == 1) queryTableNames(0)
                        else {
                            val tableColumns = queryTableNames.map(db_schema.get(_).get.keys)
                            // get most likely table
                            val mostLikelyIndex = tableColumns.map(_.toList.map(s => queryCode.exists({
                                val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                                regex.findFirstIn(_).isDefined}))).map(_.filter(_==true).size).zipWithIndex.maxBy(_._1)._2 
                            queryTableNames(mostLikelyIndex)
                        }
                    }
                    val queryColumns = db_schema(queryTableName) 
                    val unsafeColumns = db_schema(queryTableName).filterNot(_._2).keys.toList
                    val setValuesUnsafe = unsafeColumns.map(s => queryValues.exists({
                            val regex = s"(?<!\\p{Alnum})$s(?![\\p{Alnum}])".r
                            regex.findFirstIn(_).isDefined}))
                    if (unsafeColumns.isEmpty || !setValuesUnsafe.contains(true))
                        QueryLabel.SafeQuery
                    else {
                        val valuesParsed =  calculationPattern.replaceAllIn(queryValues.map(_.filter(!removeChars.contains(_))).filterNot(_.isEmpty).mkString(" "), matchResult => matchResult.group(1)).split(" ").filter(_.exists(_.isLetterOrDigit)).toList
                        val unsafeValues = valuesParsed.filter(token => unsafeColumns.contains(token.split("=")(0)))
                        val unsafeNodes = unsafeValues.map(_.split("=").lift(1).getOrElse("")).map(query.searchNodeFromQuery(_)) 
                        if (unsafeNodes.map(sanitizationObject.isSanitized(_)).contains(false))
                            QueryLabel.UnsafeQuery
                        else QueryLabel.SafeQuery
                    }
                }
            }
            case _ => {
                QueryLabel.UnsafeQuery
            }
        }
    }

    def filterPath(path: List[AstNode]): Boolean = {
        val safeDbCalls = cpg.call.filter(x => Constants.sql_func.map(x.name.contains(_)).reduce((x,y) => x || y)).l.filterNot(element => databaseCalls.contains(element))
        val queries = path.filter(databaseCalls.contains).map(getQuery(_))
        queries.map(labelQuery(_)).contains(QueryLabel.SafeQuery) || !path.filter(safeDbCalls.contains).isEmpty
    }
}

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

    def getReachingDefs(paths: List[List[AstNode]], source: List[nodes.Call] = List(), vulnerabilityInst: sanitizationObject.vulnerabilityType): List[List[AstNode]] = {
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
                case call: nodes.Call => {
                    if (!List(call).reachableByFlows(source).isEmpty) {
                        output = output :+ (path ++ List(call).reachableByFlows(source).map(_.elements).head.reverse)
                        List()
                    }
                    else call.ddgIn.filterNot(_.isLiteral).l
                }
                case literal: Literal => List()
                case block: Block => List()
                case parameter: MethodParameterIn => parameter.method.callIn.argument(parameter.index).filterNot(_.isLiteral).l
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

    def reachableBySource(sink: AstNode, source: List[nodes.Call] = List(),  vulnerabilityInst: sanitizationObject.vulnerabilityType): List[AstNode] = {
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
        implicit val vulnerabilityInst: sanitizationObject.vulnerabilityType = sanitizationObject.vulnerabilityType(vulnerability, attack_san_functions)
        // source of the attack vector: assignment nodes whose code contain defined attacker_input
        val source = cpg.call.filter(node => Constants.attacker_input.map(node.code.contains(_)).contains(true)).filterNot(sanitizationObject.isSanitized(_)(vulnerabilityInst)).l //.groupBy(_.lineNumber).map(x => x._2.head).l 
        // sink of the atack vector: unsanitized arguments of sink call nodes
        val sinks = (cpg.call.filter(x => sinkFunctions.map(x.name.contains(_)).reduce((x,y) => x || y)).filterNot(sanitizationObject.isSanitized(_)(vulnerabilityInst))).l        // intra-procedural path from source to sink
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
        val totalPaths = if (vulnerability == "XSS") {
                // globalPaths ++ paths
                val dbConstraint = new DatabaseConstraint(cpg)
                (globalPaths ++ paths).filterNot(dbConstraint.filterPath)
            } 
            else globalPaths ++ paths
        val dedupPaths = totalPaths.groupBy(path => List(path.head, path.last)).map(_._2.head)
        dedupPaths
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
            path.map(x => {
                        val (attack_san_functions, sinkFunctions) = getSinks(k)
                        implicit val vulnerabilityInst = sanitizationObject.vulnerabilityType(k, attack_san_functions)
                        "{\n\t\"pathid\": " + pathID + ",\n" + 
                        "\t\"vulnerability\": \"" + k + "\",\n" + 
                        "\t\"nodeid\": " + x.id + ",\n" +
                        "\t\"filename\": \"" + cpg.metaData.root.head.split("/").last + "/" + x.file.name.headOption.getOrElse("").replace("\"", "\\\"") + "\",\n" +
                        "\t\"linenumber\": " + x.lineNumber.getOrElse("") + ",\n" +
                        "\t\"code\": \"" + x.code.replace("\\", "\\\\").replace("\"", "\\\"") + "\",\n" +
                        "\t\"sanitized\": \"" + sanitizationObject.isSanitized(x)(vulnerabilityInst) + "\"\n},"
    }).mkString("\n")}).mkString("[", "\n", "]")}.values.filter(!_.isEmpty).mkString("").replace("[]", "").replace("},]", "}]").replace("][", ",")
        output |> "navex_utils/paths/" + cpg.metaData.root.head.split("/").last.replaceAll("[^a-zA-Z]", "").toLowerCase + "-output.json"
    }

}