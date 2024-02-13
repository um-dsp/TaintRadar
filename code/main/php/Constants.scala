object Constants {

  val attacker_input = List("_GET", "_POST", "_COOKIE", "_REQUEST", "_ENV", "HTTP_.*", "QUERY_STRING", "_FILES")

  val safe_types: List[String] = List("int", "integer", "bool", "boolean", "float", "double")

  val implicit_cast: List[String] = List("<operator>.plus", "<operator>.minus", "<operator>.multiplication", "<operator>.division", "<operator>.xor", 
                                          "<operator>.assignmentPlus", "<operator>.assignmentMinus" )

  val magic_constants: List[String] = List("__LINE__, __FILE__, __DIR__, __FUNCTION__, __CLASS__, __TRAIT__, __METHOD__, __NAMESPACE__")

  val input_func: List[String] = List("readline")

  val san_identifiers: List[String] = List("<global>", "this")

  val type_cast_byref: String = "settype"

  val constant_definition_func: String = "define"

  val query_concat_func: List[String] = List("<operator>.concat", "encaps")

  val sqli_sink: List[String] = List(
    // MySQLi Functions
    "mysqli_query",
    "mysqli_multi_query",
    "mysqli_real_query",
    // mysql_ Functions (Deprecated)
    "mysql_query",
    // PostgreSQL Functions
    "pg_query",
    "pg_query_params",
    // SQLite Functions
    "sqlite_query",
    "sqlite_exec",
    "queryExec",
    // Miscellaneous
    "sql_query",
    "query",
    "real_query"
  )

  // Useful for Stored XSS processing, i.e. not vulnerable to SQL Injection but interacts with the database
  val stored_xss_func: List[String] = sqli_sink ++ List(
    "mysqli_stmt_execute",
    "execute",
    "pg_execute"
  )

  val commandexec_sink = List(
    "shell_exec", 
    "exec", 
    "system", 
    "mail", 
    "popen", 
    "expect_popen", 
    "passthru", 
    "pcntl_exec", 
    "proc_open"
  )
  
  val codeinj_sink = List("eval", "assert")

  val fileinc_sink = List("include", "require", "include_once", "require_once")

  val xss_sink = List("print", "echo", "printf", "exit")

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

  val filter_var_arguments = List("FILTER_SANITIZE_EMAIL",
    "FILTER_VALIDATE_EMAIL",
    "FILTER_SANITIZE_FULL_SPECIAL_CHARS",
    "FILTER_SANITIZE_MAGIC_QUOTES",
    "FILTER_SANITIZE_NUMBER_FLOAT",
    "FILTER_VALIDATE_FLOAT",
    "FILTER_SANITIZE_NUMBER_INT",
    "FILTER_VALIDATE_INT",
    "FILTER_SANITIZE_SPECIAL_CHARS")

  val san_functions_code = List()

  val san_functions_os_command  = List("escapeshellarg",
    "escapeshellcmd")
  
  val san_functions_file= List("basename",
    "dirname",
    "pathinfo")

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
    "date", "ctype_digit",
    "in_array",
    "<operator>.equals",
    "<operator>.lessThan",
    "<operator>.lessEqualsThan",
    "<operator>.greaterThan",
    "<operator>.greaterEqualsThan")

}