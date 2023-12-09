object JavaConstants {

  val attacker_input = List("_GET", "_POST", "_COOKIE", "_REQUEST", "_ENV", "HTTP_.*", "QUERY_STRING", "_FILES")

  val sql_func: List[String] = List("mysql_", "mysqli_", "pg_", "sqlite_")

  val safe_types: List[String] = List("int", "integer", "bool", "boolean", "float", "double")

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
    "sqlite_single_query",
    // Miscellaneous
    "sql_query"
  )

  val commandexec_sink = List("java.lang.Runtime.exec")
  
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