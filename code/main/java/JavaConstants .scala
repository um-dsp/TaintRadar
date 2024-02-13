object Constants {

  val attacker_input = List(
    "getHeader",
    "getRequest",
    "getCookie",
    "getParameter",
    "getParameterMap",
    "getParameterValues",
    "getReader",
    "getAttribute",
    "read",
    "readLine"
  )

  val safe_types: List[String] = List(
    "boolean", 
    "number",
    "integer",
    "int",
    "float", 
    "long", 
    "double", 
    "short",
    "byte",
    "character"
  )

  val implicit_cast: List[String] = List("<operator>.plus", "<operator>.minus", "<operator>.multiplication", "<operator>.division", "<operator>.xor", 
                                          "<operator>.assignmentPlus", "<operator>.assignmentMinus" )

  val magic_constants: List[String] = List(
    
  )

  val input_func: List[String] = List(

  )

  val san_identifiers: List[String] = List(

  )

  val type_cast_byref: String = ""

  val constant_definition_func: String = ""

  val query_concat_func: List[String] = List(
    
  )

// java servlet
// hibernate
// spring 
// java.sql

  val sqli_sink: List[String] = List(
    "executeBatch",
    "executeQuery",
    "executeUpdate",
    "executeLargeUpdate",
    "execute",
    "addBatch"
  )

  // Useful for Stored XSS processing, i.e. not vulnerable to SQL Injection but interacts with the database
  val stored_xss_func: List[String] = sqli_sink ++ List(
    
  )

  val commandexec_sink = List(
    
  )
  
  val codeinj_sink = List(
    
  )

  val fileinc_sink = List(
    
  )

  val xss_sink = List(
    "print",
    "println",
    "setContentType",
    "setAttribute",
    "sendHeader",
    "sendError",
    "write"
  )

  val fileaccess_sink = List(
    
  )

  val sessionfixation_sink = List(
    
  )

  val san_functions_sql = List( 
    
  )

  val san_functions_xss = List(
    
  )

  val filter_var_arguments = List(
    
  )

  val san_functions_code = List()

  val san_functions_os_command  = List(
    
  )
  
  val san_functions_file= List(
    
  )

  val san_functions_all = List(
    
    "<operator>.equals",
    "<operator>.lessThan",
    "<operator>.lessEqualsThan",
    "<operator>.greaterThan",
    "<operator>.greaterEqualsThan")

}