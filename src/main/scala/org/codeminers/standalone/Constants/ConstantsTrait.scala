package org.codeminers.standalone.Constants

trait ConstantsTrait {
  val attacker_input: List[String]
  val safe_types: List[String]
  val implicit_cast: List[String]
  val magic_constants: List[String]
  val input_func: List[String]
  val san_identifiers: List[String]
  val type_cast_byref: String
  val constant_definition_func: String
  val query_concat_func: List[String]
  val san_functions_all: List[String]
  val unsafe_object_types: List[String]
  val attacker_object_types: List[String]
  val codeinj_sink: List[String]
  val commandexec_sink: List[String]
  val fileinc_sink: List[String]
  val sqli_sink: List[String]
  val xss_sink: List[String]
  val stored_xss_func: List[String]
  val fileaccess_sink: List[String]
  val sessionfixation_sink: List[String]
  val san_functions_code: List[String]
  val san_functions_os_command: List[String]
  val san_functions_file: List[String]
  val san_functions_sql: List[String]
  val san_functions_xss: List[String]
  val validator_functions: List[String] = List()
  val filter_functions: List[String] = List()
  val sanitizing_filters: List[String] = List()
  val type_reporting_functions: List[String] = List()
  val pattern_match_functions: List[String] = List()

  lazy val all_sinks: List[String] =
    (codeinj_sink ++ commandexec_sink ++ fileinc_sink ++ sqli_sink ++ xss_sink ++
      stored_xss_func ++ fileaccess_sink ++ sessionfixation_sink).distinct

  lazy val san_functions: List[String] = san_functions_all.diff(all_sinks)
} 