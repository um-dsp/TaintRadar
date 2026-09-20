package org.codeminers.standalone

enum Module(val label: String) {
  case VanillaJoern extends Module("Vanilla Joern")
  case Dataflow extends Module("+Dataflow")
  case Sanitization extends Module("+Sanitization")
  case Database extends Module("+Database")

  def includes(other: Module): Boolean = this.ordinal >= other.ordinal
}

object Module {
  val names: List[String] = List("vanilla", "dataflow", "sanitization", "database")

  def fromName(name: String): Option[Module] =
    name.replaceAll("[^a-zA-Z]", "").toLowerCase match {
      case "vanilla" | "vanillajoern" | "joern" => Some(VanillaJoern)
      case "dataflow"                           => Some(Dataflow)
      case "sanitization"                       => Some(Sanitization)
      case "database"                           => Some(Database)
      case _                                    => None
    }
}
