package io.joern.taintradar.Constants

object ConstantsFactory {
  def getConstants(language: String): ConstantsTrait = {
    language.toLowerCase() match {
      case "php" => {
        println("PHP constants selected")
        PHPConstants
      }
      case "java" => {
        println("Java constants selected")
        JavaConstants
      }
    }
  }
}