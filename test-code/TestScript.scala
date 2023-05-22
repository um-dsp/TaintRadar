@main def exec(cpgFile: String) = { //, outFile: String) = {
    importCpg(cpgFile)
    val identifier = cpg.identifier.id(3).l.head
    val includeFileNames = cpg.method.fullName(identifier.file.name.l.head+":<global>").call("include|require").argument.code.map(_.replaceAll("\"","")).l
    val fileIdentifiers = includeFileNames.flatMap(file => cpg.method.fullName(file+":<global>").methodReturn.ddgIn.isIdentifier.l)
}
val output = {
   var sanitized = cpg.identifier.filter(SanitizationFilter.isSanitized(_)).name.dedup.l.filter(!List("p1", "p2", "unsan11", "unsan14").contains(_))
   val unsanitized = cpg.identifier.filterNot(SanitizationFilter.isSanitized(_)).name.dedup.l.filter(!List("p1", "p2", "san12", "san61", "tmp", "_GET", "san14").contains(_))
   println("Sanitized Identifiers: " + sanitized)
   println("Unsanitized Identifiers: " + unsanitized)
} 