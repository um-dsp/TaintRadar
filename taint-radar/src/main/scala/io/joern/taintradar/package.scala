package io.joern

import io.shiftleft.codepropertygraph.generated.{Cpg, NodeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.{Method, AstNode}
import io.shiftleft.semanticcpg.language.*
import flatgraph.help.{Doc, DocSearchPackages, Traversal, TraversalSource}

import scala.jdk.CollectionConverters.IteratorHasAsScala

import io.joern.taintradar.SanitizationFilter
import io.joern.taintradar.Constants.ConstantsFactory

package object taintradar {

  // provides package names to search for @Doc annotations etc
  implicit val docSearchPackages: DocSearchPackages =
    Cpg.defaultDocSearchPackage
      .withAdditionalPackage(this.getClass.getPackageName)

  @Traversal(elementType = classOf[Method])
  implicit class CustomMethodSteps(val traversal: Iterator[Method]) extends AnyVal {
    @Doc(info = "custom step on method as an example", longInfo = "a veeery long description again")
    def customMethodStep: Iterator[String] =
      traversal.flatMap(_.parameter.name)
  }

  /** Example implicit conversion that forwards to the `StandaloneStarters` class
    */
  implicit def toStandaloneStarters(cpg: Cpg): StandaloneStarters =
    new StandaloneStarters(cpg)

  /** Example of custom node type starters */
  @TraversalSource
  class StandaloneStarters(cpg: Cpg) {
    val constants = ConstantsFactory.getConstants(cpg.metaData.head.language)
    val sanitizationObject = new SanitizationFilter(cpg)
    val utils = new Utils(cpg)
    val navexMain = new NavexMain(cpg, true)
    
    @Doc(info = "custom starter step as an example", longInfo = "a veeery long description")
    def filterSanitized: Iterator[AstNode] =
      cpg.method.ast.filter(sanitizationObject.isSanitized(_)(constants.san_functions_all))

    def isSanitized(node: AstNode): Boolean =
      sanitizationObject.isSanitized(node)(constants.san_functions_all)

    def toJson(fileName: String = "cpg.json"): String =
      utils.augmentWithSanTag()
      utils.augmentWithQueryTag()
      utils.cpgToJson(fileName)
      "Successfully created " + fileName

    def getVulnerablePaths(debug: Boolean = true): String =
      navexMain.outputPaths(debug)
  }
}
