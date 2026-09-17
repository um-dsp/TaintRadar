package org.codeminers

import io.shiftleft.codepropertygraph.generated.{Cpg, NodeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.{Method, Mynodetype, AstNode}
import io.shiftleft.semanticcpg.language.*
import flatgraph.help.{Doc, DocSearchPackages, Traversal, TraversalSource}

import scala.jdk.CollectionConverters.IteratorHasAsScala

import org.codeminers.standalone.SanitizationFilter
import org.codeminers.standalone.Constants.ConstantsFactory

package object standalone {

  // provides package names to search for @Doc annotations etc
  implicit val docSearchPackages: DocSearchPackages =
    Cpg.defaultDocSearchPackage
      .withAdditionalPackage(this.getClass.getPackageName)

  /** Example of a custom language step
    */
  implicit class MynodetypeSteps(val traversal: Iterator[Mynodetype]) extends AnyVal {
    def myCustomStep: Iterator[Mynodetype] = {
      println("custom step executed")
      traversal
    }
  }

  @Traversal(elementType = classOf[Method])
  implicit class CustomMethodSteps(val traversal: Iterator[Method]) extends AnyVal {
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
