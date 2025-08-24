package io.joern.taintradar

import io.joern.console.BridgeBase
import io.joern.console.{Help, Run}

/** Extend/use joern as a REPL application */
object ReplMain extends BridgeBase {

  def main(args: Array[String]): Unit = {
    run(parseConfig(args))
  }

  override def runBeforeCode = Seq(
      "import _root_.io.joern.console.*",
      "import _root_.io.joern.joerncli.console.JoernConsole.*",
      "import _root_.io.shiftleft.codepropertygraph.cpgloading.*",
      "import _root_.io.shiftleft.codepropertygraph.generated.{help => _, _}",
      "import _root_.io.shiftleft.codepropertygraph.generated.nodes.*",
      "import _root_.io.joern.dataflowengineoss.language.*",
      "import _root_.io.shiftleft.semanticcpg.language.*",
      "import _root_.io.joern.taintradar.*",
      "import scala.jdk.CollectionConverters.*",
      "import _root_.io.shiftleft.semanticcpg.sarif.SarifConfig",
      "implicit val resolver: ICallResolver = NoResolve",
      "implicit val finder: NodeExtensionFinder = DefaultNodeExtensionFinder",
      "implicit val sarifConfig: SarifConfig = SarifConfig(semanticVersion = Option(version))"
    )

  override protected def promptStr  = "joern-navex"
  override protected def greeting   = "Welcome to the wonderful world of this joern extension!"
  override def applicationName      = "joern-navex"
}
