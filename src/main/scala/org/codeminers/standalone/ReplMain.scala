package org.codeminers.standalone

import io.joern.console.BridgeBase
import io.joern.joerncli.console.RunBeforeCode

/** Extend/use joern as a REPL application */
object ReplMain extends BridgeBase {

  def main(args: Array[String]): Unit = {
    run(parseConfig(args))
  }

  override protected def runBeforeCode = {
    RunBeforeCode.forInteractiveShell ++ Seq(s"import _root_.${getClass.getPackageName}.*")
  }

  override protected def promptStr  = "taint-radar"
  override protected def greeting   = "Initializing TaintRadar - a Joern extension for an improved uncovering of taint-style vulnerabilities"
  override protected def onExitCode = """println("Exiting")"""
  override def applicationName      = "taint-radar"
}
