package org.codeminers.standalone

import io.joern.joerncli.console.Joern.importCpg
import io.joern.javasrc2cpg.{Config => JavaConfig, JavaSrc2Cpg}
import io.joern.php2cpg.{Config => PhpConfig, Php2Cpg}
import io.joern.x2cpg.X2Cpg.applyDefaultOverlays
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.NewMynodetype
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language._
import flatgraph.DiffGraphBuilder

import java.nio.file.{Files, Paths}
import scala.util.{Failure, Success}

import org.codeminers.standalone.Constants.ConstantsFactory

/** Example program that makes use of Joern as a library */
object Main {

  def main(args: Array[String]): Unit = {
    println("Welcome to TaintRadar")
    println("TaintRadar is an augmented-CPG approach for detecting PhP taint-style vulnerabilities.")
    val cpgPath = {
      val input = {
        if (args.size > 0)
          args(0)
        else {
          println("Please enter the path to the parsed CPG binary (cpg.bin):")
          Option(scala.io.StdIn.readLine()).getOrElse("").trim
        }
      }
      // Also accept the directory that contains cpg.bin
      val path = Paths.get(input)
      if (Files.isDirectory(path)) path.resolve("cpg.bin").toString else input
    }
    print("Loading CPG... ")
    // Name the workspace project after the CPG file, so that re-running on the same file
    // overwrites its working copy instead of creating cpg.bin1, cpg.bin2, ...
    val cpgOpt = importCpg(cpgPath, Option(Paths.get(cpgPath).getFileName).map(_.toString).getOrElse(""))

    cpgOpt match {
      case Some(cpg) =>
        println("CPG created successfully")
        println("Applying default overlays")
        applyDefaultOverlays(cpg)
        val utils = new Utils(cpg)
        println("Applying sanitization augmentation...")
        utils.augmentWithSanTag()
        println("Sanitization augmentation completed")
        println("Applying database queries augmentation...")
        utils.augmentWithQueryTag()
        println("Database queries augmentation completed with the following output:")
        utils.debugDatabaseParsing()
        println("Running Vulnerability path extraction...")
        val navexMain = new NavexMain(cpg, false)
        val outputLog = navexMain.outputPaths(true)
        println(outputLog)
      case None =>
        println("Error creating CPG")
    }
  }

}

/** Example of a custom pass that creates and stores a node in the CPG.
  */
class MyPass(cpg: Cpg) extends CpgPass(cpg) {
  override def run(builder: DiffGraphBuilder): Unit = {
    val n = NewMynodetype().myproperty("foo")
    builder.addNode(n)
  }
}
