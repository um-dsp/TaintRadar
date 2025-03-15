package org.codeminers.standalone

import io.joern.javasrc2cpg.{Config => JavaConfig, JavaSrc2Cpg}
import io.joern.php2cpg.{Config => PhpConfig, Php2Cpg}
import io.joern.x2cpg.X2Cpg.applyDefaultOverlays
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.NewMynodetype
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language._
import flatgraph.DiffGraphBuilder

import scala.util.{Failure, Success}

import org.codeminers.standalone.Constants.ConstantsFactory

/** Example program that makes use of Joern as a library */
object Main {

  def main(args: Array[String]): Unit = {
    println("Welcome to the University of Michigan's Data Security and Privacy Lab's vulnerability detection tool.")
    println("This tool is used to detect and analyze data flow vulnerabilities in application code.")
    println("What is the language of the code you want to analyze? The supported languages currently included are: PHP and Java")
    val language = scala.io.StdIn.readLine()
    println("Please enter the path to the directory containing the code you want to analyze:")
    val directory = scala.io.StdIn.readLine()
    print("Creating CPG... ")
    val config = {
      if (language.toLowerCase() == "php") {
        PhpConfig().withInputPath(directory)
      } else if (language.toLowerCase() == "java") {
        JavaConfig().withInputPath(directory)
      } else {
        println("Invalid language")
        Failure(new Exception("Invalid language"))
      }
    }

    val cpgOrException = {
      if (language.toLowerCase() == "php") {
        Php2Cpg().createCpg(config.asInstanceOf[PhpConfig])
      } else if (language.toLowerCase() == "java") {
        JavaSrc2Cpg().createCpg(config.asInstanceOf[JavaConfig])
      } else {
        println("Error creating CPG")
        Failure(new Exception("Error creating CPG"))
      }
    }

    cpgOrException match {
      case Success(cpg) =>
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
        navexMain.outputPaths(true)
        println("Vulnerability path extraction completed check the output directory for the results")
        // new MyPass(cpg).createAndApply()
      case Failure(exception) =>
        println("Error creating CPG")
        println(exception)
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
