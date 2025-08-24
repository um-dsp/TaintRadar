name := "taintradar"

dependsOn(
  Projects.x2cpg, 
  Projects.dataflowengineoss,
  Projects.console,
  Projects.javasrc2cpg,
  Projects.php2cpg
)

libraryDependencies ++= Seq(
  "io.shiftleft" %% "codepropertygraph" % Versions.cpg,
  "org.scalatest" %% "scalatest" % Versions.scalatest % Test,  
  "com.github.mpkorstanje"   % "simmetrics-core"   % "4.1.1"
)