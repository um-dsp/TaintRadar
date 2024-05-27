#!/bin/bash

JOERNDIR="/Users/elirizk/Desktop/navex_project/joern"
SCRIPTDIR="/Users/elirizk/Desktop/navex_project/navex_utils/code"
WORKSPACEDIR="/Users/elirizk/Desktop/navex_project/navex_utils/code/tests/java-tests/Safe/SafeSQLInjectionHTTP.java"
FILEMAIN="SafeSQLInjectionHTTP\$LoginHandler.handle:void(com.sun.net.httpserver.HttpExchange)"

cd $SCRIPTDIR
# $JOERNDIR/joern-parse $SCRIPTDIR/tests/java-tests/Safe/SafeSQLInjectionHTTP.java
$JOERNDIR/joern --script $SCRIPTDIR/TestScript.scala --param cpgFile=$WORKSPACEDIR --param fileMain=$FILEMAIN --import main/java/Constants.scala --import main/java/SanitizationFilter.scala
python3 addColor.py
cd $SCRIPTDIR/output_graph
# dot -Tpng coloredOutput.dot > output.png
dot -Tsvg coloredOutput.dot > output.svg