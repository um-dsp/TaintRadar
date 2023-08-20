#!/bin/bash

JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
SCRIPTDIR="/home/umd-user/Desktop/navex_project/navex_utils/test-code"
# WORKSPACEDIR="/home/umd-user/Desktop/navex_project/joern-repo/workspace/presentation.php/cpg.bin"
WORKSPACEDIR="/home/umd-user/Desktop/navex_project/navex_utils/test-code/cpg.bin"
FILEMAIN="class.php:<global>"

cd $SCRIPTDIR
joern-parse $SCRIPTDIR/examples
$JOERNDIR/joern --script $SCRIPTDIR/TestScript.scala --params cpgFile=$WORKSPACEDIR,fileMain=$FILEMAIN --import SanitizationFilter.scala,Constants.scala
python3 addColor.py
cd $SCRIPTDIR/output_graph
dot -Tpng coloredOutput.dot > output.png