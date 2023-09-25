#!/bin/bash

JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
SCRIPTDIR="/home/umd-user/Desktop/navex_project/navex_utils/code/"
# WORKSPACEDIR="/home/umd-user/Desktop/navex_project/joern-repo/workspace/presentation.php/cpg.bin"
WORKSPACEDIR="/home/umd-user/Desktop/navex_project/navex_utils/code/cpg.bin"
FILEMAIN=$1".php:<global>"

cd $SCRIPTDIR
joern-parse $SCRIPTDIR/php-tests/traversal
$JOERNDIR/joern --script $SCRIPTDIR/TestScript.scala --params cpgFile=$WORKSPACEDIR,fileMain=$FILEMAIN --import Constants.scala,SanitizationFilter.scala
python3 addColor.py
cd $SCRIPTDIR/output_graph
dot -Tpng coloredOutput.dot > output.png