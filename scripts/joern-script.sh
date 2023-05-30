#!/bin/bash

JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
SCRIPTDIR="/home/umd-user/Desktop/navex_project/navex_utils/test-code"
WORKSPACEDIR="/home/umd-user/Desktop/navex_project/joern-repo/workspace/presentation.php/cpg.bin"
WORKSPACEDIR="/home/umd-user/Desktop/navex_project/navex_utils/cpg.bin"
FILEMAIN="settype.php:<global>"

cd $SCRIPTDIR
$JOERNDIR/joern --script $SCRIPTDIR/TestScript.scala --params cpgFile=$WORKSPACEDIR,fileMain=$1 --import SanitizationFilter.scala,Constants.scala
python3 addColor.py