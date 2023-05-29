#!/bin/bash

JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
SCRIPTDIR="/home/umd-user/Desktop/navex_project/navex_utils/test-code"
WORKSPACEDIR="/home/umd-user/Desktop/navex_project/joern-repo/workspace/presentation.php/cpg.bin"

cd $SCRIPTDIR
$JOERNDIR/joern --script $SCRIPTDIR/TestScript.scala --params cpgFile=$WORKSPACEDIR,outFile=$SCRIPTDIR/output.dot --import SanitizationFilter.scala,Constants.scala