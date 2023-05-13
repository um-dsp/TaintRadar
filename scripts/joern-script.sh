#!/bin/bash

JOERNDIR="/home/kali/Desktop/navex_project/joern-repo"
SCRIPTDIR="/home/kali/Desktop/navex_project/test-code"
WORKSPACEDIR="/home/kali/Desktop/navex_project/joern-repo/workspace"

cd $JOERNDIR
./joern --script $SCRIPTDIR/SanAug.sc --params cpgFile=$WORKSPACEDIR/testFun.php1/cpg.bin > "../test-code/output.txt"