#!/bin/bash

JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
TESTDIR="/home/umd-user/Desktop/navex_project/navex_utils/test-code/sample-web-app/testCases.php"

cd $JOERNDIR
# sbt joerncli/stage
# echo "" | ./querydb-install.sh
./joern-scan $TESTDIR --tags all --overwrite