#!/bin/bash

JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
# TESTDIR="/home/umd-user/Desktop/navex_project/navex_utils/test-code/sample-web-app/testCases.php"
TESTDIR="/home/umd-user/Desktop/navex_project/joern-repo/navex_tests/oscommerce-2.3.4.1/catalog"

cd $JOERNDIR
sbt joerncli/stage
echo "" | ./querydb-install.sh
./joern-scan $TESTDIR --tags all --overwrite