#!/bin/bash

JOERNDIR="/home/kali/Desktop/navex_project/joern-repo"
TESTDIR="/home/kali/Desktop/navex_project/test-code"

cd $JOERNDIR
sbt joerncli/stage
echo "" | ./querydb-install.sh
./joern-scan $TESTDIR/sqli.php --tags all --overwrite     