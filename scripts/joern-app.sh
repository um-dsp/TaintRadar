#!/bin/bash
# Make sure to use Java 17 (17.0.6-oracle)
# sdk use java 17.0.6-oracle
JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
APPDIR="/home/umd-user/Desktop/navex_project/navex_utils/test-code"
NEO4JDIR="/home/umd-user/Desktop/navex_project/neo4j-community-5.6.0"
NEO4JPSSWD="dabaddest"

cd $JOERNDIR
./joern-parse $APPDIR/sample-web-app
rm -r $APPDIR/output
./joern-export --repr=all --format=neo4jcsv --out=$APPDIR/output
# $NEO4JDIR/bin/neo4j-admin server console
cp $APPDIR/output/*_data.csv $NEO4JDIR/import

find $APPDIR/output -name 'nodes_*_cypher.csv' -exec $NEO4JDIR/bin/cypher-shell -u neo4j -p $NEO4JPSSWD --file {} \;
find $APPDIR/output -name 'edges_*_cypher.csv' -exec $NEO4JDIR/bin/cypher-shell -u neo4j -p $NEO4JPSSWD --file {} \;