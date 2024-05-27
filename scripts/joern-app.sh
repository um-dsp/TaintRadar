#!/bin/bash
# Make sure to use Java 17 (17.0.6-oracle)
# sdk use java 17.0.6-oracle
JOERNDIR="/home/umd-user/Desktop/navex_project/joern-repo"
CODEDIR="/home/umd-user/Desktop/navex_project/navex_utils/code"
APPDIR="/home/umd-user/Desktop/navex_project/navex_tests/geccBBlite-0.1"
NEO4JDIR="/home/umd-user/Desktop/navex_project/neo4j-community-5.6.0"
NEO4JPSSWD="dabaddest"

cd $JOERNDIR
# ./joern-parse $APPDIR
rm -r $APPDIR/output
# ./joern-export --repr=all --format=neo4jcsv --out=$CODEDIR/output  



gggggghhhhffwqfrghgf   dfdsfsdf    nm adsfddsf b  dfkjsdfkdslfjsdk         

 
  
     # $NEO4JDIR/bin/neo4j-admin server console
# cp $CODEDIR/output/*_data.csv $NEO4JDIR/import

find $CODEDIR/output -name 'nodes_*_cypher.csv' -exec $NEO4JDIR/bin/cypher-shell -u neo4j -p $NEO4JPSSWD --file {} \;
find $CODEDIR/output -name 'edges_*_cypher.csv' -exec $NEO4JDIR/bin/cypher-shell -u neo4j -p $NEO4JPSSWD --file {} \;