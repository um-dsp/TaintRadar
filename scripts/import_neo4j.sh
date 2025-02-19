#!/bin/bash

# Set Neo4j credentials
NEO4J_USERNAME="neo4j"
NEO4J_PASSWORD="6AGs9'SuM)D5VRb"

# Stop Neo4j server if running
# NEO4J_USERNAME=$NEO4J_USERNAME NEO4J_PASSWORD=$NEO4J_PASSWORD neo4j stop

# Find all node CSV files
# NODE_FILES=$(find out -name 'nodes_*.csv' -print0 | xargs -0 echo | tr ' ' ',')

# Find all relationship CSV files
# RELATIONSHIP_FILES=$(find out -name 'edges_*.csv' -print0 | xargs -0 echo | tr ' ' ',')

# Import data
# neo4j-admin database import full --overwrite-destination --nodes=$NODE_FILES --relationships=$RELATIONSHIP_FILES

find out -name 'nodes_*_cypher.csv' -exec cypher-shell -u $NEO4J_USERNAME -p $NEO4J_PASSWORD --file {} \;
find out -name 'edges_*_cypher.csv' -exec cypher-shell -u $NEO4J_USERNAME -p $NEO4J_PASSWORD --file {} \;

# Start Neo4j server with authentication
NEO4J_USERNAME=$NEO4J_USERNAME NEO4J_PASSWORD=$NEO4J_PASSWORD neo4j start

# Verify connection
echo "Waiting for Neo4j to start..."
sleep 10
if curl -u "$NEO4J_USERNAME:$NEO4J_PASSWORD" http://localhost:7474 >/dev/null 2>&1; then
    echo "Neo4j successfully started with authentication"
else
    echo "Error: Failed to verify Neo4j connection"
    exit 1
fi