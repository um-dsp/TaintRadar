# TaintRadar: Cross-Language Taint-Style Vulnerability Detection via Augmented Code Property Graphs

**TaintRadar** is a static analysis framework for PHP and Java applications that builds on Code Property Graphs (CPGs) to detect taint-style vulnerabilities.  
It enhances traditional static analysis by integrating object dependency modeling, schema-aware database analysis, and language-agnostic sanitization tracking to improve precision and reduce false positives.

##  Requirements
JDK 21 (other versions might work, but have not been properly tested)
Scala 1.11.4 sudo apt-get install sbt
##  Step 1
Download Joern Repo using the following command:
git clone https://github.com/joernio/joern

##  Step 2
Add and replace the current folders/files in our repo (Add TaintRadar , replace build.sbt , add folder db-schema, replace folder project ) 



## Step 3
Install joren and build the whole project with TainTRadar included

```
chmod +x ./joern-install.sh
sudo ./joern-install.sh
sbt stage
./joern
```
## To generate a CPG for a give application:
```
./joern-parse path/to/app_directory path/to/cpg_output.bin
```



## Before running our approach check if the application has SQL file that builds the database schema and the following python code.
```
python extract_schema.py /path/to/sqlfile.sql 
```
## To run the approach and generated Vulnreable paths for a given PHP or Java APP. 
```
./joern
importCpg("path/to/app_generated_cpg.bin")
cpg.getVulnerablePaths()
```
