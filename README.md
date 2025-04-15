Sample standalone applications on top of joern
=============================================

## A program that makes use of Joern to create a CPG and list all method names

```
sbt stage
./standalone
```
## To generate a CPG for a give application:
```
./joern-parse path/to/app_directory path/to/cpg_output.bin
```
## A REPL with some custom cpg steps

```
sbt stage
./repl

Welcome to the wonderful world of this sample joern extension!
joern-sample-ext>
```

To get started you could try the following commands - then just explore
```
// import a cpg that you created previously, e.g. in joern
importCpg("path/to/some/cpg.bin")

cpg.help  
==> 
Available starter steps:
___________________________________________________________________________________________________________________________
 step               | description                                                                                         |
==========================================================================================================================|
 .all               | All nodes of the graph                                                                              |
 ...
 .customStarterStep | custom starter step as an example                                                                   |
 ...
 

cpg.customSta<TAB> // autocompletes

cpg.method.help
==>
Available steps for Method:
_______________________________________________________________________________________
 step                 | description                                                   |
======================================================================================|
 .address             | Address of the code (for binary code)                         |
 ...
 .customMethodStep    | custom step on method as an example                           |
 ...



cpg.method.cust<TAB> // autocompletes
```
## Before running our approach check if the application has SQL file that builds the database schema and the following python code.
```
python extract_schema.py /path/to/sqlfile.sql 
```
## To run the approach and generated Vulnreable paths for a given PHP or Java APP. 
```
./TaintRadar.sh /path/to/generate_Cpg path/to/therepo /logs/analysis.log
```
## To do the Path validation Part run path-validation.ipynb notebook after modifying the paths and app Name . 




Hint: `./repl --verbose` is your friend.
