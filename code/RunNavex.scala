@main def exec(path: String) = {
    importCpg(path)
    // importCpg("/home/umd-user/joern/workspace/jenkinscpg.bin/cpg.bin.tmp")
    val n = new NavexMain(cpg)
    // save
    // n.getStats() 
    n.outputPaths(false)   
}