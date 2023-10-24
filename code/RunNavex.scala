@main def exec(path: String, name: String) = {
    println("______________" + name + "______________")
    importCpg(path)
    val n = new NavexMain(cpg)
    n.getStats()
}