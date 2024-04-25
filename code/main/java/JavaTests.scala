import org.scalatest.matchers.should.Matchers.shouldBe
// sudo chmod +x /Users/elirizk/Desktop/navex_project/joern/joern-cli/target/universal/stage/frontends/javasrc2cpg/bin/javasrc2cpg
object JavaTests {
    def byFile(node: Expression, file_name: String) = node.file.name.head.contains(file_name)

    def getTag(it: Iterator[StoredNode], idx: Int = 0, tag_name: String = "") = {
        if (tag_name == "") {
            if (idx == 0) it.head.tag.value.dedup.l
            else if (idx == -1) it.last.tag.value.dedup.l
            else it.toList(idx).tag.value.dedup.l
        }
        else {
            if (idx == 0) it.head.tag.name(tag_name).value.l
            else if (idx == -1) it.last.tag.name(tag_name).value.l
            else it.toList(idx).tag.name(tag_name).value.l
        }
    }

    // val cpg = importCode("code/tests/java-tests")
    
    val test1 = "OngetParameter.java"
    getTag (cpg.identifier("n1").filter(byFile(_,test1))) shouldBe List("FALSE")
    getTag (cpg.identifier("n2").filter(byFile(_,test1))) shouldBe List("FALSE")
    getTag (cpg.identifier("result").filter(byFile(_,test1))) shouldBe List("TRUE")
    getTag (cpg.call("println").filter(byFile(_,test1))) shouldBe List("TRUE")

    val test2 = "SafeSQLInjection.java"
    getTag (cpg.identifier("username").filter(byFile(_,test2))) shouldBe List("FALSE")
    getTag (cpg.identifier("password").filter(byFile(_,test2))) shouldBe List("FALSE")
    getTag (cpg.identifier("sqlQuery").filter(byFile(_,test2))) shouldBe List("TRUE")
    getTag (cpg.call("executeUpdate").filter(byFile(_,test2))) shouldBe List("TRUE")

    val test3 = "SafeSqlInjectionHTTP.java"
    getTag (cpg.identifier("username").filter(byFile(_,test3)), -1) shouldBe List("FALSE")
    getTag (cpg.identifier("password").filter(byFile(_,test3)), -1) shouldBe List("FALSE")
    getTag (cpg.identifier("sqlQuery").filter(byFile(_,test3)), -1) shouldBe List("TRUE")
    getTag (cpg.call("executeQuery").filter(byFile(_,test3)), 0, "SAN_SQL_Injection") shouldBe List("TRUE")
    getTag (cpg.call("executeQuery").filter(byFile(_,test3)), 0, "SAN_XSS") shouldBe List("FALSE")

    val test4 = "test.java"
    getTag (cpg.identifier("this").filter(byFile(_,test3)), -1) shouldBe List("FALSE")
    getTag (cpg.identifier("password").filter(byFile(_,test3)), -1) shouldBe List("FALSE")
    getTag (cpg.identifier("sqlQuery").filter(byFile(_,test3)), -1) shouldBe List("TRUE")
    getTag (cpg.call("executeQuery").filter(byFile(_,test3)), 0, "SAN_SQL_Injection") shouldBe List("TRUE")
    getTag (cpg.assignment.filter(byFile(_,test4)), 0) shouldBe List("FALSE")
}
