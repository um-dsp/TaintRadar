import org.scalatest.matchers.should.Matchers.shouldBe
// sudo chmod +x /Users/elirizk/Desktop/navex_project/joern/joern-cli/target/universal/stage/frontends/javasrc2cpg/bin/javasrc2cpg
object PHPTests {
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
    
    val test1 = "papersan.php"
    getTag (cpg.call("echo").filter(byFile(_,test1))) shouldBe List("FALSE")
    
}
