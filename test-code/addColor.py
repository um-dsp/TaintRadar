graph = open("/home/umd-user/Desktop/navex_project/navex_utils/test-code/output.dot", "r")
tags = open("/home/umd-user/Desktop/navex_project/navex_utils/test-code/tags.txt", "r")
newGraph = open("/home/umd-user/Desktop/navex_project/navex_utils/test-code/coloredOutput.dot", "w")

newGraph.write(graph.readline())
for line in graph:
    newGraph.write(line[:-3])
    tagLine = tags.readline()
    if tagLine=="":
        newGraph.write(line[-3:])
    elif tagLine.split(", ")[1][:4] == "TRUE":
        newGraph.write(", color=green]\n")
    elif tagLine.split(", ")[1][:5] == "FALSE":
        newGraph.write(", color=red]\n")