graph = open("/home/umd-user/Desktop/navex_project/navex_utils/test-code/output_graph/output.dot", "r")
tags = open("/home/umd-user/Desktop/navex_project/navex_utils/test-code/output_graph/tags.txt", "r")
newGraph = open("/home/umd-user/Desktop/navex_project/navex_utils/test-code/output_graph/coloredOutput.dot", "w")

newGraph.write(graph.readline())
for line in graph:
    newGraph.write(line[:-3])
    tagLine = tags.readline()
    if tagLine=="":
        newGraph.write(line[-3:])
    elif tagLine.split(", ")[1][:4] == "TRUE":
        newGraph.write(", fillcolor=\"#b6d7a8ff\", style=filled]\n")
    elif tagLine.split(", ")[1][:5] == "FALSE":
        newGraph.write(", fillcolor=\"#ea9999ff\", style=filled]\n")