graph = open("/Users/elirizk/Desktop/navex_project/navex_utils/src/output_graph/output.dot", "r")
tags = open("/Users/elirizk/Desktop/navex_project/navex_utils/src/output_graph/tags.txt", "r")
newGraph = open("/Users/elirizk/Desktop/navex_project/navex_utils/src/output_graph/coloredOutput.dot", "w")

newGraph.write(graph.readline())
for line in graph:
    newGraph.write(line[:-3])
    tagLine = tags.readline()
    if tagLine=="\n" or tagLine=="":
        newGraph.write(line[-3:])
    elif tagLine.split(",")[1][:4] == "TRUE":
        newGraph.write(", fillcolor=\"#b6d7a8ff\", style=filled]\n")
    elif tagLine.split(",")[1][:5] == "FALSE":
        newGraph.write(", fillcolor=\"#ea9999ff\", style=filled]\n")