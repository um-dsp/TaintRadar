from cpgqls_client import CPGQLSClient, import_code_query

server_endpoint = "localhost:8080"
client = CPGQLSClient(server_endpoint)

query = import_code_query("/home/umd-user/Desktop/navex_project/navex_tests/mybloggie214", "test-app")    
result = client.execute(query)
print(result['stdout'])

# execute a simple CPGQuery to list all methods in the code
file = open("Constants.scala")
client.execute(file.read())
file = open("SanitizationFilter.scala")
client.execute(file.read())
file = open("NavexMain.scala")
client.execute(file.read())
query = "val n = new NavexMain(cpg)"
client.execute(query)
query = "n.outputPaths()"
result = client.execute(query)
file = open("output.csv", "w")
file.write(result['stdout'])
print(result)
	