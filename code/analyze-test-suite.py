import os
root_directory = '/home/umd-user/Desktop/navex_project/PHP-Test-Suite'
output_directory = '/home/umd-user/Desktop/navex_project/PHP-Test-Suite-Separated/XSS/'

safe = unsafe = 0
assignment = 0
for dir in os.listdir(root_directory):
	if os.path.isdir(root_directory + '/' + dir):
		for code_file in os.listdir(root_directory + '/' + dir + "/src"):
			if os.path.isfile(root_directory + '/' + dir + "/src/" + code_file): 
				with open(root_directory + '/' + dir + "/src/" + code_file) as file:
					data = file.read()
					if "Unsafe sample" in data and "CWE_79" in code_file:
						unsafe += 1
						open(output_directory + "/unsafe/" + code_file, "w").write(data)
					elif "Safe sample" in data and "CWE_79" in code_file:
						safe += 1
						open(output_directory + "/safe/" + code_file, "w").write(data)


print(safe)
print(unsafe)