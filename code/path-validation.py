import nvdlib
import json
import pandas as pd
# r = nvdlib.searchCVE(keywordSearch='phpBB')
# file = open("CVE.json", "w")
# for obj in r:
#     file.write(str(obj))
# with open("CVE.json") as file:
#     result = json.dumps(file.read())
file = open("/home/umd-user/Desktop/navex_project/paths/output.json")
df = pd.read_json(file.read())
print(df)
df.to_csv("output.csv")
print(df.groupby('pathid').apply(list))