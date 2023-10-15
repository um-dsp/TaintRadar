import nvdlib
import json
import pandas as pd
import re
import ast
from tqdm import tqdm

def getFiles(description):
    extensions = ['php', 'html', 'js']
    result = []
    for ext in extensions:
        result += re.findall(r'\b\w+\.' + ext + r'\b', description, re.IGNORECASE)
    return result

def getVersions(description):
    result = re.findall(r'\d+\.\d+\.\d+', description)
    for version in result: description = description.replace(version, '')
    result += re.findall(r'\d+\.\d+', description)
    return result

def getVulnerability(description):
    desc = description.lower()
    if "sql" in desc:
        return "SQL Injection"
    elif "xss" in desc or "cross-site scripting" in desc:
        return "XSS"
    elif "file upload" in desc or "file inclusion" in desc:
        return "File Inclusion"
    elif "file access" in desc:
        return "File Access"
    elif "session" in desc:
        return "Session Fixation"
    elif "code injection" in desc:
        return "Code Injection"
    elif "command" in desc:
        return "Command Execution"
    elif "csrf" in desc or "request forgery" in desc:
        return "CSRF"
    else:
        return "NA"
    
def getParameters(description):
    description = description.replace(".", "")
    words = description.split(" ")
    indices = [i for i in range(len(words)) if words[i] == "parameter" or words[i] == "parameters"]
    return [words[i-1] for i in indices]

def getCVEFromNavex(cve, file):
    flag = False
    for index, row in cve.iterrows():
        for fileName in row['filenames']:
            if fileName in file:
                flag = True
                cve_id = row['id']
                break
    if not flag: cve_id = 'NA'
    return cve_id

# Process CVEs into a dataframe

r = nvdlib.searchCVE(keywordSearch='mybloggie')
jsonFormattedCVE = json.dumps(ast.literal_eval(str(r)))
cve = pd.read_json(jsonFormattedCVE)
cve['descriptions'] = cve['descriptions'].apply(lambda descriptions: list(filter(lambda x: x["lang"]=="en", descriptions)))
cve['descriptions'] = cve['descriptions'].apply(lambda descriptions: descriptions[0]['value'])
cve['versions'] = cve['descriptions'].apply(getVersions)
cve['filenames'] = cve['descriptions'].apply(getFiles)
cve['cve_vulnerability'] = cve['descriptions'].apply(getVulnerability)
cve['parameters'] = cve['descriptions'].apply(getParameters)
cve = cve.loc[:, ['id', 'cve_vulnerability', 'versions', 'filenames', 'parameters', 'descriptions']]
# cve = pd.read_excel('cve.xlsx', index_col=0)

# Join potential CVEs and vulnerability paths matches
navex = pd.concat([pd.read_json('paths/mybloggie.json'), pd.read_json('paths/phpBB3.json')])
CVE_ids = []
flag = False
print(navex['vulnerability'].size)
for index, navexRow in tqdm(navex.iterrows()):
    cve_id = 'NA'
    for index, row in cve.iterrows():
        if type(row['filenames'])!=list: files = ast.literal_eval(row['filenames'])
        else: files = row['filenames']
        if not files: files = ['']
        for fileName in files:
            if fileName in navexRow['filename'] or fileName=='':
                if row['cve_vulnerability'] == navexRow['vulnerability']: 
                    if not row['parameters'] and fileName!='':
                        flag = True
                    else:
                        for param in row['parameters']:
                            if param.lower().replace('$','') in navexRow['code'].lower():
                                flag = True
                    if flag:
                            cve_id = row['id']
                            flag = False
                break
    CVE_ids.append(cve_id)
navex['CVE_id'] = CVE_ids
navex = navex.merge(cve, how='left', left_on='CVE_id', right_on='id').drop(columns=['id', 'cve_vulnerability'])

print(navex)

print("Number of exploit matches:", len(pd.unique(navex['CVE_id']))-1, "out of #" + str(len(cve['id'])), "CVEs")
print(pd.unique(navex['CVE_id']))
# print(navex['pathid'].size)
# print(cve)

# Save data to excel
navex.to_excel("navex.xlsx")
cve.to_excel("cve.xlsx")