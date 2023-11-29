import nvdlib
import json
import pandas as pd
import re
import ast
from tqdm import tqdm
import sys
import string
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import os
import fnmatch

tqdm.pandas()
directory_path = "/home/umd-user/Desktop/navex_project/navex_tests/osCommerce"
appName = 'oscommerce'
extension = ''
appVersion = '2.3.4.1'

nltk.download('stopwords')
nltk.download('punkt')

stopwords = list(filter(lambda x: len(x)>1, stopwords.words('english')))
punctuation = set(string.punctuation)
punctuation.remove('(')
punctuation.remove(')')
punctuation.remove('$')

def getFiles(description):
    # extensions = ['php', 'html', 'js']
    extensions = ['php']
    result = []
    for ext in extensions:
        result += re.findall(r'\b\w+\.' + ext + r'\b', description, re.IGNORECASE)
    return result

def getVersions(description):
    result = re.findall(r'\d+\.\d+\.\d+', description)
    for version in result: description = description.replace(version, '')
    result += re.findall(r'\d+\.\d+', description)
    if result==[]:
        return ['0']
    else: return result

def getVulnerability(description):
    desc = description.lower()
    if "sql" in desc:
        return "SQL Injection"
    elif "xss" in desc or "cross-site scripting" in desc or "cross site scripting" in desc:
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
    # elif "csrf" in desc or "request forgery" in desc:
    #     return "CSRF"
    else:
        return "NA"
    
# Compute whether appVersion was released before cveVersion (inclusive)
def compareVersions(appVersion, cveVersions):
    flag = False
    if (len(cveVersions)==0 or len(appVersion)==0 or cveVersions==['0']): flag = True
    for cveVersion in cveVersions:
        v1 = list(map(int, appVersion.split('.')))
        v2 = list(map(int, cveVersion.split('.')))
        size = min(len(v1), len(v2))
        v1 = v1[:size]
        v2 = v2[:size]
        if (v1 <= v2): flag = True
    return flag

def getParameters(description):
    words = word_tokenize(description)
    words = [word for word in words if word.lower() not in stopwords and word not in punctuation]
    indices = [i for i in range(1, len(words)) if words[i] == "parameter" or words[i] == "parameters"]
    params = [words[i-1] for i in indices]
    indices = [i for i in range(1, len(words)-2) if (words[i-1]=='(' and words[i].isdigit() and words[i+1]==')')]
    params += [words[i+2] for i in indices]
    indices = [i for i in range(len(words)-1) if words[i] == "function" or words[i]=="$"]
    params += [words[i+1] for i in indices]
    params = [param.replace('"', '') for param in params if ('.php' not in param and '/' not in param)]
    return list(set(params))

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

def filterOnFiles(fileNames):
    if fileNames == []: return True
    for root, dirs, files in os.walk(directory_path):
        for fileName in fileNames:
            for filename in fnmatch.filter(files, fileName):
                # file_path = os.path.join(root, filename)
                return True
    return False

def getFilesFromParameters(parameters):
    file_paths = []
    pattern = r'(?:' + '|'.join(re.escape(parameter) for parameter in parameters) + r')\b'
    if parameters == []: return file_paths
    for root, dirs, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                if re.search(pattern, content):
                    file_paths.append(file_path)
    return file_paths

matchedCVEs = []
def matched(value):
    if value not in matchedCVEs:
        matchedCVEs.append(value)
        # print(value)

# Process CVEs into a dataframe
if len(sys.argv)>1:
    cve = pd.read_excel(f'cve/{appName}-{extension}cve.xlsx', index_col=0)

else:
    r = nvdlib.searchCVE(keywordSearch=appName)
    jsonFormattedCVE = json.dumps(ast.literal_eval(str(r)))
    cve = pd.read_json(jsonFormattedCVE)
    cve['descriptions'] = cve['descriptions'].apply(lambda descriptions: list(filter(lambda x: x["lang"]=="en", descriptions)))
    cve['descriptions'] = cve['descriptions'].apply(lambda descriptions: descriptions[0]['value'])
    cve['versions'] = cve['descriptions'].apply(getVersions)
    cve['filenames'] = cve['descriptions'].apply(getFiles)
    cve['cve_vulnerability'] = cve['descriptions'].apply(getVulnerability)
    cve['parameters'] = cve['descriptions'].apply(getParameters)
    cve['relevant_version'] = cve['versions'].apply(lambda x: compareVersions(appVersion, x)) # and compareVersions(x[0], ['5.0.0']))

    cve = cve[cve['cve_vulnerability']!='NA']
    cve = cve[cve['relevant_version']==True]
    cve = cve[cve['filenames'].apply(filterOnFiles)]
    cve = cve[cve['parameters'].apply(lambda params: getFilesFromParameters(params) != [])]
    cve = cve[cve['filenames'].map(lambda x: x!=[]) | cve['parameters'].map(lambda x: x!=[])]
    cve['filenames'] = cve.apply(lambda x: x.filenames if x.filenames!=[] else list(map(lambda x: x.split('/')[-1], getFilesFromParameters(x.parameters))), axis=1)

    cve = cve.loc[:, ['id', 'cve_vulnerability', 'versions', 'filenames', 'parameters', 'descriptions']]

print(cve)
cve.to_excel(f"cve/{appName}-{extension}cve.xlsx")

# Join potential CVEs and vulnerability paths matches
navex = pd.read_json(f'paths/{appName}-{extension}output.json')
print(navex['vulnerability'].size)

def getCVEids(navexRow):
    flag = False
    debug = False
    cve_id = 'NA'
    for index, row in cve.iterrows():
        if row['id']=='CVE-2005-2838' and ("$_POST[\"username\"]") in navexRow['code']: debug = True

        if type(row['filenames'])!=list: files = ast.literal_eval(row['filenames'])
        else: files = row['filenames']
        if type(row['parameters'])!=list: cveParams = ast.literal_eval(row['parameters'])
        else: cveParams = row['parameters']
        if not files: files = ['']
        for fileName in files:
            if fileName in navexRow.loc['filename'] or fileName=='':
                if row['cve_vulnerability'] == navexRow['vulnerability']: 
                    if not cveParams and fileName!='':
                        flag = True
                    else:
                        for param in cveParams:
                            if param.lower().replace('$','') in navexRow['code'].lower():
                                flag = True
                    if flag:
                            cve_id = row['id']
                            flag = False
                            matched(cve_id)
                            # return cve_id
    return cve_id

CVE_ids = navex.progress_apply(getCVEids, axis=1)
navex['CVE_id'] = CVE_ids
navex = navex.merge(cve, how='left', left_on='CVE_id', right_on='id').drop(columns=['id', 'cve_vulnerability'])

print(navex)

# print("Number of exploit matches:", len(pd.unique(navex['CVE_id']))-1, "out of #" + str(len(cve['id'])), "CVEs")
print("Number of exploit matches:", len(matchedCVEs), "out of #" + str(len(cve['id'])), "CVEs")
print(matchedCVEs)
print(pd.unique(navex['CVE_id']))
# print(navex['pathid'].size)
# print(cve)

# Save data to excel
navex.to_excel(f"cve/{appName}-{extension}navex.xlsx")