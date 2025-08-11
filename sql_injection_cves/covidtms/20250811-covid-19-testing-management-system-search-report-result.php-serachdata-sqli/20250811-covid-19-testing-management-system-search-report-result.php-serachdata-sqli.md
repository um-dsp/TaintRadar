# Exploit Title: COVID 19 Testing Management System – SQL Injection in search-report-result.php (`http://localhost/covid19tms/covid-tms/search-report-result.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com  
**Software Link:** https://www.sourcecodester.com/php/14642/covid19-testing-management-system-using-phpmysql.html  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `search-report-result.php` endpoint of **COVID 19 Testing Management System**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/covid19tms/covid-tms/search-report-result.php`
- **HTTP Method:** POST
- **Vulnerable File:** `search-report-result.php`
- **Parameter:** `serachdata`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `serachdata=1') AND (SELECT 6709 FROM (SELECT(SLEEP(5)))qxpC) AND ('LpQy'='LpQy`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 7 columns
  - **Payload:** 
```
serachdata=1') UNION ALL SELECT CONCAT(0x71786b7171,0x7145575279766545714d7968696c4c4d4c567167476952705265416e444271467263456e516a506a,0x71786a6a71),NULL,NULL,NULL,NULL,NULL,NULL-- -
```



## Proof of Concept (Burp Repeater)

![burp-repeater-poc](poc.png)

## SQLMap Summary

![sqlmap-summary](sqlmap_summary.png)



## Technical Description

The vulnerable parameter is reflected into the SQL statement without proper validation or prepared statements. Boolean-based blind, time-based blind (SLEEP), and/or UNION-based vectors were verified by sqlmap. This enables database enumeration and potential data exfiltration under the privileges of the application’s DB user.

## Impact

- Enumeration of database schemas, tables, and rows  
- Exposure of sensitive user/operational data  
- Potential lateral movement if credentials or session material are stored in DB

## Steps to Reproduce

1. Browse to `http://localhost/covid19tms/covid-tms/search-report-result.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `search-report-result.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
