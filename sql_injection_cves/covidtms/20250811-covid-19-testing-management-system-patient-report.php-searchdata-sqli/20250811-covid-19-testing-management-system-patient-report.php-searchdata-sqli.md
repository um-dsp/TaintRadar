# Exploit Title: COVID 19 Testing Management System – SQL Injection in patient-report.php (`http://localhost/covid19tms/covid-tms/patient-report.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com  
**Software Link:** https://www.sourcecodester.com/php/14642/covid19-testing-management-system-using-phpmysql.html  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `patient-report.php` endpoint of **COVID 19 Testing Management System**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/covid19tms/covid-tms/patient-report.php`
- **HTTP Method:** POST
- **Vulnerable File:** `patient-report.php`
- **Parameter:** `searchdata`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `searchdata=test') AND (SELECT 5448 FROM (SELECT(SLEEP(5)))PTvu) AND ('PPUa'='PPUa`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 7 columns
  - **Payload:** 
```
searchdata=test') UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a786271,0x5366427a6c6473667070706f6e6e77735752696b7a4e6e66537866596c4b4562564b66487344536d,0x7178766271),NULL-- -
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

1. Browse to `http://localhost/covid19tms/covid-tms/patient-report.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `patient-report.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
