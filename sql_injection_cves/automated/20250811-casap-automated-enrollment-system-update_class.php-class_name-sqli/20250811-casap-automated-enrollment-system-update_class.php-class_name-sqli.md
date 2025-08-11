# Exploit Title: CASAP-Automated-Enrollment-System – SQL Injection in update_class.php (`http://localhost/automated/update_class.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com/php/12210/casap-automated-enrollment-system.html  
**Software Link:**  https://www.sourcecodester.com/download-code?nid=12210&title=CASAP+Automated+Enrollment+System+using+PHP%2FMySQLi+with+Source+Code  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `update_class.php` endpoint of **CASAP-Automated-Enrollment-System**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/automated/update_class.php`
- **HTTP Method:** POST
- **Vulnerable File:** `update_class.php`
- **Parameter:** `class_name`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
  - **Payload:** `class_name=test' RLIKE (SELECT (CASE WHEN (3833=3833) THEN 0x74657374 ELSE 0x28 END)) AND 'tNzf'='tNzf`
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `class_name=test' AND (SELECT 7960 FROM (SELECT(SLEEP(5)))EYOP) AND 'PsFV'='PsFV`



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

1. Browse to `http://localhost/automated/update_class.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `update_class.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
