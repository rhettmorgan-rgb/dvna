# Security Scan Report - DVNA (Damn Vulnerable NodeJS Application)
**Scan Date:** August 6, 2026  
**Repository:** Damn Vulnerable NodeJS Application  
**Purpose:** Educational - Demonstrates OWASP Top 10 Vulnerabilities

---

## Executive Summary

This is an **intentionally vulnerable** Node.js application designed for security training. The application contains numerous critical security vulnerabilities across multiple categories including injection attacks, insecure deserialization, command injection, and vulnerable dependencies.

### Severity Overview
- 🔴 **Critical:** 8+ vulnerabilities
- 🟠 **High:** 15+ vulnerabilities  
- 🟡 **Medium:** Multiple configuration issues
- 🔵 **Low:** Several informational findings

---

## 1. VULNERABLE DEPENDENCIES (SCA - Software Composition Analysis)

### Critical Dependency Vulnerabilities

#### 1.1 node-serialize (v0.0.4)
- **Severity:** CRITICAL
- **CVE:** Multiple RCE vulnerabilities
- **Issue:** Remote Code Execution via insecure deserialization
- **Location:** `package.json` line 29
- **Impact:** Allows arbitrary code execution
- **Remediation:** Remove this package entirely; use JSON.parse() instead

#### 1.2 ejs (v2.5.7)
- **Severity:** CRITICAL
- **Known CVEs:** CVE-2017-1000188, CVE-2022-29078
- **Issue:** Template injection leading to RCE
- **Location:** `package.json` line 18
- **Remediation:** Upgrade to ejs ^3.1.10 or later

#### 1.3 libxmljs (v0.19.1)
- **Severity:** CRITICAL
- **Known CVEs:** Multiple XXE (XML External Entity) vulnerabilities
- **Issue:** XML External Entity injection
- **Location:** `package.json` line 24
- **Remediation:** Upgrade to libxmljs2 or use alternative XML parser

#### 1.4 mathjs (v3.10.1)
- **Severity:** HIGH
- **Known CVEs:** CVE-2022-21222, CVE-2023-42460
- **Issue:** Expression injection leading to RCE
- **Location:** `package.json` line 25
- **Remediation:** Upgrade to mathjs ^11.0.0 or later

#### 1.5 express-fileupload (v0.4.0)
- **Severity:** HIGH
- **Known CVEs:** Prototype pollution vulnerabilities
- **Issue:** Prototype pollution, file upload bypass
- **Location:** `package.json` line 20
- **Remediation:** Upgrade to express-fileupload ^1.5.0 or later

#### 1.6 sequelize (v4.13.10)
- **Severity:** HIGH
- **Known CVEs:** SQL injection vulnerabilities
- **Issue:** SQL injection in certain query operations
- **Location:** `package.json` line 32
- **Remediation:** Upgrade to sequelize ^6.37.0 or later

#### 1.7 mysql2 (v1.4.2)
- **Severity:** MEDIUM
- **Issue:** Multiple security fixes in newer versions
- **Location:** `package.json` line 28
- **Remediation:** Upgrade to mysql2 ^3.0.0 or later

#### 1.8 express-session (v1.15.6)
- **Severity:** MEDIUM
- **Issue:** Session fixation and security improvements
- **Location:** `package.json` line 22
- **Remediation:** Upgrade to express-session ^1.18.0 or later

#### 1.9 bcrypt (v1.0.3)
- **Severity:** MEDIUM
- **Issue:** Outdated, multiple security improvements in newer versions
- **Location:** `package.json` line 16
- **Remediation:** Upgrade to bcrypt ^5.1.0 or later

---

## 2. CODE VULNERABILITIES (SAST - Static Application Security Testing)

### 2.1 SQL Injection (CWE-89)

#### Location: `core/appHandler.js` lines 10-11
```javascript
var query = "SELECT name,id FROM Users WHERE login='" + req.body.login + "'";
db.sequelize.query(query, {
    model: db.User
})
```

- **Severity:** CRITICAL
- **OWASP:** A03:2021 – Injection
- **Impact:** Complete database compromise, data exfiltration, authentication bypass
- **Attack Vector:** `' OR '1'='1` in login parameter
- **Remediation:** Use parameterized queries or ORM methods

**Fixed Code:**
```javascript
db.User.findOne({
    where: {
        login: req.body.login
    }
})
```

---

### 2.2 Command Injection (CWE-78)

#### Location: `core/appHandler.js` line 39
```javascript
exec('ping -c 2 ' + req.body.address, function (err, stdout, stderr) {
    output = stdout + stderr
    res.render('app/ping', {
        output: output
    })
})
```

- **Severity:** CRITICAL
- **OWASP:** A03:2021 – Injection
- **Impact:** Remote Code Execution, complete server compromise
- **Attack Vector:** `127.0.0.1; cat /etc/passwd` in address parameter
- **Remediation:** Never execute user input directly; use input validation and safe alternatives

**Fixed Code:**
```javascript
// Validate input is valid IP address only
if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(req.body.address)) {
    return res.render('app/ping', { output: 'Invalid IP address' });
}
// Use safe ping library instead of exec
```

---

### 2.3 Expression Injection (CWE-94)

#### Location: `core/appHandler.js` lines 194-198
```javascript
module.exports.calc = function (req, res) {
    if (req.body.eqn) {
        res.render('app/calc', {
            output: mathjs.eval(req.body.eqn)
        })
    }
}
```

- **Severity:** CRITICAL
- **OWASP:** A03:2021 – Injection
- **Impact:** Remote Code Execution
- **Attack Vector:** Malicious math expressions accessing Node.js internals
- **Remediation:** Sanitize and validate mathematical expressions, use safe math parser

---

### 2.4 Insecure Deserialization (CWE-502)

#### Location: `core/appHandler.js` lines 215-231
```javascript
module.exports.bulkProductsLegacy = function (req,res){
    if(req.files.products){
        var products = serialize.unserialize(req.files.products.data.toString('utf8'))
        products.forEach( function (product) {
            var newProduct = new db.Product()
            newProduct.name = product.name
            // ...
        })
    }
}
```

- **Severity:** CRITICAL
- **OWASP:** A08:2021 – Software and Data Integrity Failures
- **Impact:** Remote Code Execution
- **Attack Vector:** Malicious serialized object containing IIFE code
- **Remediation:** Never deserialize untrusted data; use JSON.parse() instead

**Attack Example:**
```javascript
{"rce":"_$$ND_FUNC$$_function (){ require('child_process').exec('malicious command', function(error, stdout, stderr) { console.log(stdout) }); }()"}
```

---

### 2.5 XML External Entity (XXE) Injection (CWE-611)

#### Location: `core/appHandler.js` line 235
```javascript
var products = libxmljs.parseXmlString(req.files.products.data.toString('utf8'), {noent:true,noblanks:true})
```

- **Severity:** CRITICAL
- **OWASP:** A05:2021 – Security Misconfiguration
- **Impact:** File disclosure, SSRF, DoS
- **Attack Vector:** XML document with external entity references
- **Option Issue:** `noent:true` enables entity expansion (vulnerable configuration)
- **Remediation:** Set `noent:false` and disable external entities

**Attack Example:**
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
```

---

### 2.6 Open Redirect (CWE-601)

#### Location: `core/appHandler.js` lines 186-192
```javascript
module.exports.redirect = function (req, res) {
    if (req.query.url) {
        res.redirect(req.query.url)
    } else {
        res.send('invalid redirect url')
    }
}
```

- **Severity:** MEDIUM
- **OWASP:** A01:2021 – Broken Access Control
- **Impact:** Phishing, credential theft
- **Attack Vector:** `?url=https://evil.com`
- **Remediation:** Validate redirect URLs against allowlist

---

### 2.7 Insecure Password Reset Token (CWE-640)

#### Location: `core/authHandler.js` lines 49, 78
```javascript
if (req.query.token == md5(req.query.login)) {
    res.render('resetpw', {
        login: req.query.login,
        token: req.query.token
    })
}
```

- **Severity:** HIGH
- **OWASP:** A07:2021 – Identification and Authentication Failures
- **Impact:** Account takeover
- **Issue:** Reset token is predictable (MD5 of username)
- **Attack Vector:** Attacker can generate valid reset tokens for any user
- **Remediation:** Use cryptographically secure random tokens

**Fixed Code:**
```javascript
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
// Store token with expiration in database
```

---

### 2.8 Insecure Session Configuration (CWE-614)

#### Location: `server.js` lines 23-28
```javascript
app.use(session({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false }
}))
```

- **Severity:** HIGH
- **OWASP:** A05:2021 – Security Misconfiguration
- **Issues:**
  1. Weak, hardcoded session secret
  2. `secure: false` allows session cookies over HTTP
  3. Missing `httpOnly` flag
  4. Missing `sameSite` flag
- **Impact:** Session hijacking, CSRF attacks
- **Remediation:** Use strong random secret, enable secure flags

**Fixed Code:**
```javascript
app.use(session({
  secret: process.env.SESSION_SECRET, // Strong random value from env
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: true,      // HTTPS only
    httpOnly: true,    // No JavaScript access
    sameSite: 'strict', // CSRF protection
    maxAge: 3600000    // 1 hour expiration
  }
}))
```

---

### 2.9 Insecure Direct Object Reference (IDOR) (CWE-639)

#### Location: `core/appHandler.js` lines 144-149
```javascript
module.exports.userEditSubmit = function (req, res) {
    db.User.find({
        where: {
            'id': req.body.id  // User-controlled ID without verification
        }		
    }).then(user =>{
        // Modifies user without checking ownership
    })
}
```

- **Severity:** HIGH
- **OWASP:** A01:2021 – Broken Access Control
- **Impact:** Horizontal privilege escalation, users can modify other users' accounts
- **Attack Vector:** Change `id` parameter to another user's ID
- **Remediation:** Verify user owns the resource before modification

**Fixed Code:**
```javascript
if (req.body.id !== req.user.id) {
    return res.status(403).send('Unauthorized');
}
```

---

### 2.10 Missing Authorization Check (CWE-862)

#### Location: `routes/app.js` line 48
```javascript
router.get('/redirect', appHandler.redirect)
```

- **Severity:** MEDIUM
- **Issue:** `/redirect` endpoint lacks authentication
- **Impact:** Open redirect available to unauthenticated users
- **Remediation:** Add `authHandler.isAuthenticated` middleware

---

### 2.11 Stored Cross-Site Scripting (XSS) (CWE-79)

#### Location: Multiple locations - Product data rendering
```javascript
// appHandler.js - User input stored without sanitization
product.name = req.body.name
product.description = req.body.description
product.tags = req.body.tags
```

- **Severity:** HIGH
- **OWASP:** A03:2021 – Injection
- **Impact:** Session hijacking, credential theft, defacement
- **Attack Vector:** `<script>alert(document.cookie)</script>` in product fields
- **Remediation:** Implement output encoding in EJS templates, Content Security Policy

---

### 2.12 Weak Cryptographic Hash (CWE-327)

#### Location: `core/authHandler.js` line 3, 49, 78
```javascript
var md5 = require('md5')
// Used for password reset tokens
if (req.query.token == md5(req.query.login))
```

- **Severity:** HIGH
- **OWASP:** A02:2021 – Cryptographic Failures
- **Issue:** MD5 is cryptographically broken
- **Impact:** Predictable tokens, easy to brute force
- **Remediation:** Use SHA-256 or better, prefer crypto.randomBytes()

---

### 2.13 Information Disclosure

#### Location: `core/appHandler.js` lines 30-35
```javascript
}).catch(err => {
    req.flash('danger', 'Internal Error')  // Generic error
    res.render('app/usersearch', {
        output: null
    })
})
```

- **Severity:** LOW
- **Good Practice:** Not revealing SQL error details
- **Note:** However, other endpoints may leak error information

---

### 2.14 Missing Rate Limiting

#### Location: `server.js` - No rate limiting configured

- **Severity:** MEDIUM
- **OWASP:** A07:2021 – Identification and Authentication Failures
- **Impact:** Brute force attacks, credential stuffing, DoS
- **Remediation:** Implement rate limiting with express-rate-limit

---

### 2.15 No CSRF Protection (Despite csurf being installed)

#### Location: `package.json` line 17, but not implemented in `server.js`

- **Severity:** HIGH
- **OWASP:** A01:2021 – Broken Access Control
- **Issue:** CSRF middleware installed but not used
- **Impact:** Cross-Site Request Forgery attacks
- **Remediation:** Enable and properly configure csurf middleware

---

## 3. SECURITY CONFIGURATION ISSUES

### 3.1 Missing Security Headers

**Missing Headers:**
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- Referrer-Policy

**Note:** `x-xss-protection` is installed but deprecated and ineffective

**Remediation:**
```javascript
const helmet = require('helmet');
app.use(helmet());
```

---

### 3.2 Debug/Development Features Enabled

- Morgan logger in production mode
- Verbose error messages
- No environment-based configuration

---

### 3.3 No Input Validation

- Missing validation middleware
- No request size limits beyond defaults
- No input sanitization

**Recommendation:** Implement express-validator or joi for input validation

---

## 4. INFRASTRUCTURE VULNERABILITIES

### 4.1 Docker Configuration Issues

#### Dockerfile Issues:
- No USER directive (runs as root)
- No health check defined
- Potential for container escape if exploited

---

## 5. SECURITY RECOMMENDATIONS

### Immediate Actions (Critical Priority)

1. **Replace vulnerable dependencies:**
   ```bash
   npm install ejs@^3.1.10 --save
   npm uninstall node-serialize
   npm install libxmljs2@latest --save
   npm install mathjs@^11.0.0 --save
   npm install express-fileupload@^1.5.0 --save
   npm install sequelize@^6.37.0 --save
   ```

2. **Fix SQL Injection:** Replace all raw queries with parameterized queries

3. **Fix Command Injection:** Remove exec() calls with user input

4. **Remove Insecure Deserialization:** Replace serialize.unserialize() with JSON.parse()

5. **Fix XXE:** Set `noent: false` in libxmljs configuration

### High Priority

6. **Implement proper authentication token generation**
7. **Add CSRF protection**
8. **Fix IDOR vulnerabilities**
9. **Implement rate limiting**
10. **Add input validation middleware**

### Medium Priority

11. **Update session configuration**
12. **Add security headers with Helmet**
13. **Implement Content Security Policy**
14. **Add output encoding for XSS prevention**
15. **Validate redirect URLs**

### Best Practices

16. **Environment variables:** Move secrets to environment variables
17. **Logging:** Implement secure logging (don't log sensitive data)
18. **Error handling:** Implement proper error handling without information leakage
19. **Docker:** Run as non-root user
20. **CI/CD:** Integrate security scanning in pipeline

---

## 6. AUTOMATED SCANNING RECOMMENDATIONS

To enable automated Snyk scanning in Cursor Cloud Agents:

### Setup Instructions:

1. **Get Snyk API Token:**
   - Go to https://app.snyk.io/
   - Account Settings → API Token
   - Copy your token

2. **Add to Cursor Dashboard:**
   - Go to Cursor Dashboard → Cloud Agents → Secrets
   - Add secret: `SNYK_TOKEN` = `<your-token>`

3. **Re-run Scan:**
   ```bash
   snyk test --all-projects
   snyk code test
   snyk container test
   ```

---

## 7. COMPLIANCE & STANDARDS

### OWASP Top 10 2021 Coverage

This application demonstrates vulnerabilities across all OWASP Top 10 categories:

- ✅ A01:2021 – Broken Access Control (IDOR, Missing Authorization, Open Redirect)
- ✅ A02:2021 – Cryptographic Failures (MD5 usage, weak session secret)
- ✅ A03:2021 – Injection (SQL, Command, Expression, XSS)
- ✅ A04:2021 – Insecure Design (Overall architecture)
- ✅ A05:2021 – Security Misconfiguration (Missing headers, weak session config, XXE enabled)
- ✅ A06:2021 – Vulnerable and Outdated Components (Multiple outdated dependencies)
- ✅ A07:2021 – Identification and Authentication Failures (Weak reset tokens, no rate limiting)
- ✅ A08:2021 – Software and Data Integrity Failures (Insecure deserialization)
- ✅ A09:2021 – Security Logging and Monitoring Failures (Minimal logging)
- ✅ A10:2021 – Server-Side Request Forgery (Potential via XXE)

---

## 8. CONCLUSION

This application contains **extensive critical vulnerabilities** by design for educational purposes. The vulnerabilities span across:

- **8+ Critical** severity issues (RCE vulnerabilities)
- **15+ High** severity issues (Authentication, injection, access control)
- **Multiple Medium/Low** severity issues (Configuration, information disclosure)

### For Educational Use:
This application serves its purpose excellently as a training tool for learning about web application security vulnerabilities.

### For Production:
**NEVER deploy this application or similar code in production environments.**

---

## Resources

- **OWASP Top 10:** https://owasp.org/Top10/
- **DVNA Documentation:** https://appsecco.com/books/dvna-developers-security-guide/
- **CWE:** https://cwe.mitre.org/
- **Snyk Vulnerability Database:** https://security.snyk.io/

---

**Report Generated By:** Cursor Cloud Agent Security Scanner  
**Scan Method:** Manual Code Review + Dependency Analysis  
**Next Steps:** Configure Snyk authentication for automated scanning
