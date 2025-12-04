# Security Vulnerability Examples

This repository contains intentionally vulnerable code examples designed to test security scanners (such as Aikido Security Scanner). **⚠️ WARNING: These are intentional security vulnerabilities for testing purposes only. Do not use in production!**

## Purpose

This repository serves as a test suite for security scanning tools, demonstrating common security vulnerabilities across multiple programming languages. Each file contains multiple security issues that security scanners should detect and flag.

## Repository Structure

- **`app.php`** - PHP application with multiple security vulnerabilities
- **`app.py`** - Python/Flask application with security issues
- **`app.js`** - Node.js/Express application with vulnerabilities
- **`app.java`** - Java application with security flaws

## Security Vulnerabilities Included

### 1. Hardcoded Secrets
- API keys (Stripe, GitHub, AWS, Google, etc.)
- Database passwords and credentials
- JWT secrets and tokens
- Encryption keys and private keys
- OAuth client secrets
- Service account credentials

### 2. Sensitive Data Logging
- User passwords logged in plaintext
- Credit card numbers in log files
- Social Security Numbers (SSN) in logs
- Authentication tokens in console output
- User credentials written to files

### 3. SQL Injection
- Unparameterized database queries
- String concatenation in SQL statements
- Direct user input in database queries
- PreparedStatement misuse

### 4. Command Injection
- Unsanitized user input in system commands
- Shell command execution with user data
- Path traversal vulnerabilities

### 5. Cross-Site Scripting (XSS)
- Unescaped user input in HTML output
- Reflected XSS vulnerabilities
- Stored XSS in templates

### 6. Insecure Cryptography
- Weak hashing algorithms (MD5)
- Weak encryption (DES instead of AES)
- Insecure random number generation
- Predictable session IDs

### 7. Insecure File Operations
- Path traversal vulnerabilities
- Unsafe file permissions
- Direct file access without validation

### 8. Exposed Credentials
- API keys in HTTP headers
- Passwords in connection strings
- Secrets in environment variables (hardcoded)
- Credentials in URLs

### 9. NoSQL Injection
- Unsanitized queries in MongoDB
- User input directly in database queries

### 10. Insecure Cookie Settings
- Cookies without HttpOnly flag
- Cookies without Secure flag
- Insecure SameSite settings

## Language-Specific Examples

### PHP (`app.php`)
- Command injection via shell execution
- SQL injection with mysqli
- XSS in HTML output
- Hardcoded secrets
- Credential logging

### Python (`app.py`)
- Flask application vulnerabilities
- SQL injection with MySQL connector
- Command injection via `os.system()`
- MD5 hashing (weak cryptography)
- Insecure random number generation

### JavaScript/Node.js (`app.js`)
- Express.js application vulnerabilities
- NoSQL injection with MongoDB
- XSS in template rendering
- Insecure cookie configuration
- Command injection via `child_process`

### Java (`app.java`)
- SQL injection vulnerabilities
- Command injection via `Runtime.exec()`
- DES encryption (weak cryptography)
- Insecure file operations
- Logging sensitive data

## Usage

This repository is intended for:
- Testing security scanning tools
- Security training and education
- Vulnerability research
- Security scanner benchmarking

**⚠️ Never deploy this code to production environments!**

## Security Scanner Testing

Security scanners like Aikido should detect and flag:
- All hardcoded secrets and credentials
- SQL injection vulnerabilities
- Command injection risks
- XSS vulnerabilities
- Sensitive data in logs
- Weak cryptography usage
- Insecure configurations

## Disclaimer

All code in this repository contains intentional security vulnerabilities for educational and testing purposes. These vulnerabilities should never be used in production code. Always follow security best practices in real applications.

