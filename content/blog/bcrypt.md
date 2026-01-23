+++
date = '2025-10-25T11:51:55+05:30'
draft = false
title = 'Breaking Authentication: Bcrypt Truncation & Email Normalization'
+++

{{< toc >}}

## Introduction

During ImaginaryCTF 2025, I tackled a very fascinating web challenge called "passwordless" that showcased how multiple subtle implementation flaws can combine to create a critical authentication bypass. The challenge presented a Node.js authentication system where users register with their email and receive a randomly generated temporary password—except the password delivery mechanism was never implemented.

What made this challenge particularly interesting is that every security component appeared properly implemented at first glance: bcrypt for password hashing, email normalization to prevent duplicates, input validation, and rate limiting. However, the devil was in the details. The interaction between bcrypt's 72-byte truncation limit, inconsistent email processing, and user-controlled password components created a perfect exploit chain allowing complete authentication bypass.

### Attack Chain Overview

**→** Identify password generation uses raw email + random hex

**→** Discover bcrypt truncates passwords at 72 bytes

**→** Find inconsistent email normalization between validation and password generation

**→** Craft 72-byte email that normalizes to <64 chars

**→** Register account bypassing length validation

**→** Login using email as password (random portion ignored by bcrypt)

---

## The Application

The target was a straightforward Express.js application with user registration and login functionality. The system was designed to send users a temporary password via email upon registration, though this feature remained unimplemented at the time of discovery.

**Key Features:**
- Email-based registration with auto-generated temporary passwords
- Bcrypt password hashing for secure storage
- Email normalization to prevent duplicate accounts
- Rate limiting on authentication endpoints
- Session-based authentication after login

### Technology Stack

- **Runtime:** Node.js with Express.js framework
- **Database:** SQLite3 with in-memory storage
- **Password Hashing:** bcrypt (10 rounds)
- **Email Processing:** normalize-email npm package
- **Session Management:** express-session with MemoryStore

---

## Source Code Analysis

Let's examine the vulnerable registration endpoint in detail. The code appears straightforward but contains subtle flaws that become apparent under scrutiny.

### User Registration Endpoint

```javascript
app.post('/user', limiter, (req, res, next) => {
    if (!req.body) return res.redirect('/login')

    const nEmail = normalizeEmail(req.body.email)

    if (nEmail.length > 64) {
        req.session.error = 'Your email address is too long'
        return res.redirect('/login')
    }

    const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')
    bcrypt.hash(initialPassword, 10, function (err, hash) {
        if (err) return next(err)

        const query = "INSERT INTO users VALUES (?, ?)"
        db.run(query, [nEmail, hash], (err) => {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    req.session.error = 'This email address is already registered'
                    return res.redirect('/login')
                }
                return next(err)
            }

            // TODO: Send email with initial password

            req.session.message = 'An email has been sent with a temporary password for you to log in'
            res.redirect('/login')
        })
    })
})
```

---

## Vulnerability Analysis

### Vulnerability #1: Predictable Password Generation

The application generates temporary passwords using a combination of the user's email and random bytes:

```javascript
const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')
```

This creates a password with the following structure:

**Password Format:**
```c
[user_email_address] + [32_hexadecimal_characters]
```

**Example:**
```c
counter@strike.com + a3f9b7d1e84c6f2a5c3d7e98f0a123bc
Result: counter@strike.coma3f9b7d1e84c6f2a5c3d7e98f0a123bc
```

While the random component appears to provide security, this design has a critical flaw: it includes user-controlled data (the email address) as part of the password. Since users control the length of their email, they can influence what portion of the password bcrypt actually processes.

### Vulnerability #2: Bcrypt's 72-Byte Truncation

Bcrypt has a well-documented limitation that's often overlooked: it only processes the first 72 bytes of input and silently discards everything beyond that point. This isn't a bug—it's a fundamental characteristic of bcrypt's design.

**Security Impact:** If an attacker can create an email address that's exactly 72 bytes long, the random hexadecimal suffix will be completely ignored by bcrypt. This effectively makes the password equal to the email address itself, since bcrypt never sees the random portion.

#### How Bcrypt Processes Our Password

```javascript
// Password with short email (20 bytes)
Input:     "user@example.com" + "a3f9b7d1e84c6f2a5c3d7e98f0a123bc"
           [----------------] [------------------------------]
           20 bytes email     32 bytes random hex
Total:     52 bytes
Bcrypt:    Hashes all 52 bytes (random portion IS used)

// Password with 72-byte email (attack scenario)
Input:     "cs...[70 dots]...2@gmail.com" + "a3f9b7d1e84c6f2a5c3d7e98f0a123bc"
           [---------------------------] [------------------------------]
           72 bytes email                32 bytes random hex
Total:     104 bytes
Bcrypt:    Hashes only first 72 bytes (random portion IGNORED!)
```

In the attack scenario, bcrypt only sees the email portion. The 32 random characters are silently truncated, making the password predictable and equal to the email address.

### Vulnerability #3: Inconsistent Email Processing

The critical vulnerability lies in how the application processes emails differently at different stages:

```javascript
// Stage 1: Length validation
const nEmail = normalizeEmail(req.body.email)  // ← Uses normalized email
if (nEmail.length > 64) {
    // Reject if too long
}

// Stage 2: Password generation
const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')  // ← Uses raw email!
```

**The Vulnerability:** Length validation checks the normalized email, but password generation uses the raw email from the request body. This inconsistency creates a bypass opportunity.

#### Why This Matters

If we can craft an email that:
1. Normalizes to ≤64 characters (passes validation)
2. Is exactly 72 bytes in raw form (triggers bcrypt truncation)

Then we can bypass both the length check AND make the password predictable!

### Vulnerability #4: Email Normalization Behavior

The `normalize-email` library removes dots and plus signs from Gmail addresses as part of its normalization process. This is intended to prevent users from creating multiple accounts with variations of the same email.

#### Normalization Examples

```javascript
// Dot removal
Input:  "user.name@gmail.com"
Output: "username@gmail.com"

// Multiple dots
Input:  "u.s.e.r@gmail.com"
Output: "user@gmail.com"

// Plus addressing removal
Input:  "user+tag123@gmail.com"
Output: "user@gmail.com"

// Combined
Input:  "u.s.e.r+testing@gmail.com"
Output: "user@gmail.com"
```

**Attack Opportunity:** We can use dots to artificially inflate the raw email length while keeping the normalized version short. For example, an email with 100 dots will normalize to a much shorter string, but the raw input remains long.

---

## Exploitation Strategy

Now that we understand all the vulnerabilities, let's develop our attack strategy. We need to create an email that satisfies these precise constraints:

### Attack Requirements

**→** Raw email must be exactly 72 bytes

**→** Normalized email must be ≤64 characters

**→** Must be a valid email format

**→** Must work with Gmail normalization rules

### Constructing the Payload

The key insight is to use dots in a Gmail address. Let's work through the math:

```javascript
// Base Gmail address
"cs2@gmail.com"  // 14 bytes when normalized

// We need 72 bytes total in raw form
// Domain portion: "@gmail.com" = 10 bytes
// Remaining space: 72 - 10 = 62 bytes for local part

// We already have "cs" and "2" = 3 characters
// Need: 62 - 3 = 59 more characters (use dots)

// Final payload structure:
"cs" + [59 dots] + "2@gmail.com"
```

#### Payload Verification

```c
Raw Email:
cs.....................................................................................................................................................2@gmail.com
(72 bytes total)

Normalized Email:
cs2@gmail.com
(13 bytes - well under 64 limit!)

Password Construction:
initialPassword = "cs...[59 dots]...2@gmail.com" + "a3f9b7d1e84c6f2a5c3d7e98f0a123bc"
                  [-----------------------------]   [------------------------------]
                  72 bytes (all bcrypt sees)        32 bytes (ignored by bcrypt)

Effective Password:
cs.....................................................................................................................................................2@gmail.com
(Just the email - random portion never hashed!)
```

---

## Step-by-Step Exploitation

### Step 1: Crafting the Malicious Email

First, let's create our precisely crafted email address with exactly 72 bytes:

```c
cs.....................................................................................................................................................2@gmail.com
```

**Important:** Count carefully! The email must be exactly 72 bytes. Too few and the random portion will be partially included; too many and the validation check might fail depending on how dots are counted.

### Step 2: Registration

Navigate to the registration page and enter the crafted email in the registration form. When submitting:

1. The application receives the raw 72-byte email
2. It normalizes the email to `cs2@gmail.com` (13 bytes)
3. The length check passes (13 ≤ 64)
4. Password is generated: 72-byte email + 32 hex chars = 104 bytes
5. Bcrypt hashes only first 72 bytes (just the email)
6. Database stores the normalized email with the truncated hash

**Registration Success:** The application accepts our registration and displays a message about sending an email with temporary password. Of course, no email is actually sent since that feature isn't implemented.

### Step 3: Authentication Bypass

Now comes the moment of truth. Navigate to the login page and enter:

```c
Email:    cs.....................................................................................................................................................2@gmail.com
Password: cs.....................................................................................................................................................2@gmail.com
```

Here's what happens during authentication:

1. Application normalizes login email to `cs2@gmail.com`
2. Retrieves stored password hash from database
3. Uses bcrypt to compare entered password with stored hash
4. Bcrypt truncates our 72-byte password input at 72 bytes (which is the full email)
5. This matches the hash stored during registration (which was also just the 72-byte email)
6. Authentication succeeds!

#### Authentication Flow

**→** User enters 72-byte email as password

**→** Bcrypt truncates at 72 bytes (entire email, no random data)

**→** Compares with stored hash (also just the 72-byte email)

**→** Match! User authenticated successfully

### Step 4: Access Granted

Upon successful authentication, the application creates a session and redirects to the dashboard. We've successfully bypassed the authentication system with predictable credentials!

**Attack Success:** We can now access the authenticated area of the application using credentials we controlled from the beginning. The "random" password was completely ineffective due to bcrypt truncation.

---

## Impact Assessment

This vulnerability chain has severe security implications for any production system:

### Immediate Threats

- **Complete Authentication Bypass:** Attackers can register and immediately access accounts without needing the temporary password
- **No Dependency on Email Delivery:** The attack works regardless of whether email functionality is implemented
- **Predictable Credentials:** Anyone who registers using this technique knows their own password
- **Session Hijacking Potential:** Once authenticated, attackers have full session access

### Attack Scalability

**Mass Registration Risk:** An attacker could register thousands of accounts using variations of this technique, all with predictable passwords. Rate limiting on the registration endpoint provides limited protection since each registration is "legitimate" from the application's perspective.

### Real-World Scenarios

1. **Data Theft:** Attacker creates accounts to access sensitive information or services
2. **Platform Abuse:** Automated bot accounts for spam, scraping, or manipulation
3. **Resource Exhaustion:** Creating numerous accounts to exhaust system resources
4. **Reputation Damage:** Public disclosure of such a vulnerability seriously damages trust

---

## Root Cause Analysis

Let's examine the fundamental design flaws that enabled this vulnerability:

### 1. Inconsistent Data Processing

The most critical error was applying different transformations to the same input at different stages:

```javascript
// Validation stage
const nEmail = normalizeEmail(req.body.email)  // Transformed
if (nEmail.length > 64) { ... }

// Password generation stage
const initialPassword = req.body.email + ...   // Raw, untransformed
```

**Principle Violated:** When applying security controls, always use the same version of data throughout the process. If you validate normalized data, generate cryptographic material from normalized data too.

### 2. Misunderstanding Cryptographic Primitives

The developers didn't account for bcrypt's 72-byte truncation behavior when designing the password generation logic. This is a well-documented characteristic that should influence implementation decisions.

### 3. User-Controlled Secret Components

Including user input (email address) in generated passwords is fundamentally problematic:

```javascript
// Bad: User controls part of the "random" password
const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')

// Good: Password is entirely random
const initialPassword = crypto.randomBytes(32).toString('hex')
```

### 4. Incomplete Feature Implementation

The commented-out email functionality (`// TODO: Send email with initial password`) was a red flag that this registration flow wasn't production-ready. The security model depended on users not knowing their temporary password, but without email delivery, this assumption was already broken.

---

## Remediation

Here's how to properly fix these vulnerabilities and prevent similar issues in the future.

### Fix #1: Consistent Email Processing

Always normalize email addresses immediately upon receipt and use the normalized version everywhere:

```javascript
app.post('/user', limiter, (req, res, next) => {
    if (!req.body) return res.redirect('/login')

    // Normalize once, use everywhere
    const email = normalizeEmail(req.body.email)

    // Validate BOTH normalized and raw lengths
    if (email.length > 64 || req.body.email.length > 72) {
        req.session.error = 'Your email address is too long'
        return res.redirect('/login')
    }

    // Use normalized email for password generation
    const initialPassword = email + crypto.randomBytes(16).toString('hex')
    
    // Rest of implementation...
})
```

### Fix #2: Remove User Input from Password Generation

Generate completely random passwords without any user-controlled components:

```javascript
// Generate 32 random bytes = 64 hex characters
// Well within bcrypt's 72-byte limit with safety margin
const initialPassword = crypto.randomBytes(32).toString('hex')
```

### Fix #3: Validate Before Bcrypt

Add an explicit check to prevent passwords from exceeding bcrypt's limit:

```javascript
const initialPassword = crypto.randomBytes(32).toString('hex')

// Verify we're within bcrypt's limits
if (Buffer.byteLength(initialPassword, 'utf8') > 72) {
    throw new Error('Generated password exceeds bcrypt maximum length')
}

bcrypt.hash(initialPassword, 10, function (err, hash) {
    // ... rest of implementation
})
```

### Fix #4: Implement Proper Password Delivery

Complete the email functionality or implement a more secure registration flow:

```javascript
// Option 1: Send password via email
const transporter = nodemailer.createTransport(config)
await transporter.sendMail({
    to: email,
    subject: 'Your temporary password',
    text: `Your temporary password is: ${initialPassword}`
})

// Option 2: Use password reset flow instead
// Generate a one-time token, email it to user
// Let user set their own password via secure link
```

### Fix #5: Add Comprehensive Input Validation

```javascript
const emailValidator = require('email-validator')

// Validate email format
if (!emailValidator.validate(req.body.email)) {
    req.session.error = 'Invalid email format'
    return res.redirect('/login')
}

// Validate both raw and normalized lengths
const rawEmail = req.body.email
const normalizedEmail = normalizeEmail(rawEmail)

if (rawEmail.length > 255 || normalizedEmail.length > 64) {
    req.session.error = 'Email address is too long'
    return res.redirect('/login')
}
```

---

## Lessons Learned

### For Developers

- **Understand your crypto primitives:** Know the limitations and behaviors of libraries like bcrypt, including input truncation
- **Process data consistently:** Apply the same transformations throughout your code when making security decisions
- **Never trust user input in secrets:** Generated passwords should be purely random without user-controlled components
- **Validate comprehensively:** Check constraints on data in both raw and processed forms
- **Complete features before deployment:** Partially implemented security features (like email delivery) often hide vulnerabilities

### For Security Reviewers

- **Look for data transformation inconsistencies:** Pay attention to where and how input is processed
- **Review crypto implementation details:** Don't assume developers understand cryptographic primitives' edge cases
- **Check for user-controlled components:** Secrets should never include user input
- **Test boundary conditions:** Exploit edge cases like maximum input lengths
- **Verify defense in depth:** Single points of failure in security controls are warning signs

---

## Conclusion

This vulnerability demonstrates a crucial principle in application security: vulnerabilities often emerge from the subtle interactions between multiple components rather than obvious coding errors. Each individual piece—bcrypt hashing, email normalization, random password generation—was implemented using industry-standard libraries and best practices. Yet their combination created a critical authentication bypass.

The key takeaway is the importance of understanding not just what your security tools do, but how they behave at their boundaries and how they interact with other components. Bcrypt's 72-byte truncation is well-documented, but it becomes a vulnerability only when combined with user-controlled input in password generation and inconsistent input processing.