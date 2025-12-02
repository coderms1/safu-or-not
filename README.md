# SAFU or NOT 🔍

A simple, fast, and clean tool that checks whether a URL is safe or suspicious.

This project was built using:

- 1. **A FastAPI backend** python configs w/ Docker container, hosted on Render
- 2. **A WordPress frontend** hosted on Bluehost with custom HTML, CSS, and JavaScript

---

## 🚀 Project Overview

***The goal of **SAFU or NOT** is to provide a no-nonsense, easy drop-in tool for checking the safety of URLs.  
Paste a link → press a button → get a result.  
That’s it.***

*Nothing fancy.  
Just a clean interface, one API endpoint, and fast responses.*

---

### FastAPI – Render Deployment

## _🌐 The website is a single custom page running inside WordPress_
- Custom HTML for structure
- Custom CSS for a neon/matrix vibe
- Custom JS (API call)

### What the user sees:
-text-prompt field
-big “CHECK SAFETY” button
-result box
-disclaimer anchored at the bottom

### Requests sent to:
-https://safu-or-not.onrender.com/check
-w/ fetch() POST call.

### 🛠️ Technologies Used

- Python 3
- FastAPI
- Uvicorn
- Pydantic
- Google Safe Browsing API
- Render (free tier hosting)
- WordPress on Bluehost
- Custom HTML / CSS / JavaScript
- Code Snippets plugin for JS execution
- Minimal block-based page template

**~ 🌙 MS1**
