# Simple Coding Platform

## Overview
A simplified Flask-based coding platform with basic programming challenges. The platform focuses on simplicity and ease of use, providing a clean interface for learning fundamental programming concepts.

## Recent Changes
- **2025-07-25**: Completely simplified the application from complex cybersecurity platform to basic coding challenges
- **User Preference**: User requested a much simpler interface, removing complex features
- **Architecture**: Reduced from 14 complex cybersecurity challenges to 3 simple programming challenges
- **UI**: Clean, minimal design with gradient background and simple card layout

## User Preferences
- **Simplicity**: User prefers simple, clean interfaces over complex feature-rich platforms
- **Minimal Design**: Focus on essential functionality without overwhelming features

## Project Architecture

### Current Structure
```
├── app.py                 # Simple Flask app with 3 basic challenges
├── main.py               # Entry point
├── templates/
│   ├── dashboard.html    # Simple challenge grid
│   └── challenge.html    # Clean coding interface
└── static/              # (minimal styling via CDN)
```

### Core Features
1. **Dashboard**: Simple grid layout with 3 coding challenges
2. **Challenge Interface**: Clean code editor with output panel
3. **Code Execution**: Basic Python code runner with timeout protection
4. **Responsive Design**: Mobile-friendly Bootstrap layout

### Challenges Included
1. **Caesar Cipher** (Easy, 25 marks) - Basic encryption
2. **Reverse String** (Easy, 15 marks) - String manipulation
3. **Fibonacci Sequence** (Medium, 35 marks) - Algorithm practice

### Technical Stack
- **Backend**: Flask (minimal setup)
- **Frontend**: Bootstrap 5 + CodeMirror
- **Code Editor**: CodeMirror with Python syntax highlighting
- **Styling**: Gradient backgrounds, card-based layout
- **No Database**: In-memory challenge data

### Key Simplifications Made
- Removed complex cybersecurity challenges
- Eliminated database dependencies
- Simplified from 14 challenges to 3 basic ones
- Removed complex UI tabs and navigation
- Streamlined code execution without advanced features
- Clean, minimal design aesthetic

## Runtime
- **Development**: Flask dev server on port 5000
- **Production**: Gunicorn WSGI server
- **Dependencies**: Flask, minimal requirements