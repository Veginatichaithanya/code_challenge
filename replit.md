# Python Code Editor - Caesar Cipher Challenge

## Overview

This is a web-based Python coding challenge platform focused on the Caesar Cipher problem. The application provides an interactive coding environment where users can write, test, and validate their Python solutions for cryptographic algorithms. The platform features a split-screen interface with problem descriptions on the left and a code editor on the right.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: Pure HTML/CSS/JavaScript with Bootstrap 5 for responsive design
- **Code Editor**: CodeMirror 5.65.2 with Python syntax highlighting and material-darker theme
- **UI Components**: Bootstrap components for navigation, panels, and form elements
- **Styling**: Custom CSS with Font Awesome icons for enhanced user experience

### Backend Architecture
- **Framework**: Flask (Python web framework)
- **Structure**: Simple monolithic architecture with separation of concerns
- **Routing**: Single-page application with API endpoints for code execution
- **Session Management**: Flask's built-in session handling with configurable secret key

### Application Structure
```
├── app.py              # Main Flask application with routes and logic
├── main.py             # Application entry point
├── templates/
│   └── index.html      # Main UI template
└── static/
    ├── css/style.css   # Custom styling
    └── js/editor.js    # Frontend JavaScript logic
```

## Key Components

### 1. Problem Management System
- **Problem Data Structure**: Centralized problem definitions in Python dictionaries
- **Content Delivery**: Server-side rendering of problem descriptions, examples, and starter code
- **Extensibility**: Designed to easily add new coding challenges

### 2. Code Editor Interface
- **Real-time Editing**: CodeMirror integration with Python syntax highlighting
- **Code Execution**: Frontend JavaScript manages code submission to backend
- **User Experience**: Features like auto-completion, bracket matching, and fullscreen mode

### 3. Code Execution Engine
- **Security**: Isolated code execution using Python's subprocess module
- **Validation**: Built-in test case system for automatic solution verification
- **Error Handling**: Comprehensive error reporting and logging

### 4. User Interface Components
- **Split Panel Layout**: Problem description and code editor in responsive columns
- **Navigation Bar**: Challenge metadata display with action buttons
- **Tabbed Interface**: Organized content presentation (problem description, examples, etc.)

## Data Flow

1. **Initial Load**: Flask serves the main template with problem data
2. **Code Editing**: User interactions handled by CodeMirror in the browser
3. **Code Execution**: JavaScript sends code to Flask backend via AJAX
4. **Processing**: Backend executes code in isolated environment
5. **Results**: JSON response with execution results returned to frontend
6. **Display**: Frontend updates UI with test results and feedback

## External Dependencies

### Frontend Libraries
- **Bootstrap 5.3.0**: UI framework for responsive design
- **CodeMirror 5.65.2**: Code editor with syntax highlighting
- **Font Awesome 6.4.0**: Icon library for enhanced UI

### Backend Dependencies
- **Flask**: Web framework for Python
- **Standard Library**: Uses built-in modules (os, logging, subprocess, tempfile, json)

### Runtime Requirements
- **Python 3.x**: Backend runtime environment
- **Modern Web Browser**: Frontend compatibility

## Deployment Strategy

### Development Environment
- **Local Development**: Flask development server with debug mode enabled
- **Hot Reload**: Automatic restart on code changes during development
- **Port Configuration**: Runs on port 5000 with host binding to 0.0.0.0

### Production Considerations
- **Secret Key**: Environment variable configuration for session security
- **Logging**: Configurable logging levels for debugging and monitoring
- **Static Assets**: CDN delivery for external libraries (Bootstrap, CodeMirror, Font Awesome)

### Security Features
- **Code Isolation**: Subprocess execution prevents direct system access
- **Session Management**: Secure session handling with configurable secrets
- **Input Validation**: Built-in protection against code injection

### Scalability Design
- **Stateless Architecture**: Each request is independent, enabling horizontal scaling
- **Minimal Dependencies**: Lightweight stack for easy deployment
- **Modular Structure**: Problem definitions can be easily extended or modified

The application is designed as a proof-of-concept for an educational coding platform, with a focus on simplicity and extensibility. The architecture supports easy addition of new problems and can be extended with features like user authentication, progress tracking, and multiple programming languages.