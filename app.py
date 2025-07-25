import os
import logging
import subprocess
import tempfile
import sys
from flask import Flask, render_template, request, jsonify

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Simple challenge data
CHALLENGES = {
    "caesar_cipher": {
        "title": "Caesar Cipher",
        "difficulty": "Easy",
        "marks": "25 Marks",
        "description": "A simple substitution cipher that shifts letters by a fixed number of positions.",
        "starter_code": '''def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

# Test your code
text = input("Enter text: ")
shift = int(input("Enter shift: "))
print(caesar_cipher(text, shift))'''
    },
    "reverse_string": {
        "title": "Reverse String",
        "difficulty": "Easy", 
        "marks": "15 Marks",
        "description": "Write a function to reverse a given string.",
        "starter_code": '''def reverse_string(text):
    # Write your code here
    pass

# Test your code
text = input("Enter text: ")
print(reverse_string(text))'''
    },
    "fibonacci": {
        "title": "Fibonacci Sequence",
        "difficulty": "Medium",
        "marks": "35 Marks", 
        "description": "Generate the first n numbers in the Fibonacci sequence.",
        "starter_code": '''def fibonacci(n):
    # Write your code here
    pass

# Test your code
n = int(input("Enter number: "))
print(fibonacci(n))'''
    }
}

@app.route('/')
def dashboard():
    return render_template('dashboard.html', challenges=CHALLENGES)

@app.route('/challenge/<challenge_id>')
def challenge(challenge_id):
    if challenge_id not in CHALLENGES:
        return "Challenge not found", 404
    
    challenge_data = CHALLENGES[challenge_id]
    return render_template('challenge.html', 
                         challenge=challenge_data,
                         challenge_id=challenge_id)

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code', '')
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_filename = f.name
        
        # Run the code
        result = subprocess.run(
            [sys.executable, temp_filename],
            capture_output=True,
            text=True,
            timeout=10,
            input=""
        )
        
        # Clean up
        os.unlink(temp_filename)
        
        if result.returncode == 0:
            return jsonify({
                'success': True,
                'output': result.stdout,
                'error': result.stderr
            })
        else:
            return jsonify({
                'success': False,
                'output': result.stdout,
                'error': result.stderr
            })
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'output': '',
            'error': 'Code execution timed out (10 seconds limit)'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'output': '',
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)