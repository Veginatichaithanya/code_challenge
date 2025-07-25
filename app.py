import os
import logging
import subprocess
import tempfile
import sys
import traceback
import json
from flask import Flask, render_template, request, jsonify

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Caesar Cipher problem data
PROBLEM_DATA = {
    "title": "Caesar Cipher",
    "difficulty": "Easy",
    "marks": "25 Marks",
    "description": """In cryptography, a Caesar cipher is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet. The method is named after Julius Caesar, who used it in his private correspondence.""",
    "how_it_works": [
        "Choose a shift value (key) between 1-25",
        "For each letter in the plaintext, shift it forward in the alphabet by the key value",
        "Wrap around to the beginning of the alphabet if necessary",
        "Leave non-alphabetic characters unchanged",
        "Return the resulting ciphertext"
    ],
    "examples": [
        {
            "input": "Plaintext: HELLO, Shift: 3",
            "output": "Ciphertext: KHOOR"
        },
        {
            "input": "Plaintext: hello world, Shift: 7",
            "output": "Ciphertext: olssv dvysk"
        }
    ],
    "starter_code": '''def caesar_cipher(text, shift):
    result = ""
    
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    
    return result

# Example usage
plain_text = input("Enter the text: ")
shift_value = int(input("Enter the shift value: "))

cipher_text = caesar_cipher(plain_text, shift_value)
print("Cipher Text:", cipher_text)'''
}

@app.route('/')
def index():
    """Render the main page with the code editor."""
    return render_template('index.html', problem=PROBLEM_DATA)

@app.route('/execute', methods=['POST'])
def execute_code():
    """Execute Python code and return results or errors."""
    try:
        data = request.get_json()
        code = data.get('code', '')
        test_input = data.get('input', '')
        
        if not code.strip():
            return jsonify({
                'success': False,
                'error': 'No code provided',
                'line_number': None
            })
        
        # Create temporary file for code execution
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
            temp_file.write(code)
            temp_file_path = temp_file.name
        
        try:
            # Execute the code with input
            process = subprocess.Popen(
                [sys.executable, temp_file_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10  # 10 second timeout
            )
            
            stdout, stderr = process.communicate(input=test_input)
            
            if process.returncode == 0:
                # Successful execution
                return jsonify({
                    'success': True,
                    'output': stdout.strip(),
                    'error': None,
                    'line_number': None
                })
            else:
                # Runtime error
                error_message = stderr.strip()
                line_number = extract_line_number(error_message)
                
                return jsonify({
                    'success': False,
                    'output': '',
                    'error': error_message,
                    'line_number': line_number
                })
        
        except subprocess.TimeoutExpired:
            return jsonify({
                'success': False,
                'output': '',
                'error': 'Code execution timed out (10 seconds limit)',
                'line_number': None
            })
        
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass
    
    except Exception as e:
        logging.error(f"Error executing code: {str(e)}")
        return jsonify({
            'success': False,
            'output': '',
            'error': f'Server error: {str(e)}',
            'line_number': None
        })

def extract_line_number(error_message):
    """Extract line number from Python error message."""
    try:
        lines = error_message.split('\n')
        for line in lines:
            if 'line' in line.lower() and 'tmp' in line:
                # Look for patterns like "line 5" or "line 10"
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.lower() == 'line' and i + 1 < len(parts):
                        try:
                            return int(parts[i + 1].rstrip(','))
                        except ValueError:
                            continue
    except Exception:
        pass
    return None

@app.route('/test_cases')
def get_test_cases():
    """Get predefined test cases for Caesar Cipher."""
    test_cases = [
        {
            'name': 'Basic Test 1',
            'input': 'HELLO\n3',
            'expected_output': 'Cipher Text: KHOOR'
        },
        {
            'name': 'Basic Test 2',
            'input': 'hello world\n7',
            'expected_output': 'Cipher Text: olssv dvysk'
        },
        {
            'name': 'Mixed Case Test',
            'input': 'Hello World\n13',
            'expected_output': 'Cipher Text: Uryyb Jbeyq'
        },
        {
            'name': 'Special Characters Test',
            'input': 'Hello, World!\n5',
            'expected_output': 'Cipher Text: Mjqqt, Btwqi!'
        }
    ]
    return jsonify(test_cases)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
