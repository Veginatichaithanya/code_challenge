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

# Problem data for different challenges
PROBLEMS_DATA = {
    "caesar_cipher": {
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
print("Cipher Text:", cipher_text)''',
        "test_cases": [
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
    },
    "monoalphabetic_cipher": {
        "title": "Basic Monoalphabetic Cipher",
        "difficulty": "Easy",
        "marks": "30 Marks",
        "description": """A monoalphabetic substitution cipher uses a fixed substitution over the entire message. Each letter of the plaintext is replaced with another letter of the alphabet, so that the letter 'A' always becomes the same letter throughout the whole encryption process.""",
        "how_it_works": [
            "Create a substitution key where each letter of the alphabet maps to another unique letter",
            "For each character in the plaintext, find its corresponding value in the mapping",
            "Replace the character with its mapped value",
            "Leave non-alphabetic characters unchanged",
            "Return the resulting ciphertext"
        ],
        "examples": [
            {
                "input": "Plaintext: HELLO, Key: {'H':'X', 'E':'Y', 'L':'Z', 'O':'W'}",
                "output": "Ciphertext: XYZW"
            }
        ],
        "starter_code": '''def monoalphabetic_cipher(plaintext, key_mapping):
    result = ""
    
    for char in plaintext:
        # Convert to lowercase for consistency
        char_lower = char.lower()
        
        # Apply mapping if character is in the key
        if char_lower in key_mapping:
            # Preserve original case
            if char.isupper():
                result += key_mapping[char_lower].upper()
            else:
                result += key_mapping[char_lower]
        else:
            # Keep characters not in the mapping unchanged
            result += char
    
    return result

# Test with a sample mapping
mapping = {'a': 'q', 'b': 'w', 'c': 'e', 'r': 't', 'd': 'y', 'e': 'u'}
text = input("Enter text to encrypt: ")
encrypted = monoalphabetic_cipher(text, mapping)
print("Encrypted:", encrypted)''',
        "test_cases": [
            {
                'name': 'Basic Mapping Test',
                'input': 'hello\n',
                'expected_output': 'Encrypted: huzzy'
            },
            {
                'name': 'Mixed Case Test',
                'input': 'Hello World\n',
                'expected_output': 'Encrypted: Huzzy Wytzy'
            }
        ]
    },
    "mac": {
        "title": "Message Authentication Code (MAC)",
        "difficulty": "Medium",
        "marks": "40 Marks",
        "description": """A Message Authentication Code (MAC) is a security mechanism used to verify both the integrity and authenticity of a message. It's a small piece of information (tag) that allows the receiver to verify that a message came from the expected sender and hasn't been altered.""",
        "how_it_works": [
            "Generate a MAC tag by applying a hash function to a combination of the message and a secret key",
            "The sender transmits both the message and the MAC tag",
            "The receiver recalculates the MAC using the same message and key",
            "If the calculated MAC matches the received MAC, the message is authentic and unaltered"
        ],
        "examples": [
            {
                "input": "Message: 'Transfer $1000', Key: 'secret'",
                "output": "MAC: '6dfde3a1b9c7d2f'"
            }
        ],
        "starter_code": '''import hashlib
import hmac
import os

def generate_mac(message, key):
    """Generate a Message Authentication Code (MAC) using HMAC-SHA256"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Create the HMAC
    mac = hmac.new(key, message, hashlib.sha256)
    return mac.hexdigest()

def verify_mac(message, key, received_mac):
    """Verify a received MAC against a newly generated one"""
    calculated_mac = generate_mac(message, key)
    # Use a constant-time comparison to prevent timing attacks
    return hmac.compare_digest(calculated_mac, received_mac)

# Example usage
secret_key = os.urandom(16)  # Generate a random key
message = "Transfer $1000 to Account #12345"

# Generate the MAC
mac = generate_mac(message, secret_key)
print("Message:", message)
print("MAC:", mac)

# Verify the MAC (should be True)
is_valid = verify_mac(message, secret_key, mac)
print("MAC is valid:", is_valid)

# Try with a tampered message
tampered_message = "Transfer $9999 to Account #12345"
is_valid = verify_mac(tampered_message, secret_key, mac)
print("Tampered message MAC is valid:", is_valid)''',
        "test_cases": [
            {
                'name': 'Basic MAC Generation',
                'input': 'Test Message\nsecret123\n',
                'expected_output': 'MAC is valid: True'
            },
            {
                'name': 'MAC Verification',
                'input': 'Hello World\nmykey\n',
                'expected_output': 'MAC is valid: True'
            }
        ]
    }
}

# Current challenge tracker
current_challenge = "caesar_cipher"

@app.route('/')
def index():
    """Render the main page with the code editor."""
    global current_challenge
    return render_template('index.html', problem=PROBLEMS_DATA[current_challenge])

@app.route('/next_challenge')
def next_challenge():
    """Switch to the next challenge."""
    global current_challenge
    
    challenge_order = ["caesar_cipher", "monoalphabetic_cipher", "mac"]
    current_index = challenge_order.index(current_challenge)
    next_index = (current_index + 1) % len(challenge_order)
    current_challenge = challenge_order[next_index]
    
    return jsonify({
        'success': True,
        'challenge': current_challenge,
        'problem': PROBLEMS_DATA[current_challenge]
    })

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
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(input=test_input, timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                raise subprocess.TimeoutExpired([sys.executable, temp_file_path], 10)
            
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
    """Get predefined test cases for current challenge."""
    global current_challenge
    return jsonify(PROBLEMS_DATA[current_challenge]['test_cases'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
