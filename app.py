import os
import logging
import subprocess
import tempfile
import sys
import traceback
import json
from flask import Flask, render_template, request, jsonify, redirect

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
        "description": """In cryptography, a Caesar cipher is one of the simplest and most widely known encryption techniques. It is a type of substitution cipher in which each letter in the plaintext is replaced by a letter some fixed number of positions down the alphabet.""",
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
                'input': 'HELLO\\n3',
                'expected_output': 'Cipher Text: KHOOR'
            },
            {
                'name': 'Basic Test 2',
                'input': 'hello world\\n7',
                'expected_output': 'Cipher Text: olssv dvysk'
            }
        ]
    },
    "monoalphabetic_cipher": {
        "title": "Basic Monoalphabetic Cipher",
        "difficulty": "Easy",
        "marks": "30 Marks",
        "description": """A monoalphabetic substitution cipher uses a fixed substitution over the entire message. Each letter of the plaintext is replaced with another letter of the alphabet.""",
        "how_it_works": [
            "Create a substitution key where each letter maps to another unique letter",
            "For each character in the plaintext, find its corresponding value in the mapping",
            "Replace the character with its mapped value",
            "Leave non-alphabetic characters unchanged"
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
        char_lower = char.lower()
        
        if char_lower in key_mapping:
            if char.isupper():
                result += key_mapping[char_lower].upper()
            else:
                result += key_mapping[char_lower]
        else:
            result += char
    
    return result

# Test with a sample mapping
mapping = {'h': 'x', 'e': 'y', 'l': 'z', 'o': 'w'}
text = input("Enter text to encrypt: ")
encrypted = monoalphabetic_cipher(text, mapping)
print("Encrypted:", encrypted)''',
        "test_cases": [
            {
                'name': 'Basic Mapping Test',
                'input': 'hello\\n',
                'expected_output': 'Encrypted: xyzz'
            }
        ]
    },
    "mac": {
        "title": "Message Authentication Code (MAC)",
        "difficulty": "Medium",
        "marks": "40 Marks",
        "description": """A Message Authentication Code (MAC) is a security mechanism used to verify both the integrity and authenticity of a message.""",
        "how_it_works": [
            "Generate a MAC tag by applying a hash function to a combination of the message and a secret key",
            "The sender transmits both the message and the MAC tag",
            "The receiver recalculates the MAC using the same message and key",
            "If the calculated MAC matches the received MAC, the message is authentic"
        ],
        "examples": [
            {
                "input": "Message: 'Transfer $1000', Key: 'secret'",
                "output": "MAC: '6dfde3a1b9c7d2f'"
            }
        ],
        "starter_code": '''import hashlib
import hmac

def generate_mac(message, key):
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    mac = hmac.new(key, message, hashlib.sha256)
    return mac.hexdigest()

def verify_mac(message, key, received_mac):
    calculated_mac = generate_mac(message, key)
    return hmac.compare_digest(calculated_mac, received_mac)

# Example usage
message = input("Enter message: ")
key = input("Enter key: ")

mac = generate_mac(message, key)
is_valid = verify_mac(message, key, mac)
print("MAC is valid:", is_valid)''',
        "test_cases": [
            {
                'name': 'Basic MAC Generation',
                'input': 'Hello World\\nmykey\\n',
                'expected_output': 'MAC is valid: True'
            }
        ]
    },
    "diffie_hellman": {
        "title": "Secure Key Exchange (Diffie-Hellman)",
        "difficulty": "Hard",
        "marks": "55 Marks",
        "description": """The Diffie-Hellman key exchange is a method for securely exchanging cryptographic keys over a public channel. It allows two parties to establish a shared secret key without having to directly communicate the key itself.""",
        "how_it_works": [
            "Both parties agree on a large prime number and a base (generator)",
            "Each party generates a private key and computes a public key",
            "They exchange public keys over the insecure channel",
            "Each party combines their private key with the other's public key to compute the shared secret"
        ],
        "examples": [
            {
                "input": "Prime: 23, Base: 5, Alice Private: 6, Bob Private: 15",
                "output": "Shared Secret: 2"
            }
        ],
        "starter_code": '''def power_mod(base, exponent, modulus):
    """Efficient modular exponentiation"""
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def diffie_hellman_key_exchange(prime, base, private_key_a, private_key_b):
    """Simulate Diffie-Hellman key exchange"""
    # Generate public keys
    public_key_a = power_mod(base, private_key_a, prime)
    public_key_b = power_mod(base, private_key_b, prime)
    
    # Generate shared secrets
    shared_secret_a = power_mod(public_key_b, private_key_a, prime)
    shared_secret_b = power_mod(public_key_a, private_key_b, prime)
    
    return public_key_a, public_key_b, shared_secret_a, shared_secret_b

# Example usage
prime = int(input("Enter prime number: "))
base = int(input("Enter base (generator): "))
private_a = int(input("Enter Alice's private key: "))
private_b = int(input("Enter Bob's private key: "))

pub_a, pub_b, secret_a, secret_b = diffie_hellman_key_exchange(prime, base, private_a, private_b)

print(f"Alice's public key: {pub_a}")
print(f"Bob's public key: {pub_b}")
print(f"Shared secret: {secret_a}")
print(f"Keys match: {secret_a == secret_b}")''',
        "test_cases": [
            {
                'name': 'Basic Key Exchange',
                'input': '23\\n5\\n6\\n15\\n',
                'expected_output': 'Shared secret: 2'
            }
        ]
    },
    "digital_signature": {
        "title": "Digital Signature Generation and Verification",
        "difficulty": "Hard",
        "marks": "65 Marks",
        "description": """Digital signatures provide cryptographic authentication of digital messages. They use public key cryptography to ensure message integrity, authenticity, and non-repudiation.""",
        "how_it_works": [
            "Generate a key pair (private key for signing, public key for verification)",
            "Create a hash of the message to be signed",
            "Encrypt the hash with the private key to create the signature",
            "Verify by decrypting the signature with the public key and comparing hashes"
        ],
        "examples": [
            {
                "input": "Message: 'Important document', Private key used for signing",
                "output": "Signature verified: True"
            }
        ],
        "starter_code": '''import hashlib

def simple_hash_signature(message, private_key):
    """Create a simple signature using hash and private key"""
    message_hash = hashlib.sha256(message.encode()).hexdigest()
    # Simple signature: combine hash with private key
    signature = str(hash(message_hash + str(private_key)))
    return signature

def verify_signature(message, signature, private_key):
    """Verify signature by recreating it"""
    expected_signature = simple_hash_signature(message, private_key)
    return signature == expected_signature

# Example usage
message = input("Enter message to sign: ")
private_key = 12345  # Simple private key for demo

signature = simple_hash_signature(message, private_key)
is_valid = verify_signature(message, signature, private_key)

print(f"Message: {message}")
print(f"Signature: {signature}")
print(f"Signature verified: {is_valid}")''',
        "test_cases": [
            {
                'name': 'Basic Signature Test',
                'input': 'Hello World\\n',
                'expected_output': 'Signature verified: True'
            }
        ]
    },
    "mobile_security": {
        "title": "Mobile Security Implementation",
        "difficulty": "Medium",
        "marks": "50 Marks",
        "description": """Mobile security involves implementing essential security features for mobile applications including secure storage, authentication, and communication protection.""",
        "how_it_works": [
            "Implement secure storage mechanisms for sensitive data",
            "Add authentication and authorization controls",
            "Encrypt data in transit and at rest",
            "Implement session management and token validation"
        ],
        "examples": [
            {
                "input": "User credentials, session tokens, encrypted data",
                "output": "Secure mobile app with proper authentication"
            }
        ],
        "starter_code": '''import hashlib
import base64

class MobileSecurityManager:
    def __init__(self):
        self.secret_key = "mobile_secret_key_2024"
    
    def hash_password(self, password):
        """Securely hash passwords"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password, hashed):
        """Verify password against hash"""
        return self.hash_password(password) == hashed
    
    def encrypt_data(self, data):
        """Simple encryption for demonstration"""
        encoded = base64.b64encode(data.encode()).decode()
        return encoded
    
    def decrypt_data(self, encrypted_data):
        """Decrypt encoded data"""
        try:
            return base64.b64decode(encrypted_data).decode()
        except:
            return None

# Example usage
security_manager = MobileSecurityManager()

username = input("Enter username: ")
password = input("Enter password: ")

# Hash password
hashed_password = security_manager.hash_password(password)
print("Password hashed successfully")

# Verify password
is_valid = security_manager.verify_password(password, hashed_password)
print(f"Password verification: {is_valid}")

if is_valid:
    # Encrypt sensitive data
    sensitive_data = "Credit card: 1234-5678-9012-3456"
    encrypted = security_manager.encrypt_data(sensitive_data)
    print(f"Data encrypted successfully")
    
    # Decrypt data
    decrypted = security_manager.decrypt_data(encrypted)
    print(f"Data decrypted: {decrypted}")''',
        "test_cases": [
            {
                'name': 'Security Features Test',
                'input': 'testuser\\npassword123\\n',
                'expected_output': 'Password verification: True'
            }
        ]
    },
    "intrusion_detection": {
        "title": "Intrusion Detection System with Snort",
        "difficulty": "Hard",
        "marks": "70 Marks",
        "description": """Implement a simplified IDS using Snort-like rules to detect malicious network activity and potential security threats.""",
        "how_it_works": [
            "Define rules for detecting suspicious network patterns",
            "Monitor network traffic for rule violations",
            "Generate alerts when threats are detected",
            "Log and analyze security events"
        ],
        "examples": [
            {
                "input": "Network packet with suspicious payload",
                "output": "ALERT: Potential intrusion detected"
            }
        ],
        "starter_code": '''import re
from datetime import datetime

class IntrusionDetectionSystem:
    def __init__(self):
        self.rules = [
            {'name': 'SQL Injection', 'pattern': r'(SELECT|INSERT|DELETE|DROP).*FROM', 'severity': 'HIGH'},
            {'name': 'XSS Attack', 'pattern': r'<script.*?>.*?</script>', 'severity': 'MEDIUM'},
            {'name': 'Port Scan', 'pattern': r'SCAN.*PORT.*\\d+', 'severity': 'LOW'},
            {'name': 'Brute Force', 'pattern': r'(FAILED.*LOGIN.*){3,}', 'severity': 'HIGH'}
        ]
        self.alerts = []
    
    def analyze_traffic(self, packet_data):
        """Analyze network packet for threats"""
        threats_found = []
        
        for rule in self.rules:
            if re.search(rule['pattern'], packet_data, re.IGNORECASE):
                alert = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'threat': rule['name'],
                    'severity': rule['severity'],
                    'data': packet_data[:50] + '...' if len(packet_data) > 50 else packet_data
                }
                threats_found.append(alert)
                self.alerts.append(alert)
        
        return threats_found
    
    def generate_report(self):
        """Generate security report"""
        if not self.alerts:
            return "No threats detected"
        
        report = f"Security Report - {len(self.alerts)} threats detected:\\n"
        for alert in self.alerts:
            report += f"[{alert['timestamp']}] {alert['severity']}: {alert['threat']}\\n"
        
        return report

# Example usage
ids = IntrusionDetectionSystem()

print("Intrusion Detection System Active")
packet = input("Enter network packet data to analyze: ")

threats = ids.analyze_traffic(packet)

if threats:
    print("THREATS DETECTED:")
    for threat in threats:
        print(f"- {threat['severity']}: {threat['threat']}")
else:
    print("No threats detected in packet")

print("\\n" + ids.generate_report())''',
        "test_cases": [
            {
                'name': 'SQL Injection Detection',
                'input': 'SELECT * FROM users WHERE id=1\\n',
                'expected_output': 'THREATS DETECTED:'
            }
        ]
    },
    "malware_trojans": {
        "title": "Defeating Malware – Building Trojans",
        "difficulty": "Hard",
        "marks": "75 Marks",
        "description": """Implement and analyze Trojan behavior in a safe simulation environment to understand malware characteristics and defense mechanisms.""",
        "how_it_works": [
            "Simulate trojan installation and hiding mechanisms",
            "Implement covert communication channels",
            "Analyze system vulnerabilities",
            "Create detection and removal strategies"
        ],
        "examples": [
            {
                "input": "System vulnerability analysis",
                "output": "Trojan behavior simulated safely"
            }
        ],
        "starter_code": '''import os
import hashlib
import time
from datetime import datetime

class TrojanSimulator:
    def __init__(self):
        self.hidden_files = []
        self.communication_log = []
        self.system_info = {}
    
    def simulate_installation(self):
        """Simulate trojan installation process"""
        print("Simulating trojan installation...")
        
        # Simulate creating hidden files
        hidden_file = f"system_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}.tmp"
        self.hidden_files.append(hidden_file)
        
        # Simulate gathering system info
        self.system_info = {
            'os': 'simulation_os',
            'user': 'test_user',
            'install_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return f"Installation complete. Hidden file: {hidden_file}"
    
    def simulate_communication(self, command):
        """Simulate covert communication"""
        response = f"Command '{command}' executed at {datetime.now().strftime('%H:%M:%S')}"
        self.communication_log.append({'command': command, 'response': response})
        return response
    
    def detect_trojan(self):
        """Simulate trojan detection methods"""
        detection_methods = [
            "File signature analysis",
            "Behavioral monitoring",
            "Network traffic analysis",
            "Registry monitoring"
        ]
        
        print("Running detection methods:")
        for method in detection_methods:
            print(f"- {method}: {'SUSPICIOUS' if self.hidden_files else 'CLEAN'}")
        
        return len(self.hidden_files) > 0
    
    def remove_trojan(self):
        """Simulate trojan removal"""
        removed_files = len(self.hidden_files)
        self.hidden_files.clear()
        self.communication_log.clear()
        return f"Removed {removed_files} suspicious files"

# Example usage - SIMULATION ONLY
print("=== TROJAN ANALYSIS SIMULATION ===")
print("This is for educational purposes only!")

trojan = TrojanSimulator()

action = input("Enter action (install/communicate/detect/remove): ").lower()

if action == "install":
    result = trojan.simulate_installation()
    print(result)
elif action == "communicate":
    cmd = input("Enter command to simulate: ")
    result = trojan.simulate_communication(cmd)
    print(result)
elif action == "detect":
    detected = trojan.detect_trojan()
    print(f"Trojan detected: {detected}")
elif action == "remove":
    result = trojan.remove_trojan()
    print(result)
else:
    print("Invalid action")''',
        "test_cases": [
            {
                'name': 'Trojan Simulation Test',
                'input': 'install\\n',
                'expected_output': 'Installation complete'
            }
        ]
    },
    "rootkit_hunter": {
        "title": "Defeating Malware – Rootkit Hunter",
        "difficulty": "Hard",
        "marks": "80 Marks",
        "description": """Implement tools to detect and analyze system-level rootkits that hide deep within the operating system.""",
        "how_it_works": [
            "Scan system files for unauthorized modifications",
            "Detect hidden processes and network connections",
            "Analyze system call hooking attempts",
            "Implement rootkit removal and system restoration"
        ],
        "examples": [
            {
                "input": "System scan for rootkit presence",
                "output": "Rootkit detection analysis complete"
            }
        ],
        "starter_code": '''import hashlib
import time
from datetime import datetime

class RootkitHunter:
    def __init__(self):
        self.known_good_hashes = {
            'system32.dll': 'a1b2c3d4e5f6',
            'kernel32.dll': 'f6e5d4c3b2a1',
            'ntdll.dll': '123456789abc'
        }
        self.suspicious_processes = []
        self.scan_results = []
    
    def scan_system_files(self):
        """Scan critical system files for modifications"""
        print("Scanning system files...")
        
        # Simulate file integrity checking
        modified_files = []
        for filename, expected_hash in self.known_good_hashes.items():
            # Simulate hash checking
            current_hash = hashlib.md5(f"current_{filename}".encode()).hexdigest()[:12]
            
            if current_hash != expected_hash:
                modified_files.append(filename)
                self.scan_results.append(f"MODIFIED: {filename}")
            else:
                self.scan_results.append(f"OK: {filename}")
        
        return modified_files
    
    def detect_hidden_processes(self):
        """Detect processes attempting to hide"""
        print("Scanning for hidden processes...")
        
        # Simulate process detection
        suspicious_procs = ['svchost_fake.exe', 'system_hidden.exe']
        
        for proc in suspicious_procs:
            if hash(proc) % 3 == 0:  # Random simulation
                self.suspicious_processes.append(proc)
                self.scan_results.append(f"HIDDEN PROCESS: {proc}")
        
        return self.suspicious_processes
    
    def analyze_system_calls(self):
        """Analyze system call hooking"""
        print("Analyzing system call integrity...")
        
        system_calls = ['NtCreateFile', 'NtOpenProcess', 'NtQuerySystemInformation']
        hooked_calls = []
        
        for call in system_calls:
            # Simulate hook detection
            if hash(call) % 2 == 0:
                hooked_calls.append(call)
                self.scan_results.append(f"HOOKED: {call}")
            else:
                self.scan_results.append(f"CLEAN: {call}")
        
        return hooked_calls
    
    def generate_report(self):
        """Generate comprehensive rootkit scan report"""
        report = f"=== ROOTKIT HUNTER REPORT ===\\n"
        report += f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n"
        report += f"Total Issues: {len([r for r in self.scan_results if 'MODIFIED' in r or 'HIDDEN' in r or 'HOOKED' in r])}\\n\\n"
        
        for result in self.scan_results:
            report += f"{result}\\n"
        
        return report

# Example usage
print("=== ROOTKIT HUNTER ===")
hunter = RootkitHunter()

scan_type = input("Enter scan type (files/processes/syscalls/full): ").lower()

if scan_type == "files":
    modified = hunter.scan_system_files()
    print(f"Modified files found: {len(modified)}")
elif scan_type == "processes":
    hidden = hunter.detect_hidden_processes()
    print(f"Hidden processes found: {len(hidden)}")
elif scan_type == "syscalls":
    hooked = hunter.analyze_system_calls()
    print(f"Hooked system calls: {len(hooked)}")
elif scan_type == "full":
    hunter.scan_system_files()
    hunter.detect_hidden_processes()
    hunter.analyze_system_calls()
    print("Full system scan complete")
    print("\\n" + hunter.generate_report())
else:
    print("Invalid scan type")''',
        "test_cases": [
            {
                'name': 'Rootkit Detection Test',
                'input': 'full\\n',
                'expected_output': 'Full system scan complete'
            }
        ]
    },
    "database_security": {
        "title": "Database Security Implementation",
        "difficulty": "Medium",
        "marks": "55 Marks",
        "description": """Implement access control, role-based permissions, and authentication for databases to prevent unauthorized access and data breaches.""",
        "how_it_works": [
            "Create user authentication system",
            "Implement role-based access control (RBAC)",
            "Set up database permissions and restrictions",
            "Monitor and log database access attempts"
        ],
        "examples": [
            {
                "input": "User login attempt with role verification",
                "output": "Access granted with appropriate permissions"
            }
        ],
        "starter_code": '''import hashlib
from datetime import datetime

class DatabaseSecurity:
    def __init__(self):
        self.users = {
            'admin': {'password_hash': self.hash_password('admin123'), 'role': 'administrator'},
            'user1': {'password_hash': self.hash_password('user123'), 'role': 'read_only'},
            'user2': {'password_hash': self.hash_password('user456'), 'role': 'read_write'}
        }
        
        self.permissions = {
            'administrator': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP'],
            'read_write': ['SELECT', 'INSERT', 'UPDATE'],
            'read_only': ['SELECT']
        }
        
        self.access_log = []
    
    def hash_password(self, password):
        """Hash password securely"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        if username not in self.users:
            self.log_access(username, 'FAILED', 'User not found')
            return False
        
        password_hash = self.hash_password(password)
        if self.users[username]['password_hash'] == password_hash:
            self.log_access(username, 'SUCCESS', 'Authentication successful')
            return True
        else:
            self.log_access(username, 'FAILED', 'Invalid password')
            return False
    
    def check_permission(self, username, operation):
        """Check if user has permission for operation"""
        if username not in self.users:
            return False
        
        user_role = self.users[username]['role']
        allowed_operations = self.permissions.get(user_role, [])
        
        has_permission = operation.upper() in allowed_operations
        self.log_access(username, 'PERMISSION_CHECK', f"{operation}: {'ALLOWED' if has_permission else 'DENIED'}")
        
        return has_permission
    
    def log_access(self, username, action, details):
        """Log database access attempts"""
        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'username': username,
            'action': action,
            'details': details
        }
        self.access_log.append(log_entry)
    
    def get_access_log(self):
        """Get recent access log"""
        return self.access_log[-10:]  # Last 10 entries

# Example usage
db_security = DatabaseSecurity()

print("=== DATABASE SECURITY SYSTEM ===")
username = input("Enter username: ")
password = input("Enter password: ")

if db_security.authenticate_user(username, password):
    print(f"Welcome, {username}!")
    
    operation = input("Enter database operation (SELECT/INSERT/UPDATE/DELETE): ")
    
    if db_security.check_permission(username, operation):
        print(f"Operation {operation} allowed")
        print("Executing database operation...")
    else:
        print(f"Access denied for operation: {operation}")
else:
    print("Authentication failed")

print("\\nRecent access log:")
for entry in db_security.get_access_log():
    print(f"[{entry['timestamp']}] {entry['username']}: {entry['action']} - {entry['details']}")''',
        "test_cases": [
            {
                'name': 'Database Authentication Test',
                'input': 'admin\\nadmin123\\nSELECT\\n',
                'expected_output': 'Operation SELECT allowed'
            }
        ]
    },
    "database_encryption": {
        "title": "Database Encryption & Integrity Control",
        "difficulty": "Hard",
        "marks": "65 Marks",
        "description": """Secure stored data using hashing and encryption techniques to maintain data integrity and confidentiality in databases.""",
        "how_it_works": [
            "Implement field-level encryption for sensitive data",
            "Use hashing for data integrity verification",
            "Create secure key management system",
            "Implement data masking and tokenization"
        ],
        "examples": [
            {
                "input": "Sensitive data: 'Credit Card: 1234-5678-9012-3456'",
                "output": "Encrypted and stored securely with integrity hash"
            }
        ],
        "starter_code": '''import hashlib
import base64
from datetime import datetime

class DatabaseEncryption:
    def __init__(self):
        self.encryption_key = "database_encryption_key_2024"
        self.integrity_hashes = {}
        self.encrypted_data = {}
    
    def encrypt_field(self, field_name, data):
        """Encrypt sensitive field data"""
        # Simple XOR encryption for demonstration
        key_bytes = self.encryption_key.encode()
        data_bytes = data.encode()
        
        encrypted_bytes = bytes(a ^ b for a, b in zip(data_bytes, key_bytes * (len(data_bytes) // len(key_bytes) + 1)))
        encrypted_data = base64.b64encode(encrypted_bytes).decode()
        
        # Store encrypted data
        self.encrypted_data[field_name] = encrypted_data
        
        # Generate integrity hash
        integrity_hash = hashlib.sha256((data + self.encryption_key).encode()).hexdigest()
        self.integrity_hashes[field_name] = integrity_hash
        
        return encrypted_data
    
    def decrypt_field(self, field_name):
        """Decrypt field data"""
        if field_name not in self.encrypted_data:
            return None
        
        try:
            encrypted_data = self.encrypted_data[field_name]
            encrypted_bytes = base64.b64decode(encrypted_data)
            key_bytes = self.encryption_key.encode()
            
            decrypted_bytes = bytes(a ^ b for a, b in zip(encrypted_bytes, key_bytes * (len(encrypted_bytes) // len(key_bytes) + 1)))
            return decrypted_bytes.decode()
        except:
            return None
    
    def verify_integrity(self, field_name, original_data):
        """Verify data integrity using hash"""
        if field_name not in self.integrity_hashes:
            return False
        
        expected_hash = hashlib.sha256((original_data + self.encryption_key).encode()).hexdigest()
        stored_hash = self.integrity_hashes[field_name]
        
        return expected_hash == stored_hash
    
    def mask_sensitive_data(self, data, mask_char='*', visible_chars=4):
        """Mask sensitive data for display"""
        if len(data) <= visible_chars:
            return mask_char * len(data)
        
        return data[:visible_chars] + mask_char * (len(data) - visible_chars)
    
    def generate_report(self):
        """Generate encryption status report"""
        report = f"=== DATABASE ENCRYPTION REPORT ===\\n"
        report += f"Report Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\\n"
        report += f"Encrypted Fields: {len(self.encrypted_data)}\\n"
        report += f"Integrity Hashes: {len(self.integrity_hashes)}\\n\\n"
        
        for field_name in self.encrypted_data:
            report += f"Field: {field_name}\\n"
            report += f"  Status: ENCRYPTED\\n"
            report += f"  Hash Verification: {'VALID' if field_name in self.integrity_hashes else 'MISSING'}\\n"
        
        return report

# Example usage
print("=== DATABASE ENCRYPTION SYSTEM ===")
db_encryption = DatabaseEncryption()

field_name = input("Enter field name: ")
sensitive_data = input("Enter sensitive data to encrypt: ")

# Encrypt the data
encrypted = db_encryption.encrypt_field(field_name, sensitive_data)
print(f"Data encrypted successfully")

# Show masked version
masked = db_encryption.mask_sensitive_data(sensitive_data)
print(f"Masked display: {masked}")

# Decrypt and verify
decrypted = db_encryption.decrypt_field(field_name)
integrity_valid = db_encryption.verify_integrity(field_name, sensitive_data)

print(f"Decryption successful: {decrypted == sensitive_data}")
print(f"Integrity verified: {integrity_valid}")

print("\\n" + db_encryption.generate_report())''',
        "test_cases": [
            {
                'name': 'Encryption Test',
                'input': 'credit_card\\n1234-5678-9012-3456\\n',
                'expected_output': 'Data encrypted successfully'
            }
        ]
    },
    "des": {
        "title": "Data Encryption Standard (DES)",
        "difficulty": "Medium",
        "marks": "45 Marks",
        "description": """Data Encryption Standard (DES) is a symmetric-key algorithm for the encryption of digital data. It uses a 56-bit key to encrypt data in 64-bit blocks.""",
        "how_it_works": [
            "Input 64-bit plaintext block",
            "Apply initial permutation",
            "Perform 16 rounds of Feistel function",
            "Apply final permutation to get ciphertext"
        ],
        "examples": [
            {
                "input": "Plaintext: 'HELLO123', Key: '1234567890ABCDEF'",
                "output": "Ciphertext: encrypted block"
            }
        ],
        "starter_code": '''# Simplified DES implementation for educational purposes
def des_encrypt(plaintext, key):
    """Simplified DES encryption simulation"""
    # This is a simplified version for demonstration
    encrypted = ""
    key_int = sum(ord(c) for c in key) % 256
    
    for char in plaintext:
        encrypted_char = chr((ord(char) + key_int) % 256)
        encrypted += encrypted_char
    
    return encrypted

def des_decrypt(ciphertext, key):
    """Simplified DES decryption simulation"""
    decrypted = ""
    key_int = sum(ord(c) for c in key) % 256
    
    for char in ciphertext:
        decrypted_char = chr((ord(char) - key_int) % 256)
        decrypted += decrypted_char
    
    return decrypted

# Example usage
plaintext = input("Enter text to encrypt: ")
key = "DESKEY12"  # 8-character key for DES

encrypted = des_encrypt(plaintext, key)
print(f"Encrypted: {encrypted}")

decrypted = des_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")
print(f"Match: {plaintext == decrypted}")''',
        "test_cases": [
            {
                'name': 'DES Encryption Test',
                'input': 'HELLO123\\n',
                'expected_output': 'Match: True'
            }
        ]
    },
    "aes": {
        "title": "Advanced Encryption Standard (AES)",
        "difficulty": "Medium",
        "marks": "50 Marks",
        "description": """Advanced Encryption Standard (AES) is a symmetric encryption algorithm that replaced DES. It supports key sizes of 128, 192, and 256 bits.""",
        "how_it_works": [
            "Initialize with key expansion",
            "Apply initial round key addition",
            "Perform multiple rounds of SubBytes, ShiftRows, MixColumns",
            "Final round without MixColumns"
        ],
        "examples": [
            {
                "input": "Plaintext: 'Secret Message', Key: 128-bit key",
                "output": "Ciphertext: AES encrypted data"
            }
        ],
        "starter_code": '''import hashlib

class SimpleAES:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()[:16]  # 128-bit key
    
    def encrypt(self, plaintext):
        """Simplified AES encryption simulation"""
        # Pad plaintext to 16-byte blocks
        padded = self._pad(plaintext)
        encrypted = b''
        
        for i in range(0, len(padded), 16):
            block = padded[i:i+16]
            encrypted_block = self._encrypt_block(block)
            encrypted += encrypted_block
        
        return encrypted.hex()
    
    def decrypt(self, ciphertext_hex):
        """Simplified AES decryption simulation"""
        ciphertext = bytes.fromhex(ciphertext_hex)
        decrypted = b''
        
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_block = self._decrypt_block(block)
            decrypted += decrypted_block
        
        return self._unpad(decrypted).decode()
    
    def _encrypt_block(self, block):
        """Simulate block encryption"""
        result = bytearray(16)
        for i in range(16):
            result[i] = (block[i] ^ self.key[i]) % 256
        return bytes(result)
    
    def _decrypt_block(self, block):
        """Simulate block decryption"""
        result = bytearray(16)
        for i in range(16):
            result[i] = (block[i] ^ self.key[i]) % 256
        return bytes(result)
    
    def _pad(self, text):
        """PKCS7 padding"""
        text_bytes = text.encode()
        pad_len = 16 - (len(text_bytes) % 16)
        return text_bytes + bytes([pad_len] * pad_len)
    
    def _unpad(self, padded):
        """Remove PKCS7 padding"""
        pad_len = padded[-1]
        return padded[:-pad_len]

# Example usage
plaintext = input("Enter text to encrypt: ")
key = "MySecretAESKey123"

aes = SimpleAES(key)
encrypted = aes.encrypt(plaintext)
print(f"Encrypted: {encrypted}")

decrypted = aes.decrypt(encrypted)
print(f"Decrypted: {decrypted}")
print(f"Match: {plaintext == decrypted}")''',
        "test_cases": [
            {
                'name': 'AES Encryption Test',
                'input': 'Hello AES\\n',
                'expected_output': 'Match: True'
            }
        ]
    },
    "rsa": {
        "title": "Asymmetric Key Encryption (RSA)",
        "difficulty": "Hard",
        "marks": "60 Marks",
        "description": """RSA is a public-key cryptosystem that uses the mathematical properties of large prime numbers for secure communication.""",
        "how_it_works": [
            "Generate two large prime numbers p and q",
            "Calculate n = p × q and φ(n) = (p-1)(q-1)",
            "Choose public exponent e and calculate private exponent d",
            "Encrypt with public key (e,n), decrypt with private key (d,n)"
        ],
        "examples": [
            {
                "input": "Message: 'HELLO', Public key used for encryption",
                "output": "Encrypted message that can only be decrypted with private key"
            }
        ],
        "starter_code": '''def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    """Extended Euclidean Algorithm"""
    if gcd(a, m) != 1:
        return None
    
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    _, x, _ = extended_gcd(a, m)
    return (x % m + m) % m

def power_mod(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def rsa_keygen(p, q):
    """Generate RSA key pair"""
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537  # Common public exponent
    while gcd(e, phi) != 1:
        e += 2
    
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)  # (public_key, private_key)

def rsa_encrypt(message, public_key):
    """Encrypt message with RSA public key"""
    e, n = public_key
    # Convert message to number (simplified)
    message_num = sum(ord(char) * (256 ** i) for i, char in enumerate(message)) % n
    return power_mod(message_num, e, n)

def rsa_decrypt(ciphertext, private_key):
    """Decrypt message with RSA private key"""
    d, n = private_key
    return power_mod(ciphertext, d, n)

# Example usage with small primes (for demonstration)
print("RSA Encryption Demo")
message = input("Enter message to encrypt: ")

# Use small primes for demo
p, q = 61, 53
public_key, private_key = rsa_keygen(p, q)

encrypted = rsa_encrypt(message, public_key)
decrypted_num = rsa_decrypt(encrypted, private_key)

print(f"Original message: {message}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted number: {decrypted_num}")
print(f"RSA encryption successful: {encrypted != decrypted_num}")''',
        "test_cases": [
            {
                'name': 'RSA Encryption Test',
                'input': 'HELLO\\n',
                'expected_output': 'RSA encryption successful: True'
            }
        ]
    }
}

# Current challenge tracker
current_challenge = "caesar_cipher"

@app.route('/')
def dashboard():
    """Render the dashboard with all challenges."""
    return render_template('dashboard.html')

@app.route('/challenge/<challenge_id>')
def challenge(challenge_id):
    """Render the challenge page with the code editor."""
    global current_challenge
    if challenge_id in PROBLEMS_DATA:
        current_challenge = challenge_id
        return render_template('index.html', problem=PROBLEMS_DATA[challenge_id])
    else:
        return redirect('/')

@app.route('/next_challenge')
def next_challenge():
    """Switch to the next challenge."""
    global current_challenge
    
    challenge_order = ["caesar_cipher", "monoalphabetic_cipher", "mac", "des", "aes", "rsa", "diffie_hellman", "digital_signature", "mobile_security", "intrusion_detection", "malware_trojans", "rootkit_hunter", "database_security", "database_encryption"]
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
    """Execute Python code safely and return results."""
    try:
        request_data = request.get_json() or {}
        user_code = request_data.get('code', '')
        test_input = request_data.get('input', '').replace('\\n', '\n')
        
        if not user_code.strip():
            return jsonify({
                'success': False,
                'output': '',
                'error': 'No code provided'
            })
        
        # Create temporary file for code execution
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
            tmp_file.write(user_code)
            tmp_file_path = tmp_file.name
        
        try:
            # Execute the code with timeout and provide test input
            result = subprocess.run(
                [sys.executable, tmp_file_path],
                capture_output=True,
                text=True,
                timeout=10,
                input=test_input
            )
            
            if result.returncode == 0:
                return jsonify({
                    'success': True,
                    'output': result.stdout,
                    'error': ''
                })
            else:
                # Parse error for line numbers
                error_msg = result.stderr
                line_number = None
                
                # Extract line number from error message
                if 'line' in error_msg:
                    import re
                    line_match = re.search(r'line (\d+)', error_msg)
                    if line_match:
                        line_number = int(line_match.group(1))
                
                return jsonify({
                    'success': False,
                    'output': result.stdout,
                    'error': error_msg,
                    'line_number': line_number
                })
                
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_file_path)
            except:
                pass
                
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'output': '',
            'error': 'Code execution timed out (10 second limit)'
        })
    except Exception as e:
        logging.error(f"Code execution error: {str(e)}")
        return jsonify({
            'success': False,
            'output': '',
            'error': f'Execution error: {str(e)}'
        })

@app.route('/test_cases')
def get_test_cases():
    """Get test cases for the current challenge."""
    global current_challenge
    if current_challenge in PROBLEMS_DATA:
        return jsonify({
            'success': True,
            'test_cases': PROBLEMS_DATA[current_challenge].get('test_cases', [])
        })
    return jsonify({'success': False, 'test_cases': []})

@app.route('/run_test_cases', methods=['POST'])
def run_test_cases():
    """Execute code against all test cases for the current challenge."""
    try:
        request_data = request.get_json() or {}
        user_code = request_data.get('code', '')
        global current_challenge
        
        if not user_code.strip():
            return jsonify({
                'success': False,
                'error': 'No code provided'
            })
        
        if current_challenge not in PROBLEMS_DATA:
            return jsonify({
                'success': False,
                'error': 'No valid challenge selected'
            })
            
        test_cases = PROBLEMS_DATA[current_challenge].get('test_cases', [])
        results = []
        
        for i, test_case in enumerate(test_cases):
            test_input = test_case.get('input', '').replace('\\n', '\n')
            
            # Create temporary file for this test
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp_file:
                tmp_file.write(user_code)
                tmp_file_path = tmp_file.name
            
            try:
                # Execute the code with test input
                result = subprocess.run(
                    [sys.executable, tmp_file_path],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    input=test_input
                )
                
                output = result.stdout.strip()
                expected = test_case.get('expected_output', '').strip()
                
                # Check if output contains expected text (more flexible matching)
                if expected:
                    passed = expected.lower() in output.lower()
                else:
                    passed = result.returncode == 0
                
                results.append({
                    'name': test_case.get('name', f'Test {i+1}'),
                    'passed': passed,
                    'output': output,
                    'expected': expected,
                    'error': result.stderr if result.returncode != 0 else None
                })
                
            except subprocess.TimeoutExpired:
                results.append({
                    'name': test_case.get('name', f'Test {i+1}'),
                    'passed': False,
                    'output': '',
                    'expected': test_case.get('expected_output', ''),
                    'error': 'Test timed out'
                })
            finally:
                try:
                    os.unlink(tmp_file_path)
                except:
                    pass
        
        passed_count = sum(1 for r in results if r['passed'])
        total_count = len(results)
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': f'{passed_count}/{total_count} tests passed'
        })
        
    except Exception as e:
        logging.error(f"Test execution error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Test execution error: {str(e)}'
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)