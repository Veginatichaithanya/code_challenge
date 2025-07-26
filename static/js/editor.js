// Global variables
let codeEditor;
let currentTestCases = [];

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeCodeEditor();
    setupEventListeners();
    loadTestCases();
});

// Initialize CodeMirror editor
function initializeCodeEditor() {
    const textarea = document.getElementById('codeEditor');
    
    codeEditor = CodeMirror.fromTextArea(textarea, {
        mode: 'python',
        theme: 'material-darker',
        lineNumbers: true,
        indentUnit: 4,
        indentWithTabs: false,
        matchBrackets: true,
        autoCloseBrackets: true,
        lineWrapping: false,
        extraKeys: {
            "Ctrl-Space": "autocomplete",
            "Ctrl-/": "toggleComment",
            "F11": function(cm) {
                cm.setOption("fullScreen", !cm.getOption("fullScreen"));
            },
            "Esc": function(cm) {
                if (cm.getOption("fullScreen")) cm.setOption("fullScreen", false);
            }
        }
    });

    // Set default code
    const starterCode = `def caesar_cipher(text, shift):
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
print("Cipher Text:", cipher_text)`;
    
    codeEditor.setValue(starterCode);
    
    // Auto-resize editor
    codeEditor.setSize(null, "100%");
    
    // Refresh editor on window resize
    window.addEventListener('resize', function() {
        codeEditor.refresh();
    });
}

// Setup event listeners
function setupEventListeners() {
    // Run Code button
    document.getElementById('runCode').addEventListener('click', function() {
        showTestInputModal();
    });
    
    // Execute Test Cases button
    document.getElementById('executeTestCases').addEventListener('click', function() {
        executeAllTestCases();
    });
    
    // Execute with input button in modal
    document.getElementById('executeWithInput').addEventListener('click', function() {
        const input = document.getElementById('testInput').value.replace(/\\n/g, '\n');
        executeCode(input);
        bootstrap.Modal.getInstance(document.getElementById('testInputModal')).hide();
    });
    
    // Copy Code button
    document.getElementById('copyCode').addEventListener('click', function() {
        copyCodeToEditor();
    });
    
    // Next Challenge button
    document.getElementById('nextChallenge').addEventListener('click', function() {
        loadNextChallenge();
    });
    
    // Previous Challenge button
    document.getElementById('previousChallenge').addEventListener('click', function() {
        loadPreviousChallenge();
    });
}

// Show test input modal
function showTestInputModal() {
    const modal = new bootstrap.Modal(document.getElementById('testInputModal'));
    
    // Set default input
    document.getElementById('testInput').value = 'Hello World\n3';
    
    modal.show();
}

// Execute code with given input
function executeCode(input = '') {
    const code = codeEditor.getValue();
    
    if (!code.trim()) {
        showMessage('Please write some code first!', 'warning');
        return;
    }
    
    // Clear previous errors
    clearErrorHighlighting();
    
    // Show loading
    const outputDiv = document.getElementById('executionOutput');
    outputDiv.innerHTML = '<div class="loading">Executing code...</div>';
    
    // Switch to output tab
    document.getElementById('output-tab').click();
    
    // Make API call to execute code
    fetch('/execute', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            code: code,
            input: input
        })
    })
    .then(response => response.json())
    .then(data => {
        displayExecutionResult(data);
    })
    .catch(error => {
        console.error('Error:', error);
        outputDiv.innerHTML = `<div class="output-error">Network error: ${error.message}</div>`;
    });
}

// Display execution result
function displayExecutionResult(result) {
    const outputDiv = document.getElementById('executionOutput');
    const errorDiv = document.getElementById('errorOutput');
    
    if (result.success) {
        // Success
        outputDiv.innerHTML = `<div class="output-success">${escapeHtml(result.output) || 'Code executed successfully (no output)'}</div>`;
        errorDiv.innerHTML = '<div class="text-muted">No errors to display</div>';
        
        // Switch to output tab
        document.getElementById('output-tab').click();
    } else {
        // Error
        outputDiv.innerHTML = '<div class="text-muted">Code execution failed</div>';
        errorDiv.innerHTML = `<div class="output-error">${escapeHtml(result.error)}</div>`;
        
        // Highlight error line if available
        if (result.line_number) {
            highlightErrorLine(result.line_number);
        }
        
        // Switch to errors tab
        document.getElementById('errors-tab').click();
    }
}

// Execute all test cases
function executeAllTestCases() {
    if (currentTestCases.length === 0) {
        showMessage('No test cases available', 'warning');
        return;
    }
    
    const outputDiv = document.getElementById('executionOutput');
    outputDiv.innerHTML = '<div class="loading">Running test cases...</div>';
    
    // Switch to output tab
    document.getElementById('output-tab').click();
    
    // Use the dedicated test cases endpoint
    fetch('/run_test_cases', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            code: codeEditor.getValue()
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            displayServerTestResults(data.results, data.summary);
        } else {
            outputDiv.innerHTML = `<div class="output-error">Test execution failed: ${escapeHtml(data.error)}</div>`;
        }
    })
    .catch(error => {
        console.error('Error running test cases:', error);
        outputDiv.innerHTML = `<div class="output-error">Network error: ${error.message}</div>`;
    });
}

// Display test results from server endpoint
function displayServerTestResults(results, summary) {
    const outputDiv = document.getElementById('executionOutput');
    let html = '<div class="test-results">';
    
    results.forEach((testResult, index) => {
        const passed = testResult.passed;
        
        html += `
            <div class="test-case-result ${passed ? 'success' : 'failure'}">
                <div class="test-case-name">${testResult.name} ${passed ? '✓' : '✗'}</div>
                <div class="test-case-details">
                    <strong>Expected:</strong> ${escapeHtml(testResult.expected)}<br>
                    <strong>Got:</strong> ${testResult.error ? `Error: ${escapeHtml(testResult.error)}` : escapeHtml(testResult.output)}
                </div>
            </div>
        `;
    });
    
    html += `</div><div class="mt-3"><strong>Results: ${summary}</strong></div>`;
    
    outputDiv.innerHTML = html;
}

// Display test results (legacy function for single test execution)
function displayTestResults(results) {
    const outputDiv = document.getElementById('executionOutput');
    let html = '<div class="test-results">';
    
    let passedTests = 0;
    
    results.forEach((item, index) => {
        const testCase = item.testCase;
        const result = item.result;
        
        const isSuccess = result.success && result.output.toLowerCase().includes(testCase.expected_output.toLowerCase());
        if (isSuccess) passedTests++;
        
        html += `
            <div class="test-case-result ${isSuccess ? 'success' : 'failure'}">
                <div class="test-case-name">${testCase.name}</div>
                <div class="test-case-details">
                    <strong>Input:</strong> ${escapeHtml(testCase.input.replace('\n', ' → '))}<br>
                    <strong>Expected:</strong> ${escapeHtml(testCase.expected_output)}<br>
                    <strong>Got:</strong> ${result.success ? escapeHtml(result.output) : `Error: ${escapeHtml(result.error)}`}
                </div>
            </div>
        `;
    });
    
    html += `</div><div class="mt-3"><strong>Results: ${passedTests}/${results.length} test cases passed</strong></div>`;
    
    outputDiv.innerHTML = html;
}

// Load test cases from server
function loadTestCases() {
    fetch('/test_cases')
        .then(response => response.json())
        .then(data => {
            if (data.success && Array.isArray(data.test_cases)) {
                currentTestCases = data.test_cases;
            } else {
                currentTestCases = [];
                console.warn('No test cases available or invalid format:', data);
            }
        })
        .catch(error => {
            console.error('Error loading test cases:', error);
            currentTestCases = [];
        });
}

// Load next challenge
function loadNextChallenge() {
    fetch('/next_challenge')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update the problem data and reload test cases
                updateChallenge(data.problem);
                loadTestCases();
                updateNavigationInfo(data.current_index, data.total_challenges);
                showMessage(`Next Challenge: ${data.problem.title}`, 'success');
            }
        })
        .catch(error => {
            console.error('Error loading next challenge:', error);
            showMessage('Error loading next challenge', 'error');
        });
}

// Load previous challenge
function loadPreviousChallenge() {
    fetch('/previous_challenge')
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update the problem data and reload test cases
                updateChallenge(data.problem);
                loadTestCases();
                updateNavigationInfo(data.current_index, data.total_challenges);
                showMessage(`Previous Challenge: ${data.problem.title}`, 'success');
            }
        })
        .catch(error => {
            console.error('Error loading previous challenge:', error);
            showMessage('Error loading previous challenge', 'error');
        });
}

// Update challenge content
function updateChallenge(problemData) {
    // Update the main title in navbar
    const navbarTitle = document.getElementById('challengeTitle');
    if (navbarTitle && problemData.title) {
        navbarTitle.textContent = problemData.title;
    }
    
    // Update difficulty badge
    const difficultyElement = document.getElementById('challengeDifficulty');
    if (difficultyElement && problemData.difficulty) {
        difficultyElement.textContent = problemData.difficulty;
        // Update difficulty color based on level
        difficultyElement.className = `badge me-2 ${getDifficultyBadgeClass(problemData.difficulty)}`;
    }
    
    // Update marks badge
    const marksElement = document.getElementById('challengeMarks');
    if (marksElement && problemData.marks) {
        marksElement.textContent = problemData.marks;
    }
    
    // Update page title
    document.title = `${problemData.title} - Python Code Editor`;
    
    // Update problem description
    const descElement = document.querySelector('.problem-description');
    if (descElement && problemData.description) {
        descElement.textContent = problemData.description;
    }
    
    // Update how it works section
    const howItWorksElement = document.querySelector('.how-it-works-list');
    if (howItWorksElement && problemData.how_it_works) {
        howItWorksElement.innerHTML = problemData.how_it_works.map(step => `<li>${step}</li>`).join('');
    }
    
    // Update examples section
    const examplesElement = document.querySelector('.examples-section');
    if (examplesElement && problemData.examples) {
        let examplesHtml = '';
        problemData.examples.forEach(example => {
            examplesHtml += `
                <div class="example-item">
                    <strong>Input:</strong> ${example.input}<br>
                    <strong>Output:</strong> ${example.output}
                </div>
            `;
        });
        examplesElement.innerHTML = examplesHtml;
    }
    
    // Update starter code
    if (problemData.starter_code && codeEditor) {
        codeEditor.setValue(problemData.starter_code);
    }
}

// Get appropriate badge class for difficulty
function getDifficultyBadgeClass(difficulty) {
    switch(difficulty.toLowerCase()) {
        case 'easy': return 'bg-success';
        case 'medium': return 'bg-warning';
        case 'hard': return 'bg-danger';
        default: return 'bg-secondary';
    }
}

// Update navigation info
function updateNavigationInfo(currentIndex, totalChallenges) {
    // You can add progress indicator here if needed
    console.log(`Challenge ${currentIndex} of ${totalChallenges}`);
}



// Copy code to editor
function copyCodeToEditor() {
    const solutionCode = document.querySelector('#solutionCode').textContent;
    codeEditor.setValue(solutionCode);
    showMessage('Code copied to editor!', 'success');
}

// Highlight error line
function highlightErrorLine(lineNumber) {
    // Clear previous error highlighting
    clearErrorHighlighting();
    
    // Highlight the error line (CodeMirror uses 0-based line numbers)
    const line = lineNumber - 1;
    codeEditor.addLineClass(line, 'background', 'error-line');
    
    // Add error marker
    const marker = document.createElement('div');
    marker.className = 'error-marker';
    marker.innerHTML = '●';
    marker.title = 'Error on this line';
    
    codeEditor.setGutterMarker(line, 'CodeMirror-linenumbers', marker);
    
    // Scroll to error line
    codeEditor.scrollIntoView({ line: line, ch: 0 });
}

// Clear error highlighting
function clearErrorHighlighting() {
    const totalLines = codeEditor.lineCount();
    for (let i = 0; i < totalLines; i++) {
        codeEditor.removeLineClass(i, 'background', 'error-line');
        codeEditor.setGutterMarker(i, 'CodeMirror-linenumbers', null);
    }
}

// Show message to user
function showMessage(message, type = 'info') {
    // Create toast notification
    const toast = document.createElement('div');
    toast.className = `alert alert-${type === 'success' ? 'success' : type === 'warning' ? 'warning' : type === 'error' ? 'danger' : 'info'} position-fixed`;
    toast.style.cssText = 'top: 70px; right: 20px; z-index: 9999; min-width: 300px;';
    toast.innerHTML = `
        ${message}
        <button type="button" class="btn-close float-end" onclick="this.parentElement.remove()"></button>
    `;
    
    document.body.appendChild(toast);
    
    // Auto-remove after 3 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.remove();
        }
    }, 3000);
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Handle keyboard shortcuts
document.addEventListener('keydown', function(event) {
    // Ctrl+Enter or Cmd+Enter to run code
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        showTestInputModal();
    }
    
    // Ctrl+S or Cmd+S to save (prevent default browser save)
    if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        showMessage('Auto-save feature coming soon!', 'info');
    }
});
