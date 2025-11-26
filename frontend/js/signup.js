// signup.js - Enhanced with real-time validation
const API_BASE_URL = 'https://architect-johan-secure.onrender.com';

// Validation state management
const validationState = {
    username: { isValid: false, message: '', checking: false },
    email: { isValid: false, message: '', checking: false },
    mobile: { isValid: false, message: '', checking: false }
};

// Debounce function to limit API calls
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Show validation message under input
function showValidationMessage(inputId, message, type = 'error') {
    // Remove existing message
    const existingMessage = document.getElementById(`${inputId}-message`);
    if (existingMessage) {
        existingMessage.remove();
    }

    if (!message) return;

    const input = document.getElementById(inputId);
    const formGroup = input.closest('.form-group');
    
    const messageDiv = document.createElement('div');
    messageDiv.id = `${inputId}-message`;
    messageDiv.className = `validation-message ${type}`;
    messageDiv.textContent = message;
    messageDiv.style.cssText = `
        font-size: 12px;
        margin-top: 5px;
        padding: 4px 8px;
        border-radius: 4px;
        animation: fadeIn 0.3s ease;
    `;

    if (type === 'error') {
        messageDiv.style.cssText += `
            color: #FF004C;
            background: rgba(255, 0, 76, 0.1);
            border: 1px solid rgba(255, 0, 76, 0.3);
        `;
        input.style.borderColor = '#FF004C';
    } else if (type === 'success') {
        messageDiv.style.cssText += `
            color: #00FFB3;
            background: rgba(0, 255, 179, 0.1);
            border: 1px solid rgba(0, 255, 179, 0.3);
        `;
        input.style.borderColor = '#00FFB3';
    } else if (type === 'loading') {
        messageDiv.style.cssText += `
            color: #2EC6FF;
            background: rgba(46, 198, 255, 0.1);
            border: 1px solid rgba(46, 198, 255, 0.3);
        `;
        input.style.borderColor = '#2EC6FF';
    }

    formGroup.appendChild(messageDiv);
}

// Clear validation message
function clearValidationMessage(inputId) {
    const messageDiv = document.getElementById(`${inputId}-message`);
    if (messageDiv) {
        messageDiv.remove();
    }
    const input = document.getElementById(inputId);
    if (input) {
        input.style.borderColor = '';
    }
}

// Check username availability
const checkUsernameAvailability = debounce(async function(username) {
    if (!username || username.length < 3) {
        clearValidationMessage('username');
        validationState.username = { isValid: false, message: '', checking: false };
        return;
    }

    validationState.username.checking = true;
    showValidationMessage('username', 'Checking username availability...', 'loading');

    try {
        const response = await fetch(`${API_BASE_URL}/api/check-username`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username })
        });

        const data = await response.json();

        if (data.exists) {
            showValidationMessage('username', 'Username already taken. Please choose another.', 'error');
            validationState.username = { isValid: false, message: 'Username taken', checking: false };
        } else {
            showValidationMessage('username', '✓ Username available', 'success');
            validationState.username = { isValid: true, message: 'Available', checking: false };
        }
    } catch (error) {
        console.error('Username check error:', error);
        showValidationMessage('username', 'Unable to verify username. Please try again.', 'error');
        validationState.username = { isValid: false, message: 'Check failed', checking: false };
    }
}, 500);

// Check email availability
const checkEmailAvailability = debounce(async function(email) {
    if (!email) {
        clearValidationMessage('email');
        validationState.email = { isValid: false, message: '', checking: false };
        return;
    }

    // Enhanced Gmail validation
    const gmailRegex = /^[a-zA-Z0-9.]+@gmail\.com$/;
    if (!gmailRegex.test(email)) {
        showValidationMessage('email', 'Only Gmail accounts are allowed (@gmail.com)', 'error');
        validationState.email = { isValid: false, message: 'Invalid email', checking: false };
        return;
    }

    validationState.email.checking = true;
    showValidationMessage('email', 'Checking email availability...', 'loading');

    try {
        const response = await fetch(`${API_BASE_URL}/api/check-email`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email })
        });

        const data = await response.json();

        if (data.exists) {
            showValidationMessage('email', 'Email already registered. Please use a different email.', 'error');
            validationState.email = { isValid: false, message: 'Email taken', checking: false };
        } else {
            showValidationMessage('email', '✓ Email available', 'success');
            validationState.email = { isValid: true, message: 'Available', checking: false };
        }
    } catch (error) {
        console.error('Email check error:', error);
        showValidationMessage('email', 'Unable to verify email. Please try again.', 'error');
        validationState.email = { isValid: false, message: 'Check failed', checking: false };
    }
}, 500);

// Check mobile availability
const checkMobileAvailability = debounce(async function(mobileNo) {
    if (!mobileNo || mobileNo.length !== 10) {
        clearValidationMessage('mobile_no');
        validationState.mobile = { isValid: false, message: '', checking: false };
        return;
    }

    // Validate Indian mobile format
    const mobileRegex = /^[6-9]\d{9}$/;
    if (!mobileRegex.test(mobileNo)) {
        showValidationMessage('mobile_no', 'Please enter a valid 10-digit Indian mobile number', 'error');
        validationState.mobile = { isValid: false, message: 'Invalid format', checking: false };
        return;
    }

    validationState.mobile.checking = true;
    showValidationMessage('mobile_no', 'Checking mobile number...', 'loading');

    try {
        const response = await fetch(`${API_BASE_URL}/api/check-mobile`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ mobile_no: mobileNo })
        });

        const data = await response.json();

        if (data.exists) {
            showValidationMessage('mobile_no', 'Mobile number already registered. Please use a different number.', 'error');
            validationState.mobile = { isValid: false, message: 'Mobile taken', checking: false };
        } else {
            showValidationMessage('mobile_no', '✓ Mobile number available', 'success');
            validationState.mobile = { isValid: true, message: 'Available', checking: false };
        }
    } catch (error) {
        console.error('Mobile check error:', error);
        showValidationMessage('mobile_no', 'Unable to verify mobile number. Please try again.', 'error');
        validationState.mobile = { isValid: false, message: 'Check failed', checking: false };
    }
}, 500);

// Check if form is valid for submission
function isFormValid() {
    return validationState.username.isValid && 
           validationState.email.isValid && 
           validationState.mobile.isValid;
}

// Update submit button state
function updateSubmitButton() {
    const signupBtn = document.getElementById('signup-btn');
    if (signupBtn) {
        if (isFormValid()) {
            signupBtn.disabled = false;
            signupBtn.style.opacity = '1';
            signupBtn.style.cursor = 'pointer';
        } else {
            signupBtn.disabled = true;
            signupBtn.style.opacity = '0.6';
            signupBtn.style.cursor = 'not-allowed';
        }
    }
}

// Password strength checker (existing function - keep as is)
function checkPasswordStrength(password) {
    let strength = 0;
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?`~]/.test(password)
    };

    Object.values(requirements).forEach(req => {
        if (req) strength++;
    });

    return { strength, requirements };
}

// Update password strength indicator (existing function - keep as is)
function updatePasswordStrength(password) {
    const strengthFill = document.getElementById('strength-fill');
    const requirements = document.getElementById('password-requirements');
    
    if (!password) {
        strengthFill.style.width = '0%';
        strengthFill.className = 'strength-fill';
        requirements.innerHTML = '• 8+ characters • Uppercase • Lowercase • Number • Special character';
        return;
    }

    const { strength, requirements: reqs } = checkPasswordStrength(password);
    
    // Update strength bar
    switch(strength) {
        case 0:
        case 1:
            strengthFill.style.width = '20%';
            strengthFill.className = 'strength-fill weak';
            break;
        case 2:
            strengthFill.style.width = '40%';
            strengthFill.className = 'strength-fill fair';
            break;
        case 3:
            strengthFill.style.width = '60%';
            strengthFill.className = 'strength-fill good';
            break;
        case 4:
            strengthFill.style.width = '80%';
            strengthFill.className = 'strength-fill strong';
            break;
        case 5:
            strengthFill.style.width = '100%';
            strengthFill.className = 'strength-fill very-strong';
            break;
    }

    // Update requirements text
    let reqText = '';
    if (!reqs.length) reqText += '• <span style="color: #FF004C">8+ characters</span> ';
    else reqText += '• <span style="color: #00FFB3">8+ characters</span> ';

    if (!reqs.uppercase) reqText += '• <span style="color: #FF004C">Uppercase</span> ';
    else reqText += '• <span style="color: #00FFB3">Uppercase</span> ';

    if (!reqs.lowercase) reqText += '• <span style="color: #FF004C">Lowercase</span> ';
    else reqText += '• <span style="color: #00FFB3">Lowercase</span> ';

    if (!reqs.number) reqText += '• <span style="color: #FF004C">Number</span> ';
    else reqText += '• <span style="color: #00FFB3">Number</span> ';

    if (!reqs.special) reqText += '• <span style="color: #FF004C">Special character</span>';
    else reqText += '• <span style="color: #00FFB3">Special character</span>';

    requirements.innerHTML = reqText;
}

// Input sanitization function (existing function - keep as is)
function sanitizeInput(input) {
    return input.replace(/[<>"'`]/g, '').trim();
}

// Show error message with animation (existing function - keep as is)
function showError(message) {
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const card = document.getElementById('signup-card');
    
    errorMessage.textContent = message;
    errorMessage.classList.add('show');
    successMessage.classList.remove('show');
    
    card.classList.add('shake');
    setTimeout(() => card.classList.remove('shake'), 500);
    
    setTimeout(() => {
        errorMessage.classList.remove('show');
    }, 5000);
}

// Show success message (existing function - keep as is)
function showSuccess(message) {
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    
    successMessage.textContent = message;
    successMessage.classList.add('show');
    errorMessage.classList.remove('show');
}

// Get CSRF Token function (existing function - keep as is)
async function getCSRFToken() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/csrf-token`);
        if (!response.ok) {
            throw new Error('Failed to get CSRF token');
        }
        const data = await response.json();
        return data.csrf_token;
    } catch (error) {
        console.error('Error fetching CSRF token:', error);
        return 'fallback-csrf-token-' + Math.random().toString(36).substring(2);
    }
}

// Main signup functionality
document.addEventListener('DOMContentLoaded', function() {
    // Check social verification (existing code - keep as is)
    const sessionVerified = sessionStorage.getItem('social_verification') === 'completed';
    const localVerified = localStorage.getItem('social_verification');
    
    let socialVerified = sessionVerified;
    if (localVerified) {
        try {
            const status = JSON.parse(localVerified);
            if (status.youtube && status.telegram && status.instagram) {
                socialVerified = true;
            }
        } catch (e) {
            console.error('Error parsing social verification:', e);
        }
    }
    
    if (!socialVerified) {
        showError('Please complete social media verification first. Redirecting to gateway...');
        setTimeout(() => {
            window.location.href = 'gateway.html';
        }, 3000);
        return;
    }

    const signupForm = document.getElementById('signup-form');
    const signupBtn = document.getElementById('signup-btn');
    const csrfTokenInput = document.getElementById('csrf_token');

    // Get CSRF token on page load
    getCSRFToken().then(token => {
        if (token) {
            csrfTokenInput.value = token;
            console.log('CSRF token initialized');
        }
    }).catch(error => {
        console.error('Error initializing CSRF token:', error);
        showError('Security token initialization failed. Please refresh the page.');
    });

    // Real-time validation event listeners
    const usernameInput = document.getElementById('username');
    const emailInput = document.getElementById('email');
    const mobileInput = document.getElementById('mobile_no');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');

    // Username validation
    if (usernameInput) {
        usernameInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^a-zA-Z0-9_]/g, '');
            const username = this.value.trim();
            checkUsernameAvailability(username);
            updateSubmitButton();
        });

        usernameInput.addEventListener('blur', function() {
            const username = this.value.trim();
            if (username && !validationState.username.checking) {
                checkUsernameAvailability(username);
            }
        });
    }

    // Email validation
    if (emailInput) {
        emailInput.addEventListener('input', function() {
            const email = this.value.trim().toLowerCase();
            checkEmailAvailability(email);
            updateSubmitButton();
        });

        emailInput.addEventListener('blur', function() {
            const email = this.value.trim().toLowerCase();
            if (email && !validationState.email.checking) {
                checkEmailAvailability(email);
            }
        });
    }

    // Mobile validation
    if (mobileInput) {
        mobileInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
            if (this.value.length > 10) {
                this.value = this.value.slice(0, 10);
            }
            const mobileNo = this.value;
            checkMobileAvailability(mobileNo);
            updateSubmitButton();
        });

        mobileInput.addEventListener('blur', function() {
            const mobileNo = this.value;
            if (mobileNo && mobileNo.length === 10 && !validationState.mobile.checking) {
                checkMobileAvailability(mobileNo);
            }
        });
    }

    // Password strength (existing code - keep as is)
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            updatePasswordStrength(this.value);
        });
    }

    // Password confirmation (existing code - keep as is)
    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', function() {
            const password = document.getElementById('password').value;
            if (this.value && password !== this.value) {
                this.style.borderColor = '#FF004C';
                this.setCustomValidity('Passwords do not match');
            } else {
                this.style.borderColor = '#00FFB3';
                this.setCustomValidity('');
            }
            updateSubmitButton();
        });
    }

    // Form submission handler
    signupForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Final validation check
        if (!isFormValid()) {
            showError('Please fix validation errors before submitting.');
            return;
        }

        // Get fresh CSRF token
        const freshCSRFToken = await getCSRFToken();
        csrfTokenInput.value = freshCSRFToken;
        
        // Collect form data
        const formData = {
            username: sanitizeInput(document.getElementById('username').value),
            full_name: sanitizeInput(document.getElementById('full_name').value),
            email: sanitizeInput(document.getElementById('email').value).toLowerCase(),
            mobile_no: '+91' + document.getElementById('mobile_no').value,
            password: document.getElementById('password').value,
            confirm_password: document.getElementById('confirm_password').value,
            csrf_token: freshCSRFToken
        };

        // Update UI for loading state
        signupBtn.disabled = true;
        signupBtn.innerHTML = '<span class="btn-text">Creating Secure Account...</span>';
        signupBtn.classList.add('loading');

        try {
            const response = await fetch(`${API_BASE_URL}/api/signup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': freshCSRFToken
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (response.ok) {
                showSuccess(data.message || 'Account created successfully!');
                
                // Clear social verification status
                sessionStorage.removeItem('social_verification');
                
                console.log('User registration successful:', formData.username);
                
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 2000);
            } else {
                let errorMessage = data.error || 'Registration failed';
                showError(errorMessage);
                console.warn('User registration failed:', errorMessage);
            }
        } catch (error) {
            console.error('Signup network error:', error);
            showError('Network error. Please check your internet connection and try again.');
        } finally {
            signupBtn.disabled = false;
            signupBtn.innerHTML = '<span class="btn-text">Create Secure Account</span>';
            signupBtn.classList.remove('loading');
            updateSubmitButton();
        }
    });

    // Initialize submit button state
    updateSubmitButton();

    // Auto-advance to next field on Enter key (existing code - keep as is)
    const inputs = document.querySelectorAll('input');
    inputs.forEach((input, index) => {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (index < inputs.length - 1) {
                    inputs[index + 1].focus();
                } else {
                    signupForm.dispatchEvent(new Event('submit'));
                }
            }
        });
    });

    // Input focus effects (existing code - keep as is)
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('focused');
        });
    });

    // Auto-focus on first input
    document.getElementById('username').focus();

    console.log('Secure signup page with real-time validation initialized:', new Date().toISOString());
});

// Additional security features (existing code - keep as is)
window.addEventListener('beforeunload', function() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        input.value = '';
    });
});

if (window.history.replaceState) {
    window.history.replaceState(null, null, window.location.href);
}
