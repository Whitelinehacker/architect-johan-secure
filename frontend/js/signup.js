// Add API base URL
const API_BASE_URL = 'https://architect-johan-secure.onrender.com';

// Password strength checker
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

// Update password strength indicator
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

// Input sanitization function
function sanitizeInput(input) {
    return input.replace(/[<>"'`]/g, '').trim();
}

// Validate email format
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Validate username format
function validateUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
    return usernameRegex.test(username);
}

// Show error message with animation
function showError(message) {
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const card = document.getElementById('signup-card');
    
    errorMessage.textContent = message;
    errorMessage.classList.add('show');
    successMessage.classList.remove('show');
    
    card.classList.add('shake');
    setTimeout(() => card.classList.remove('shake'), 500);
    
    // Auto-hide error after 5 seconds
    setTimeout(() => {
        errorMessage.classList.remove('show');
    }, 5000);
}

// Show success message
function showSuccess(message) {
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    
    successMessage.textContent = message;
    successMessage.classList.add('show');
    errorMessage.classList.remove('show');
}

// Validate form data
function validateFormData(formData) {
    // Check required fields
    if (!formData.username || !formData.full_name || !formData.email || !formData.mobile_no || !formData.password) {
        return { isValid: false, error: 'Please fill in all required fields' };
    }

    // Validate username
    if (formData.username.length < 3 || formData.username.length > 30) {
        return { isValid: false, error: 'Username must be between 3 and 30 characters long', field: 'username' };
    }

    if (!validateUsername(formData.username)) {
        return { isValid: false, error: 'Username can only contain letters, numbers, and underscores', field: 'username' };
    }

    // Validate full name
    if (formData.full_name.length < 2 || formData.full_name.length > 100) {
        return { isValid: false, error: 'Full name must be between 2 and 100 characters long', field: 'full_name' };
    }

    // Validate email
    if (!validateEmail(formData.email)) {
        return { isValid: false, error: 'Please enter a valid email address', field: 'email' };
    }

    // Validate mobile number
    const mobileDigits = formData.mobile_no.replace('+91', '');
    if (mobileDigits.length !== 10 || !/^\d+$/.test(mobileDigits)) {
        return { isValid: false, error: 'Please enter a valid 10-digit mobile number', field: 'mobile_no' };
    }

    // Validate password strength
    const passwordStrength = checkPasswordStrength(formData.password);
    if (passwordStrength.strength < 3) {
        return { isValid: false, error: 'Password is too weak. Please include uppercase letters, lowercase letters, numbers, and special characters', field: 'password' };
    }

    // Check password confirmation
    if (formData.password !== formData.confirm_password) {
        return { isValid: false, error: 'Passwords do not match', field: 'confirm_password' };
    }

    return { isValid: true };
}

// Main signup functionality
document.addEventListener('DOMContentLoaded', function() {
    const signupForm = document.getElementById('signup-form');
    const signupBtn = document.getElementById('signup-btn');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const csrfTokenInput = document.getElementById('csrf_token');

    // Get CSRF token
    fetch(`${API_BASE_URL}/api/csrf-token`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to get CSRF token');
            }
            return response.json();
        })
        .then(data => {
            if (data.csrf_token) {
                csrfTokenInput.value = data.csrf_token;
            }
        })
        .catch(error => {
            console.error('Error fetching CSRF token:', error);
            showError('Security token initialization failed. Please refresh the page.');
        });

    // Password strength real-time feedback
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            updatePasswordStrength(this.value);
        });
    }

    // Password confirmation validation
    const confirmPasswordInput = document.getElementById('confirm_password');
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
        });
    }

    // Mobile number validation (only numbers)
    const mobileInput = document.getElementById('mobile_no');
    if (mobileInput) {
        mobileInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
            if (this.value.length > 10) {
                this.value = this.value.slice(0, 10);
            }
        });
    }

    // Username validation
    const usernameInput = document.getElementById('username');
    if (usernameInput) {
        usernameInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^a-zA-Z0-9_]/g, '');
        });
    }

    // Real-time email validation
    const emailInput = document.getElementById('email');
    if (emailInput) {
        emailInput.addEventListener('blur', function() {
            if (this.value && !validateEmail(this.value)) {
                this.style.borderColor = '#FF004C';
            } else if (this.value) {
                this.style.borderColor = '#00FFB3';
            }
        });
    }

    // Form submission handler
    signupForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Collect form data
        const formData = {
            username: sanitizeInput(document.getElementById('username').value),
            full_name: sanitizeInput(document.getElementById('full_name').value),
            email: sanitizeInput(document.getElementById('email').value).toLowerCase(),
            mobile_no: '+91' + document.getElementById('mobile_no').value,
            password: document.getElementById('password').value,
            confirm_password: document.getElementById('confirm_password').value,
            csrf_token: csrfTokenInput.value
        };

        // Validate form data
        const validation = validateFormData(formData);
        if (!validation.isValid) {
            showError(validation.error);
            if (validation.field) {
                document.getElementById(validation.field).focus();
            }
            return;
        }

        // Update UI for loading state
        signupBtn.disabled = true;
        signupBtn.innerHTML = '<span class="btn-text">Creating Secure Account...</span>';
        
        // Add loading animation to button
        signupBtn.classList.add('loading');

        try {
            const response = await fetch(`${API_BASE_URL}/api/signup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfTokenInput.value
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (response.ok) {
                showSuccess(data.message || 'Account created successfully!');
                
                // Log successful signup attempt
                console.log('User registration successful:', formData.username);
                
                // Redirect to login page after delay
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 2000);
            } else {
                // Handle specific error messages
                let errorMessage = data.error || 'Registration failed';
                
                // Provide specific guidance based on error type
                if (errorMessage.includes('username') || errorMessage.includes('Username')) {
                    errorMessage += ' Please choose a different username.';
                    document.getElementById('username').focus();
                } else if (errorMessage.includes('email') || errorMessage.includes('Email')) {
                    errorMessage += ' Please use a different email or try logging in.';
                    document.getElementById('email').focus();
                } else if (errorMessage.includes('password')) {
                    document.getElementById('password').focus();
                }
                
                showError(errorMessage);
                
                // Log failed signup attempt
                console.warn('User registration failed:', errorMessage);
            }
        } catch (error) {
            console.error('Signup network error:', error);
            showError('Network error. Please check your internet connection and try again.');
        } finally {
            // Reset UI state
            signupBtn.disabled = false;
            signupBtn.innerHTML = '<span class="btn-text">Create Account</span>';
            signupBtn.classList.remove('loading');
        }
    });

    // Auto-advance to next field on Enter key
    const inputs = document.querySelectorAll('input');
    inputs.forEach((input, index) => {
        input.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                if (index < inputs.length - 1) {
                    inputs[index + 1].focus();
                } else {
                    // If last input, submit form
                    signupForm.dispatchEvent(new Event('submit'));
                }
            }
        });
    });

    // Input focus effects
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

    // Add security logging
    console.log('Signup page security initialized:', new Date().toISOString());
});

// Additional security features
window.addEventListener('beforeunload', function() {
    // Clear sensitive data from memory
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    passwordInputs.forEach(input => {
        input.value = '';
    });
});

// Prevent form resubmission on page refresh
if (window.history.replaceState) {
    window.history.replaceState(null, null, window.location.href);
}

// Password visibility toggle (optional enhancement)
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
    input.setAttribute('type', type);
}

// Export functions for testing (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        checkPasswordStrength,
        validateEmail,
        validateUsername,
        sanitizeInput,
        validateFormData
    };
}
