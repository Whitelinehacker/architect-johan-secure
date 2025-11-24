// signup.js - Enhanced with Gmail validation and OTP verification
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

// Gmail validation function
function validateGmail(email) {
    const gmailRegex = /^[a-zA-Z0-9.]+@gmail\.com$/;
    return gmailRegex.test(email);
}

// Disposable email domain check
function isDisposableEmail(email) {
    const disposableDomains = [
        'tempmail.com', 'guerrillamail.com', 'mailinator.com',
        '10minutemail.com', 'throwawaymail.com', 'fakeinbox.com',
        'yopmail.com', 'trashmail.com', 'temp-mail.org',
        'sharklasers.com', 'guerrillamail.biz', 'grr.la',
        'guerrillamail.org', 'guerrillamail.net', 'guerrillamail.de',
        'spam4.me', 'fake-mail.com', 'dispostable.com',
        'mailnesia.com', 'getairmail.com', 'maildrop.cc'
    ];
    
    const domain = email.split('@')[1].toLowerCase();
    return disposableDomains.includes(domain);
}

// Enhanced email validation
function validateEmailEnhanced(email) {
    if (!email) {
        return {
            isValid: false,
            error: 'Email is required'
        };
    }

    if (!validateGmail(email)) {
        return {
            isValid: false,
            error: 'Only Gmail accounts are allowed. Please use a valid Gmail address ending with @gmail.com'
        };
    }
    
    if (isDisposableEmail(email)) {
        return {
            isValid: false,
            error: 'Temporary/disposable email addresses are not allowed. Please use your personal Gmail account.'
        };
    }
    
    return { isValid: true };
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

// OTP Management
let otpCountdown = 0;
let otpTimer = null;

function startOTPTimer() {
    const sendOtpBtn = document.getElementById('send-otp-btn');
    const otpStatus = document.getElementById('otp-status');
    
    otpCountdown = 60;
    sendOtpBtn.disabled = true;
    
    otpTimer = setInterval(() => {
        otpCountdown--;
        sendOtpBtn.textContent = `Resend OTP (${otpCountdown}s)`;
        otpStatus.innerHTML = `<span style="color: #FF8A00">OTP sent! Valid for 10 minutes. Resend in ${otpCountdown}s</span>`;
        
        if (otpCountdown <= 0) {
            clearInterval(otpTimer);
            sendOtpBtn.disabled = false;
            sendOtpBtn.textContent = 'Resend OTP';
            otpStatus.innerHTML = '<span style="color: #FF004C">OTP expired. Click to resend.</span>';
        }
    }, 1000);
}

async function sendOTP() {
    const mobileInput = document.getElementById('mobile_no');
    const mobileNo = mobileInput.value;
    const sendOtpBtn = document.getElementById('send-otp-btn');
    const otpInput = document.getElementById('otp');
    const verifyOtpBtn = document.getElementById('verify-otp-btn');
    const otpStatus = document.getElementById('otp-status');

    // Validate mobile number first
    if (!mobileNo || mobileNo.length !== 10 || !/^[6-9]\d{9}$/.test(mobileNo)) {
        showError('Please enter a valid 10-digit Indian mobile number starting with 6-9');
        mobileInput.focus();
        return;
    }

    // Update UI for loading
    sendOtpBtn.disabled = true;
    sendOtpBtn.textContent = 'Sending OTP...';
    otpStatus.innerHTML = '<span style="color: #2EC6FF">Sending OTP via SMS...</span>';

    try {
        const response = await fetch(`${API_BASE_URL}/api/send-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                mobile_no: '+91' + mobileNo
            })
        });

        const data = await response.json();

        if (response.ok) {
            // Show OTP input field
            otpInput.style.display = 'block';
            verifyOtpBtn.style.display = 'block';
            otpInput.value = ''; // Clear previous OTP
            
            // Start countdown timer
            startOTPTimer();
            
            // Show success message
            if (data.otp) {
                // SMS failed, but OTP generated for testing
                otpStatus.innerHTML = `<span style="color: #FF8A00">SMS service issue. Use OTP: ${data.otp}</span>`;
                console.log(`📱 Test OTP (SMS failed): ${data.otp}`);
            } else {
                otpStatus.innerHTML = '<span style="color: #00FFB3">OTP sent via SMS! Check your phone.</span>';
            }
            
        } else {
            showError(data.error || 'Failed to send OTP');
            sendOtpBtn.disabled = false;
            sendOtpBtn.textContent = 'Send OTP';
        }
    } catch (error) {
        console.error('OTP sending error:', error);
        showError('Network error. Please check your connection and try again.');
        sendOtpBtn.disabled = false;
        sendOtpBtn.textContent = 'Send OTP';
        otpStatus.innerHTML = '<span style="color: #FF004C">Network error</span>';
    }
}

async function verifyOTP() {
    const mobileNo = document.getElementById('mobile_no').value;
    const otpInput = document.getElementById('otp');
    const otpValue = otpInput.value;
    const verifyOtpBtn = document.getElementById('verify-otp-btn');
    const otpStatus = document.getElementById('otp-status');

    if (!otpValue || otpValue.length !== 6 || !/^\d+$/.test(otpValue)) {
        showError('Please enter a valid 6-digit OTP');
        otpInput.focus();
        return;
    }

    // Update UI for loading
    verifyOtpBtn.disabled = true;
    verifyOtpBtn.textContent = 'Verifying...';
    otpStatus.innerHTML = '<span style="color: #2EC6FF">Verifying OTP...</span>';

    try {
        const response = await fetch(`${API_BASE_URL}/api/verify-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                mobile_no: '+91' + mobileNo,
                otp: otpValue
            })
        });

        const data = await response.json();

        if (response.ok) {
            // OTP verified successfully
            otpStatus.innerHTML = '<span style="color: #00FFB3">✅ Mobile number verified via SMS!</span>';
            verifyOtpBtn.textContent = 'Verified';
            verifyOtpBtn.disabled = true;
            verifyOtpBtn.style.background = '#00FFB3';
            verifyOtpBtn.style.color = '#02040A';
            
            // Store mobile verification status
            sessionStorage.setItem('mobile_verified', 'true');
            sessionStorage.setItem('verified_mobile', '+91' + mobileNo);
            sessionStorage.setItem('verified_at', new Date().toISOString());
            
            showSuccess('Mobile number verified successfully!');
            
            // Clear OTP timer
            if (otpTimer) {
                clearInterval(otpTimer);
            }
        } else {
            showError(data.error || 'Invalid OTP');
            verifyOtpBtn.disabled = false;
            verifyOtpBtn.textContent = 'Verify OTP';
            
            if (data.attempts_remaining) {
                otpStatus.innerHTML = `<span style="color: #FF004C">${data.error}</span>`;
            }
        }
    } catch (error) {
        console.error('OTP verification error:', error);
        showError('Network error during OTP verification');
        verifyOtpBtn.disabled = false;
        verifyOtpBtn.textContent = 'Verify OTP';
        otpStatus.innerHTML = '<span style="color: #FF004C">Network error</span>';
    }
}

// Check if mobile is already verified
function isMobileVerified() {
    return sessionStorage.getItem('mobile_verified') === 'true';
}

// Check social media verification
document.addEventListener('DOMContentLoaded', function() {
    // Enhanced social verification check
    function checkSocialVerification() {
        const sessionVerified = sessionStorage.getItem('social_verification') === 'completed';
        const localVerified = localStorage.getItem('social_verification');
        
        if (localVerified) {
            try {
                const status = JSON.parse(localVerified);
                if (status.youtube && status.telegram && status.instagram) {
                    return true;
                }
            } catch (e) {
                console.error('Error parsing social verification:', e);
            }
        }
        
        return sessionVerified;
    }

    // Check if user completed social verification
    if (!checkSocialVerification()) {
        showError('Please complete social media verification first. Redirecting to gateway...');
        setTimeout(() => {
            window.location.href = 'gateway.html';
        }, 3000);
        return;
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

    // Enhanced Gmail validation
    const emailValidation = validateEmailEnhanced(formData.email);
    if (!emailValidation.isValid) {
        return { isValid: false, error: emailValidation.error, field: 'email' };
    }

    // Validate mobile number
    const mobileDigits = formData.mobile_no.replace('+91', '');
    if (mobileDigits.length !== 10 || !/^[6-9]\d{9}$/.test(mobileDigits)) {
        return { isValid: false, error: 'Please enter a valid 10-digit Indian mobile number starting with 6-9', field: 'mobile_no' };
    }

    // Check mobile verification
    if (!isMobileVerified()) {
        return { isValid: false, error: 'Please verify your mobile number with OTP before signing up', field: 'mobile_no' };
    }

    // Check if mobile number matches verified number
    const verifiedMobile = sessionStorage.getItem('verified_mobile');
    if (verifiedMobile !== formData.mobile_no) {
        return { isValid: false, error: 'Mobile number does not match verified number. Please verify the correct number.', field: 'mobile_no' };
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
    // Check if user completed social verification
    if (!checkSocialVerification()) {
        showError('Please complete social media verification first. Redirecting to gateway...');
        setTimeout(() => {
            window.location.href = 'gateway.html';
        }, 3000);
        return;
    }

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
            
            // Reset OTP verification if mobile number changes
            const verifiedMobile = sessionStorage.getItem('verified_mobile');
            if (verifiedMobile && verifiedMobile !== '+91' + this.value) {
                resetOTPVerification();
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

    // Real-time email validation with Gmail check
    const emailInput = document.getElementById('email');
    if (emailInput) {
        emailInput.addEventListener('blur', function() {
            if (this.value) {
                const emailValidation = validateEmailEnhanced(this.value);
                if (!emailValidation.isValid) {
                    this.style.borderColor = '#FF004C';
                    showError(emailValidation.error);
                } else if (!validateEmail(this.value)) {
                    this.style.borderColor = '#FF004C';
                    showError('Please enter a valid email address');
                } else {
                    this.style.borderColor = '#00FFB3';
                }
            }
        });
        
        // Real-time Gmail validation
        emailInput.addEventListener('input', function() {
            if (this.value && !this.value.endsWith('@gmail.com')) {
                this.style.borderColor = '#FF8A00';
            } else if (this.value) {
                this.style.borderColor = '#00FFB3';
            }
        });
    }

    // OTP input validation
    const otpInput = document.getElementById('otp');
    if (otpInput) {
        otpInput.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
            if (this.value.length > 6) {
                this.value = this.value.slice(0, 6);
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
                
                // Clear verification status
                sessionStorage.removeItem('mobile_verified');
                sessionStorage.removeItem('verified_mobile');
                sessionStorage.removeItem('social_verification');
                
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
                    errorMessage += ' Please use a different Gmail or try logging in.';
                    document.getElementById('email').focus();
                } else if (errorMessage.includes('password')) {
                    document.getElementById('password').focus();
                } else if (errorMessage.includes('mobile')) {
                    document.getElementById('mobile_no').focus();
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
            signupBtn.innerHTML = '<span class="btn-text">Create Secure Account</span>';
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
    console.log('Secure signup page initialized:', new Date().toISOString());
});

// Reset OTP verification when mobile number changes
function resetOTPVerification() {
    const otpInput = document.getElementById('otp');
    const verifyOtpBtn = document.getElementById('verify-otp-btn');
    const otpStatus = document.getElementById('otp-status');
    
    if (otpTimer) {
        clearInterval(otpTimer);
    }
    
    otpInput.style.display = 'none';
    verifyOtpBtn.style.display = 'none';
    verifyOtpBtn.disabled = false;
    verifyOtpBtn.textContent = 'Verify OTP';
    verifyOtpBtn.style.background = '';
    verifyOtpBtn.style.color = '';
    otpStatus.innerHTML = '';
    
    sessionStorage.removeItem('mobile_verified');
    sessionStorage.removeItem('verified_mobile');
}

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

// Test MSG91 integration
async function testMSG91() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/test-msg91`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                mobile_no: '9999999999'
            })
        });
        const result = await response.json();
        console.log('MSG91 Test Result:', result);
        return result;
    } catch (error) {
        console.error('MSG91 Test Error:', error);
    }
}

// Export functions for testing (if needed)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        checkPasswordStrength,
        validateEmail,
        validateUsername,
        validateEmailEnhanced,
        validateGmail,
        isDisposableEmail,
        sanitizeInput,
        validateFormData
    };
}

