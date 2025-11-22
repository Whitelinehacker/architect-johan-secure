// Security utilities
class SecurityUtils {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        
        return input
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;')
            .trim();
    }

    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static validatePassword(password) {
        // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special character
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        return passwordRegex.test(password);
    }

    static getPasswordStrength(password) {
        let strength = 0;
        
        if (password.length >= 8) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[@$!%*?&]/.test(password)) strength++;
        
        return strength;
    }

    static generateSessionId() {
        return 'session_' + Math.random().toString(36).substr(2, 16) + Date.now().toString(36);
    }

    static encryptData(data, key) {
        // Simple XOR encryption for demonstration
        // In production, use Web Crypto API
        let result = '';
        for (let i = 0; i < data.length; i++) {
            result += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
        }
        return btoa(result);
    }

    static decryptData(encryptedData, key) {
        try {
            const data = atob(encryptedData);
            let result = '';
            for (let i = 0; i < data.length; i++) {
                result += String.fromCharCode(data.charCodeAt(i) ^ key.charCodeAt(i % key.length));
            }
            return result;
        } catch (error) {
            return null;
        }
    }
}

// Input validation for forms
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const inputs = this.querySelectorAll('input[required]');
            let isValid = true;
            
            inputs.forEach(input => {
                const value = SecurityUtils.sanitizeInput(input.value);
                
                if (!value) {
                    isValid = false;
                    this.showInputError(input, 'This field is required');
                } else {
                    this.clearInputError(input);
                }
                
                // Special validation for email fields
                if (input.type === 'email' && value) {
                    if (!SecurityUtils.validateEmail(value)) {
                        isValid = false;
                        this.showInputError(input, 'Please enter a valid email address');
                    }
                }
                
                // Password strength indicator
                if (input.type === 'password' && value) {
                    this.showPasswordStrength(input, value);
                }
            });
            
            if (!isValid) {
                e.preventDefault();
            }
        });
    });
});

// Enhanced login form handling
const loginForm = document.getElementById('login-form');
if (loginForm) {
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = SecurityUtils.sanitizeInput(document.getElementById('username').value);
        const password = document.getElementById('password').value;
        
        if (!username || !password) {
            showError('Please enter both username and password');
            return;
        }
        
        // Show loading state
        const loginBtn = document.getElementById('login-btn');
        const btnText = document.querySelector('.btn-text');
        
        loginBtn.disabled = true;
        btnText.textContent = 'AUTHENTICATING...';
        
        const result = await authManager.login(username, password);
        
        if (result.success) {
            handleSuccess();
        } else {
            handleError(result.error);
            await authManager.getCSRFToken();
        }
        
        loginBtn.disabled = false;
        btnText.textContent = 'Initialize Access';
    });
}

function handleSuccess() {
    const loginCard = document.getElementById('login-card');
    const loginBtn = document.getElementById('login-btn');
    const btnText = document.querySelector('.btn-text');
    const successMessage = document.getElementById('success-message');
    const successOverlay = document.getElementById('success-overlay');
    const errorMessage = document.getElementById('error-message');
    
    errorMessage.classList.remove('show');
    loginCard.classList.add('success');
    loginBtn.classList.add('success');
    btnText.textContent = 'ACCESS GRANTED';
    successMessage.classList.add('show');
    successOverlay.classList.add('show');
    
    document.getElementById('username').disabled = true;
    document.getElementById('password').disabled = true;
    loginBtn.disabled = true;
    
    setTimeout(() => { 
        window.location.href = 'home.html'; 
    }, 2000);
}

function handleError(message) {
    const loginCard = document.getElementById('login-card');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    
    successMessage.classList.remove('show');
    errorMessage.textContent = message || 'Access Denied — Invalid Credentials';
    errorMessage.classList.add('show');
    loginCard.classList.add('shake', 'glitch');
    
    setTimeout(() => {
        loginCard.classList.remove('shake', 'glitch');
    }, 500);
    
    setTimeout(() => {
        errorMessage.classList.remove('show');
    }, 4000);
    
    document.getElementById('password').value = '';
    document.getElementById('password').focus();
}