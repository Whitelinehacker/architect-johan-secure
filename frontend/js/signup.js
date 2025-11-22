// Add API base URL
const API_BASE_URL = 'https://architect-johan-secure.onrender.com';

document.addEventListener('DOMContentLoaded', function() {
    const signupForm = document.getElementById('signup-form');
    const signupBtn = document.getElementById('signup-btn');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const csrfTokenInput = document.getElementById('csrf_token');

    // Get CSRF token
    fetch(`${API_BASE_URL}/api/csrf-token`)
        .then(response => response.json())
        .then(data => {
            csrfTokenInput.value = data.csrf_token;
        });

    // Password confirmation validation
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');

    confirmPasswordInput.addEventListener('input', function() {
        if (passwordInput.value !== confirmPasswordInput.value) {
            confirmPasswordInput.style.borderColor = '#FF004C';
        } else {
            confirmPasswordInput.style.borderColor = '#00FFB3';
        }
    });

    // Mobile number validation (only numbers)
    const mobileInput = document.getElementById('mobile_no');
    mobileInput.addEventListener('input', function() {
        this.value = this.value.replace(/[^0-9]/g, '');
    });

    signupForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = {
            username: document.getElementById('username').value.trim(),
            full_name: document.getElementById('full_name').value.trim(),
            email: document.getElementById('email').value.trim(),
            mobile_no: '+91' + document.getElementById('mobile_no').value.trim(),
            password: document.getElementById('password').value,
            confirm_password: document.getElementById('confirm_password').value,
            csrf_token: csrfTokenInput.value
        };

        // Validate required fields
        if (!formData.username || !formData.full_name || !formData.email || !formData.mobile_no || !formData.password) {
            showError('Please fill in all required fields');
            return;
        }

        // Validate passwords match
        if (formData.password !== formData.confirm_password) {
            showError('Passwords do not match');
            confirmPasswordInput.focus();
            return;
        }

        // Validate password length
        if (formData.password.length < 8) {
            showError('Password must be at least 8 characters long');
            passwordInput.focus();
            return;
        }

        // Validate mobile number
        if (formData.mobile_no.replace('+91', '').length !== 10) {
            showError('Please enter a valid 10-digit mobile number');
            mobileInput.focus();
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(formData.email)) {
            showError('Please enter a valid email address');
            document.getElementById('email').focus();
            return;
        }

        signupBtn.disabled = true;
        signupBtn.innerHTML = '<span class="btn-text">Creating Account...</span>';

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
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 2000);
            } else {
                showError(data.error || 'Registration failed');
            }
        } catch (error) {
            showError('Network error. Please try again.');
        } finally {
            signupBtn.disabled = false;
            signupBtn.innerHTML = '<span class="btn-text">Create Account</span>';
        }
    });

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.add('show');
        successMessage.classList.remove('show');
        
        const card = document.getElementById('signup-card');
        card.classList.add('shake');
        setTimeout(() => card.classList.remove('shake'), 500);
    }

    function showSuccess(message) {
        successMessage.textContent = message;
        successMessage.classList.add('show');
        errorMessage.classList.remove('show');
    }

    // Auto-advance to next field on Enter key
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

    // Auto-focus on first input
    document.getElementById('username').focus();
});