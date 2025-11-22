// Add API base URL
const API_BASE_URL = 'https://architect-johan-secure.onrender.com';

document.addEventListener('DOMContentLoaded', function() {
    const resetPasswordForm = document.getElementById('reset-password-form');
    const resetPasswordBtn = document.getElementById('reset-password-btn');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const csrfTokenInput = document.getElementById('csrf_token');
    const resetTokenInput = document.getElementById('reset_token');
    const resetTokenDisplayInput = document.getElementById('reset_token_input');

    // Get CSRF token
    fetch(`${API_BASE_URL}/api/csrf-token`)
        .then(response => response.json())
        .then(data => {
            csrfTokenInput.value = data.csrf_token;
        });

    // Check if token is in URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    if (token) {
        resetTokenDisplayInput.value = token;
        resetTokenInput.value = token;
    }

    // Sync the token fields
    resetTokenDisplayInput.addEventListener('input', function() {
        resetTokenInput.value = this.value;
    });

    // Password confirmation validation
    const newPasswordInput = document.getElementById('new_password');
    const confirmPasswordInput = document.getElementById('confirm_password');

    confirmPasswordInput.addEventListener('input', function() {
        if (newPasswordInput.value !== confirmPasswordInput.value) {
            confirmPasswordInput.style.borderColor = '#FF004C';
        } else {
            confirmPasswordInput.style.borderColor = '#00FFB3';
        }
    });

    resetPasswordForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const formData = {
            reset_token: resetTokenInput.value,
            new_password: newPasswordInput.value,
            confirm_password: confirmPasswordInput.value,
            csrf_token: csrfTokenInput.value
        };

        // Validate passwords match
        if (formData.new_password !== formData.confirm_password) {
            showError('Passwords do not match');
            return;
        }

        // Validate password length
        if (formData.new_password.length < 8) {
            showError('Password must be at least 8 characters long');
            return;
        }

        resetPasswordBtn.disabled = true;
        resetPasswordBtn.innerHTML = '<span class="btn-text">Resetting Password...</span>';

        try {
            const response = await fetch(`${API_BASE_URL}/api/reset-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfTokenInput.value
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (response.ok) {
                showSuccess(data.message || 'Password reset successfully!');
                setTimeout(() => {
                    window.location.href = 'index.html';
                }, 2000);
            } else {
                showError(data.error || 'Password reset failed');
            }
        } catch (error) {
            showError('Network error. Please try again.');
        } finally {
            resetPasswordBtn.disabled = false;
            resetPasswordBtn.innerHTML = '<span class="btn-text">Reset Password</span>';
        }
    });

    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.add('show');
        successMessage.classList.remove('show');
        
        const card = document.getElementById('reset-password-card');
        card.classList.add('shake');
        setTimeout(() => card.classList.remove('shake'), 500);
    }

    function showSuccess(message) {
        successMessage.textContent = message;
        successMessage.classList.add('show');
        errorMessage.classList.remove('show');
    }
});