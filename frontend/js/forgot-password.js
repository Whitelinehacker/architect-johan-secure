// Add API base URL
const API_BASE_URL = 'https://architect-johan-secure.onrender.com';

document.addEventListener('DOMContentLoaded', function() {
    const forgotPasswordForm = document.getElementById('forgot-password-form');
    const resetBtn = document.getElementById('reset-btn');
    const errorMessage = document.getElementById('error-message');
    const successMessage = document.getElementById('success-message');
    const csrfTokenInput = document.getElementById('csrf_token');

    console.log('✅ Forgot password script loaded');
    console.log('✅ Form element:', forgotPasswordForm);
    console.log('✅ CSRF input:', csrfTokenInput);

    // Get CSRF token with better error handling
    fetch(`${API_BASE_URL}/api/csrf-token`)
        .then(response => {
            console.log('🔍 CSRF response status:', response.status);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log('🔍 CSRF response data:', data);
            if (data.csrf_token) {
                csrfTokenInput.value = data.csrf_token;
                console.log('✅ CSRF token set:', csrfTokenInput.value);
            } else {
                console.error('❌ No CSRF token in response');
            }
        })
        .catch(error => {
            console.error('❌ Error fetching CSRF token:', error);
            // Fallback: generate a simple token
            csrfTokenInput.value = 'fallback-token-' + Date.now();
            console.log('🔄 Using fallback token');
        });

    forgotPasswordForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        console.log('🎯 Form submission started');
        
        const email = document.getElementById('email').value.trim();
        console.log('📧 Email:', email);
        console.log('🔑 CSRF Token:', csrfTokenInput.value);
        
        if (!email) {
            showError('Please enter your email address');
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showError('Please enter a valid email address');
            return;
        }

        const formData = {
            email: email,
            csrf_token: csrfTokenInput.value
        };

        console.log('📤 Sending request with data:', formData);

        resetBtn.disabled = true;
        resetBtn.innerHTML = '<span class="btn-text">Sending Reset Link...</span>';

        try {
            const response = await fetch(`${API_BASE_URL}/api/forgot-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfTokenInput.value
                },
                body: JSON.stringify(formData)
            });

            console.log('📥 Response status:', response.status);
            const data = await response.json();
            console.log('📥 Response data:', data);

            if (response.ok) {
                console.log('✅ Request successful');
                if (data.reset_token) {
                    console.log('🔑 Reset token received:', data.reset_token);
                    showSuccess(`Reset link sent!<br><br>
                        <strong>Token:</strong> ${data.reset_token}<br><br>
                        <a href="reset-password.html?token=${data.reset_token}" 
                           style="color: #00FFB3; text-decoration: underline; font-weight: bold;">
                           Click here to reset password
                        </a>`);
                } else {
                    showSuccess(data.message || 'Reset link sent to your email! Check your inbox.');
                }
            } else {
                console.error('❌ Request failed:', data.error);
                showError(data.error || 'Failed to send reset link');
            }
        } catch (error) {
            console.error('💥 Fetch error:', error);
            showError('Network error. Please check your connection and try again.');
        } finally {
            resetBtn.disabled = false;
            resetBtn.innerHTML = '<span class="btn-text">Send Reset Link</span>';
        }
    });

    function showError(message) {
        console.log('❌ Showing error:', message);
        errorMessage.innerHTML = message;
        errorMessage.classList.add('show');
        successMessage.classList.remove('show');
        
        const card = document.getElementById('forgot-password-card');
        card.classList.add('shake');
        setTimeout(() => card.classList.remove('shake'), 500);
    }

    function showSuccess(message) {
        console.log('✅ Showing success:', message);
        successMessage.innerHTML = message;
        successMessage.classList.add('show');
        errorMessage.classList.remove('show');
    }

    // Enter key support
    document.getElementById('email').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            forgotPasswordForm.dispatchEvent(new Event('submit'));
        }
    });

    // Auto-focus on email field
    document.getElementById('email').focus();

    console.log('✅ Forgot password form fully initialized');
});