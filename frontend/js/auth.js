// Add API base URL
const API_BASE_URL = 'https://architect-johan-secure.onrender.com';

// Authentication management
class AuthManager {
    constructor() {
        this.csrfToken = '';
        this.inactivityTimer = null;
        this.INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes
        this.init();
    }

    async init() {
        await this.getCSRFToken();
        this.setupEventListeners();
        this.startInactivityTimer();
        this.checkExistingSession();
    }

    async getCSRFToken() {
        try {
            const response = await fetch(`${API_BASE_URL}/api/csrf-token`);
            const data = await response.json();
            this.csrfToken = data.csrf_token;
            document.getElementById('csrf_token').value = this.csrfToken;
        } catch (error) {
            console.error('Failed to get CSRF token:', error);
        }
    }

    storeToken(token) {
        localStorage.setItem('auth_token', token);
        localStorage.setItem('token_timestamp', Date.now().toString());
        sessionStorage.setItem('secure_session', 'true');
    }

    getToken() {
        const token = localStorage.getItem('auth_token');
        const timestamp = localStorage.getItem('token_timestamp');
        
        if (token && timestamp) {
            const age = Date.now() - parseInt(timestamp);
            if (age > 3600000) { // 1 hour
                this.clearToken();
                return null;
            }
        }
        
        return token;
    }

    clearToken() {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('token_timestamp');
        localStorage.removeItem('username');
        sessionStorage.clear();
    }

    async validateToken() {
        const token = this.getToken();
        if (!token) return false;

        try {
            const response = await fetch(`${API_BASE_URL}/api/validate-token`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            return response.ok;
        } catch (error) {
            return false;
        }
    }

    async login(username, password) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': this.csrfToken
                },
                body: JSON.stringify({
                    username: username,
                    password: password,
                    csrf_token: this.csrfToken
                })
            });

            const data = await response.json();

            if (response.ok) {
                this.storeToken(data.token);
                localStorage.setItem('username', data.username);
                this.csrfToken = data.csrf_token;
                return { success: true, data: data };
            } else {
                return { success: false, error: data.error };
            }
        } catch (error) {
            return { success: false, error: 'Network error' };
        }
    }

    async logout() {
        const token = this.getToken();
        
        if (token) {
            try {
                await fetch(`${API_BASE_URL}/api/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                console.error('Logout API call failed:', error);
            }
        }
        
        this.clearToken();
        window.location.href = 'index.html';
    }

    startInactivityTimer() {
        this.resetInactivityTimer();
        
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, () => this.resetInactivityTimer(), false);
        });
    }

    resetInactivityTimer() {
        clearTimeout(this.inactivityTimer);
        this.inactivityTimer = setTimeout(() => this.logoutDueToInactivity(), this.INACTIVITY_TIMEOUT);
    }

    logoutDueToInactivity() {
        if (this.getToken()) {
            alert('Session expired due to inactivity');
            this.logout();
        }
    }

    checkExistingSession() {
        const token = this.getToken();
        const currentPage = window.location.pathname;
        
        if (token && currentPage.includes('index.html')) {
            window.location.href = 'home.html';
        } else if (!token && !currentPage.includes('index.html')) {
            window.location.href = 'index.html';
        }
    }

    setupEventListeners() {
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                if (confirm('Are you sure you want to logout?')) {
                    this.logout();
                }
            });
        }
    }
}

// Initialize auth manager
const authManager = new AuthManager();