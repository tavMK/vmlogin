const API_BASE = 'http://localhost:5000';

// DOM Elements
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const dashboard = document.getElementById('dashboard');
const messageDiv = document.getElementById('message');

// Social Login URLs
const socialAuthUrls = {
    google: `${API_BASE}/auth/google`,
    instagram: `${API_BASE}/auth/instagram`,
    facebook: `${API_BASE}/auth/facebook`,
    github: `${API_BASE}/auth/github`,
    linkedin: `${API_BASE}/auth/linkedin`
};

// Initialize app
function init() {
    checkAuth();
    handleAuthCallback();
}

// Show login form
function showLogin() {
    loginForm.classList.remove('hidden');
    registerForm.classList.add('hidden');
    dashboard.classList.add('hidden');
}

// Show register form
function showRegister() {
    loginForm.classList.add('hidden');
    registerForm.classList.remove('hidden');
    dashboard.classList.add('hidden');
}

// Show dashboard
function showDashboard(user) {
    loginForm.classList.add('hidden');
    registerForm.classList.add('hidden');
    dashboard.classList.remove('hidden');
    
    document.getElementById('userName').textContent = user.name || user.username || 'User';
    document.getElementById('userEmail').textContent = user.email || 'Not provided';
    document.getElementById('userProvider').textContent = user.provider || 'email';
    
    // Set profile picture if available
    const profilePic = document.getElementById('userPicture');
    if (user.picture) {
        profilePic.src = user.picture;
        profilePic.style.display = 'block';
    } else {
        profilePic.style.display = 'none';
    }
    
    // Update connected accounts
    updateConnectedAccounts(user);
}

// Update connected accounts display
function updateConnectedAccounts(user) {
    const accountsList = document.getElementById('accountsList');
    const connectedAccounts = document.getElementById('connectedAccounts');
    
    if (user.provider && user.provider !== 'email') {
        accountsList.innerHTML = `
            <div class="account-badge ${user.provider}">
                <i class="fab fa-${user.provider}"></i>
                ${user.provider.charAt(0).toUpperCase() + user.provider.slice(1)}
            </div>
        `;
        connectedAccounts.style.display = 'block';
    } else {
        connectedAccounts.style.display = 'none';
    }
}

// Show message
function showMessage(message, type = 'info') {
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.classList.remove('hidden');
    
    setTimeout(() => {
        messageDiv.classList.add('hidden');
    }, 5000);
}

// Regular Login
document.getElementById('loginFormElement').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    try {
        const response = await fetch(`${API_BASE}/api/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password }),
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            showDashboard(data.user);
            showMessage('Login successful!', 'success');
        } else {
            showMessage(data.message, 'error');
        }
    } catch (error) {
        showMessage('Network error. Please try again.', 'error');
    }
});

// Regular Register
document.getElementById('registerFormElement').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const name = document.getElementById('registerName').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;

    try {
        const response = await fetch(`${API_BASE}/api/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, email, password }),
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            showDashboard(data.user);
            showMessage('Registration successful!', 'success');
        } else {
            showMessage(data.message, 'error');
        }
    } catch (error) {
        showMessage('Network error. Please try again.', 'error');
    }
});

// Social Login
function socialLogin(provider) {
    window.location.href = socialAuthUrls[provider];
}

// Handle social auth callback
function handleAuthCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    const provider = urlParams.get('provider');

    if (token && provider) {
        localStorage.setItem('token', token);
        
        // Fetch user profile
        fetchUserProfile(token);
        
        // Clean URL
        window.history.replaceState({}, document.title, window.location.pathname);
    }
}

// Fetch user profile after social login
async function fetchUserProfile(token) {
    try {
        const response = await fetch(`${API_BASE}/api/profile`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            const data = await response.json();
            localStorage.setItem('user', JSON.stringify(data.user));
            showDashboard(data.user);
            showMessage(`Successfully logged in with ${data.user.provider}!`, 'success');
        } else {
            showMessage('Failed to fetch user profile', 'error');
        }
    } catch (error) {
        showMessage('Network error. Please try again.', 'error');
    }
}

// Check if user is already logged in
function checkAuth() {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        showDashboard(JSON.parse(user));
    } else {
        showLogin();
    }
}

// Logout function
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    showLogin();
    showMessage('Logged out successfully', 'success');
}

// Initialize the application
init();