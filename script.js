// User session management
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// DOM Elements
const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');

// Initialize forms if they exist
if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
}

if (registerForm) {
    registerForm.addEventListener('submit', handleRegister);
}

// Login handler
function handleLogin(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const user = {
        email: formData.get('email'),
        password: formData.get('password'),
        role: formData.get('role')
    };

    // Simple validation
    if (!user.email || !user.password || !user.role) {
        alert('Please fill all fields');
        return;
    }

    // Save to localStorage (in a real app, this would be an API call)
    currentUser = {
        ...user,
        name: 'Demo User', // Would come from DB in real app
        id: Date.now().toString()
    };
    localStorage.setItem('currentUser', JSON.stringify(currentUser));

    // Redirect based on role
    switch(user.role) {
        case 'customer':
            window.location.href = 'index.html';
            break;
        case 'vendor':
            window.location.href = 'vendor-dashboard.html';
            break;
        case 'admin':
            window.location.href = 'admin-dashboard.html';
            break;
    }
}

// Registration handler
function handleRegister(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    const accountType = formData.get('accountType');
    
    const user = {
        name: formData.get('name'),
        email: formData.get('email'),
        password: formData.get('password'),
        role: accountType,
        ...(accountType === 'vendor' && {
            businessName: formData.get('businessName'),
            businessDescription: formData.get('businessDescription')
        })
    };

    // Simple validation
    if (!user.name || !user.email || !user.password || !user.role) {
        alert('Please fill all required fields');
        return;
    }

    // Save to localStorage (in a real app, this would be an API call)
    currentUser = {
        ...user,
        id: Date.now().toString()
    };
    localStorage.setItem('currentUser', JSON.stringify(currentUser));

    // Redirect based on role
    if (user.role === 'customer') {
        window.location.href = 'index.html';
    } else {
        window.location.href = 'vendor-dashboard.html';
    }
}

// Logout function
function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'login.html';
}

// Check authentication on page load
function checkAuth() {
    if (!currentUser && !['login.html', 'register.html'].includes(window.location.pathname.split('/').pop())) {
        window.location.href = 'login.html';
    }
}

// Initialize auth check
window.addEventListener('DOMContentLoaded', checkAuth);