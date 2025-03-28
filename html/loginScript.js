// Check authentication status on page load
async function checkAuthStatus() {
    try {
      const response = await fetch('http://localhost:3000/check-auth', {
        credentials: 'include',
      });
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      const data = await response.json();
      const loginButton = document.getElementById('login-button');
      const userDisplay = document.getElementById('user-display');
      const loginForm = document.getElementById('loginForm');
      const changePasswordForm = document.getElementById('changePasswordForm');
  
      if (data.authenticated) {
        // Hide login form, show change password form on login.html
        if (loginForm && changePasswordForm) {
            loginForm.style.display = 'none';
            changePasswordForm.style.display = 'block';
        }
        // Update button based on role
        if (data.isAdmin) {
            loginButton.innerHTML = 'Admin Panel';
            loginButton.onclick = () => window.location.href = 'admin.html';
        } else {
            loginButton.innerHTML = 'Change Password';
            loginButton.onclick = () => window.location.href = 'login.html';
        }
        userDisplay.textContent = data.email; // Show logged-in user's email
      } else {
            if (loginForm && changePasswordForm) {
                loginForm.style.display = 'block';
                changePasswordForm.style.display = 'none';
            }
            loginButton.innerHTML = '<a href="login.html">Login</a>';
            loginButton.onclick = null; // Clear any previous onclick
            userDisplay.textContent = 'Guest'; // Show "guest" when not logged in
        }
    } catch (error) {
      console.error('Error checking auth status:', error);
    }
}
  
// Handle login form submission
function setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
  
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const csrfToken = document.getElementById('csrf-token-login').value;
        const errorMessage = document.getElementById('login-error');
  
        try {
          const response = await fetch('http://localhost:3000/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, _csrf: csrfToken }),
            credentials: 'include',
          });
  
          const data = await response.json();
  
          if (!response.ok) {
            errorMessage.textContent = data.error || 'Invalid email or password';
            return;
          }
  
          errorMessage.textContent = '';
          await checkAuthStatus();
          if (data.isAdmin) {
            window.location.href = 'admin.html';
          } else {
            window.location.href = 'index.html';
          }
        } catch (error) {
          errorMessage.textContent = 'An error occurred. Please try again.';
          console.error('Login error:', error);
        }
      });
    }
}
  
// Handle password change form submission
function setupChangePasswordForm() {
    const changePasswordForm = document.getElementById('changePasswordForm');
    if (changePasswordForm) {
      changePasswordForm.addEventListener('submit', async (e) => {
        e.preventDefault();
  
        const currentPassword = document.getElementById('current-password').value;
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const csrfToken = document.getElementById('csrf-token-change').value;
        const errorMessage = document.getElementById('change-password-error');
  
        if (newPassword !== confirmPassword) {
          errorMessage.textContent = 'New passwords do not match';
          return;
        }
  
        try {
          const response = await fetch('http://localhost:3000/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ currentPassword, newPassword, _csrf: csrfToken }),
            credentials: 'include',
          });
  
          const data = await response.json();
  
          if (!response.ok) {
            errorMessage.textContent = data.error || 'Error changing password';
            return;
          }
  
          await logout(); // Logout after successful password change
        } catch (error) {
          errorMessage.textContent = 'An error occurred. Please try again.';
          console.error('Password change error:', error);
        }
      });
    }
}
  
// Logout function
async function logout() {
    try {
      await fetch('http://localhost:3000/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ _csrf: document.getElementById('csrf-token-change')?.value || '' }),
        credentials: 'include',
      });
      window.location.href = 'login.html';
    } catch (error) {
      console.error('Logout error:', error);
    }
}
  
// Check auth status on page load
window.onload = async function () {
    checkAuthStatus();
    setupLoginForm();
    setupChangePasswordForm();
    loadCart();
    loadCategories();
    console.log(isAdminPage)
    if (isAdminPage) {
      console.log('admin')
      /* loadCategoriesAddSelect();
      loadProductsUpdateSelect();
      loadProductsDeleteSelect(); */

      const response = await fetch('http://localhost:3000/check-auth', { credentials: 'include' });
      const data = await response.json();
      if (!data.authenticated || !data.isAdmin) {
          window.location.href = 'login.html';
      } else {
          loadCategoriesAddSelect();
          loadProductsUpdateSelect();
          loadProductsDeleteSelect();
      } 
    }
};