// frontend/login.js
import { apiPost } from './js/api.js';

document.getElementById('btnLogin').onclick = async () => {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  if (!username || !password) return alert('Enter credentials');

  try {
    const res = await apiPost('/auth/login', { username, password });
    if (res.access_token) {
      localStorage.setItem('token', res.access_token);
      localStorage.setItem('username', username);
      // redirect to send page by default
      window.location.href = 'send.html';
    } else {
      alert(res.error || 'Login failed');
    }
  } catch (e) {
    alert('Login error: ' + e.message);
  }
};

document.getElementById('btnRegister').onclick = async () => {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  if (!username || !password) return alert('Enter credentials');

  try {
    const res = await apiPost('/auth/register', { username, password });
    if (res.status === 'ok') {
      alert('Registered. Now login.');
    } else {
      alert(res.error || 'Register failed');
    }
  } catch (e) {
    alert('Register error: ' + e.message);
  }
};
