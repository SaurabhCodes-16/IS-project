// frontend/send.js
import { apiGet, apiPostForm } from './js/api.js';

const username = localStorage.getItem('username');
document.getElementById('who').textContent = username ? `User: ${username}` : '';

document.getElementById('logout').onclick = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  window.location.href = 'login.html';
};
document.getElementById('goInbox').onclick = () => window.location.href = 'inbox.html';

async function loadUsers() {
  const res = await apiGet('/users/list');
  const sel = document.getElementById('receiver');
  sel.innerHTML = '';
  (res.users || []).forEach(u => {
    const opt = document.createElement('option');
    opt.value = u.id;
    opt.textContent = u.username;
    sel.appendChild(opt);
  });
}
loadUsers();

document.getElementById('btnSend').onclick = async () => {
  const sel = document.getElementById('receiver');
  const receiver_id = sel.value;
  const message = document.getElementById('message').value;
  const coverInput = document.getElementById('cover');
  if (!receiver_id || !message || coverInput.files.length === 0) return alert('Fill all fields');

  const form = new FormData();
  form.append('receiver_id', receiver_id);
  form.append('message', message);
  form.append('cover', coverInput.files[0]);

  document.getElementById('status').textContent = 'Sending...';
  try {
    const res = await apiPostForm('/messages/send', form);
    if (res.status === 'ok') {
      document.getElementById('status').textContent = 'Message sent ✓';
    } else {
      document.getElementById('status').textContent = 'Error: ' + (res.error || JSON.stringify(res));
    }
  } catch (e) {
    document.getElementById('status').textContent = 'Send failed: ' + e.message;
  }
};
