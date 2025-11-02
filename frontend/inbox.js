// frontend/inbox.js
import { apiGet, apiPost } from './js/api.js';

const username = localStorage.getItem('username');
document.getElementById('who').textContent = username ? `User: ${username}` : '';

document.getElementById('logout').onclick = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('username');
  window.location.href = 'login.html';
};
document.getElementById('goSend').onclick = () => window.location.href = 'send.html';

const API_BASE = 'http://127.0.0.1:5000';

async function loadInbox() {
  const res = await apiGet('/messages/inbox');
  const list = document.getElementById('list');
  list.innerHTML = '';
  (res.messages || []).forEach(m => {
    const div = document.createElement('div');
    div.className = 'card';
    const badge = m.is_one_time ? '<span class="badge">One-time</span>' : (m.expires_at ? `<span class="badge">Expires ${m.expires_at}</span>` : '');
    const sigFlag = m.has_signature ? '<span class="badge">Signed</span>' : '';
    div.innerHTML = `
      <div><b>From:</b> ${m.sender_username} ${badge} ${sigFlag} <span class="small"> ${m.timestamp || ''}</span></div>
      <div style="margin-top:8px;">
        <button data-id="${m.id}" class="btn-preview">Preview Image</button>
        <button data-id="${m.id}" class="btn-decrypt">Decrypt</button>
      </div>
      <div class="small" id="res_${m.id}"></div>
    `;
    list.appendChild(div);
  });

  // preview: fetch the stego image as blob and show modal (blurred). User must click decrypt to reveal message.
  document.querySelectorAll('.btn-preview').forEach(btn => {
    btn.onclick = async (e) => {
      const id = e.target.getAttribute('data-id');
      const token = localStorage.getItem('token');
      try {
        const resp = await fetch(`${API_BASE}/messages/download/${id}`, {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!resp.ok) return alert('Preview failed: ' + resp.status);
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);

        // create modal
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
          <div class="modal-content">
            <img id="preview_img" src="${url}" style="max-width:100%; filter: blur(8px);" />
            <div style="margin-top:10px;">
              <button id="btn_reveal">Enter password to decrypt</button>
              <button id="btn_close">Close</button>
            </div>
            <div id="preview_msg" style="margin-top:8px;"></div>
          </div>
        `;
        document.body.appendChild(modal);

        document.getElementById('btn_close').onclick = () => { modal.remove(); URL.revokeObjectURL(url); };
        document.getElementById('btn_reveal').onclick = async () => {
          const pwd = prompt('Enter your account password to decrypt:');
          if (!pwd) return;
          const outDiv = document.getElementById('preview_msg');
          outDiv.textContent = 'Decrypting...';
          try {
            const data = await apiPost(`/messages/decrypt/${id}`, { password: pwd });
            if (data.message) {
              outDiv.textContent = 'Message: ' + data.message + (data.signature_valid === true ? ' (Signature OK)' : (data.signature_valid === false ? ' (Signature FAILED)' : ''));
              // if message was one-time, the server deleted it; close modal
            } else {
              outDiv.textContent = 'Error: ' + (data.error || JSON.stringify(data));
            }
          } catch (err) {
            outDiv.textContent = 'Decrypt failed: ' + err.message;
          }
        };
      } catch (err) {
        alert('Preview error: ' + err.message);
      }
    };
  });

  // Decrypt button (no preview) — same password prompt flow
  document.querySelectorAll('.btn-decrypt').forEach(btn => {
    btn.onclick = async (e) => {
      const id = e.target.getAttribute('data-id');
      const pwd = prompt('Enter your account password to decrypt:');
      if (!pwd) return;
      const resBlock = document.getElementById('res_' + id);
      resBlock.textContent = 'Decrypting...';
      try {
        const res = await apiPost(`/messages/decrypt/${id}`, { password: pwd });
        if (res.message) {
          resBlock.textContent = 'Message: ' + res.message + (res.signature_valid === true ? ' (Signature OK)' : (res.signature_valid === false ? ' (Signature FAILED)' : ''));
        } else {
          resBlock.textContent = 'Error: ' + (res.error || JSON.stringify(res));
        }
      } catch (err) {
        resBlock.textContent = 'Decrypt failed: ' + err.message;
      }
    };
  });
}

loadInbox();
