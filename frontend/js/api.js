// frontend/js/api.js
const API_BASE = "http://127.0.0.1:5000";

export async function apiPost(path, body, isJSON = true) {
  const token = localStorage.getItem('token');
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (isJSON) headers['Content-Type'] = 'application/json';
  const res = await fetch(API_BASE + path, {
    method: 'POST',
    headers,
    body: isJSON ? JSON.stringify(body) : body
  });
  return res.json();
}

export async function apiGet(path) {
  const token = localStorage.getItem('token');
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API_BASE + path, { headers });
  return res.json();
}

export async function apiPostForm(path, formData) {
  const token = localStorage.getItem('token');
  const headers = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API_BASE + path, {
    method: 'POST',
    headers,
    body: formData
  });
  return res.json();
}
