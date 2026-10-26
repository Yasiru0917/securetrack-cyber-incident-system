const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { after, before, test } = require('node:test');
const mongoose = require('mongoose');
const Incident = require('../models/Incident');
const User = require('../models/User');

const port = 5102;
const databaseName = `securetrack_qa_${Date.now()}`;
const mongoUri = `mongodb://127.0.0.1:27017/${databaseName}`;
const baseUrl = `http://127.0.0.1:${port}`;
const bootstrapKey = 'qa-bootstrap-key-only';
let server;
let adminToken;
let userToken;
let otherUserToken;
let incident;
const concurrentIncidents = [];

async function apiRequest(endpoint, { method = 'GET', body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${baseUrl}${endpoint}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try {
    data = await response.json();
  } catch {}
  return { response, data };
}

before(async () => {
  await mongoose.connect(mongoUri);
  server = spawn(process.execPath, ['server.js'], {
    cwd: path.resolve(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(port),
      MONGODB_URI: mongoUri,
      JWT_SECRET: `qa-jwt-secret-${Date.now()}`,
      ADMIN_BOOTSTRAP_KEY: bootstrapKey,
    },
    stdio: 'ignore',
  });

  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) {
      throw new Error(`QA backend exited with code ${server.exitCode}`);
    }
    try {
      const { response, data } = await apiRequest('/health');
      if (response.ok && data.database === 'connected') return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error('QA backend did not become healthy within 20 seconds');
});

after(async () => {
  if (server && server.exitCode === null) {
    server.kill();
    await new Promise((resolve) => server.once('exit', resolve));
  }
  await mongoose.connect(mongoUri);
  await mongoose.connection.dropDatabase();
  await mongoose.disconnect();
});

test('SecureTrack API integration', async (t) => {
  const unique = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
  const adminEmail = `admin_${unique}@qa.example`;
  const userEmail = `user_${unique}@qa.example`;
  const otherEmail = `other_${unique}@qa.example`;
  const password = 'QA-Passphrase-123';

  await t.test('health and registration validation', async () => {
    const health = await apiRequest('/health');
    assert.equal(health.response.status, 200);
    assert.equal(health.data.database, 'connected');
    assert.equal((await apiRequest('/register', { method: 'POST', body: {} })).response.status, 400);
    assert.equal((await apiRequest('/register', { method: 'POST', body: { name: 'QA', email: 'invalid', password } })).response.status, 400);
    assert.equal((await apiRequest('/register', { method: 'POST', body: { name: 'QA', email: userEmail, password: 'short' } })).response.status, 400);
    assert.equal((await apiRequest('/register', { method: 'POST', body: { name: 'QA', email: userEmail, password, confirmPassword: 'mismatch' } })).response.status, 400);
    assert.equal((await apiRequest('/register', { method: 'POST', body: { name: 'N'.repeat(101), email: userEmail, password } })).response.status, 400);

    const malformedJson = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{',
    });
    assert.equal(malformedJson.status, 400);
    assert.equal(malformedJson.headers.get('content-type').includes('application/json'), true);
    assert.deepEqual(await malformedJson.json(), { message: 'Invalid JSON request body' });

    const oversizedBody = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ oversized: 'x'.repeat(1024 * 1024 + 1) }),
    });
    assert.equal(oversizedBody.status, 413);
    assert.deepEqual(await oversizedBody.json(), { message: 'Request body is too large' });
  });

  await t.test('admin bootstrap and login validation', async () => {
    const created = await apiRequest('/create-admin', {
      method: 'POST',
      body: { name: 'QA Admin', email: adminEmail, password, bootstrapKey },
    });
    assert.equal(created.response.status, 201);
    assert.equal((await apiRequest('/create-admin', {
      method: 'POST',
      body: { name: 'Other Admin', email: `other_admin_${unique}@qa.example`, password, bootstrapKey: 'wrong' },
    })).response.status, 403);

    const login = await apiRequest('/login', { method: 'POST', body: { email: adminEmail, password } });
    assert.equal(login.response.status, 200);
    assert.ok(login.data.token);
    assert.equal(Object.hasOwn(login.data.user, 'password'), false);
    adminToken = login.data.token;
    assert.equal((await apiRequest('/login', { method: 'POST', body: { email: adminEmail, password: 'incorrect' } })).response.status, 401);
    assert.equal((await apiRequest('/login', { method: 'POST', body: { email: `missing_${unique}@qa.example`, password } })).response.status, 401);
    assert.equal((await apiRequest('/login', { method: 'POST', body: {} })).response.status, 400);
  });

  await t.test('user registration, password hashing, and role restrictions', async () => {
    const registered = await apiRequest('/register', {
      method: 'POST',
      body: { name: 'QA User', email: userEmail, password, confirmPassword: password, role: 'admin' },
    });
    assert.equal(registered.response.status, 201);
    assert.equal(registered.data.user.role, 'user');
    assert.equal(Object.hasOwn(registered.data.user, 'password'), false);
    userToken = registered.data.token;
    assert.equal((await apiRequest('/register', {
      method: 'POST',
      body: { name: 'Duplicate', email: userEmail, password },
    })).response.status, 409);

    const other = await apiRequest('/register', {
      method: 'POST',
      body: { name: 'Other User', email: otherEmail, password },
    });
    assert.equal(other.response.status, 201);
    otherUserToken = other.data.token;

    const storedUser = await User.findOne({ email: userEmail }).lean();
    assert.match(storedUser.password, /^\$2[aby]\$/);
    assert.ok(storedUser.createdAt instanceof Date);
    assert.ok(storedUser.updatedAt instanceof Date);
    const profile = await apiRequest('/me', { token: userToken });
    assert.equal(Object.hasOwn(profile.data, 'password'), false);
  });

  await t.test('authentication and administrator authorization', async () => {
    assert.equal((await apiRequest('/incidents')).response.status, 401);
    assert.equal((await apiRequest('/incidents', { token: 'invalid.token' })).response.status, 401);
    assert.equal((await apiRequest('/admin/stats', { token: userToken })).response.status, 403);
    assert.equal((await apiRequest('/users', { token: userToken })).response.status, 403);
    assert.equal((await apiRequest('/users/not-an-object-id', { method: 'PUT', token: adminToken, body: { name: 'bad' } })).response.status, 400);
    const ownUser = (await apiRequest('/me', { token: userToken })).data;
    assert.equal((await apiRequest(`/users/${ownUser.id}`, {
      method: 'PUT', token: userToken, body: { role: 'admin' },
    })).response.status, 400);
    assert.equal((await apiRequest('/me', { token: userToken })).data.role, 'user');
  });

  await t.test('incident creation, ownership, search, and filters', async () => {
    const created = await apiRequest('/incidents', {
      method: 'POST',
      token: userToken,
      body: { type: 'Phishing', severity: 'High', description: 'Isolated QA marker for incident search' },
    });
    assert.equal(created.response.status, 201);
    incident = created.data.incident;
    assert.ok(incident.createdAt);
    assert.ok(incident.updatedAt);
    assert.match(incident.incidentId, /^INC-\d+-[A-F0-9]{8}$/);
    assert.equal(String(incident.reportedBy), (await apiRequest('/me', { token: userToken })).data.id);
    assert.equal((await apiRequest('/incidents', { token: userToken })).data.length, 1);
    assert.equal((await apiRequest('/incidents', { token: otherUserToken })).data.length, 0);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, { token: otherUserToken })).response.status, 403);
    assert.equal((await apiRequest('/incidents', {
      method: 'POST', token: userToken, body: { type: 'Phishing', severity: 'Invalid', description: 'bad' },
    })).response.status, 400);
    assert.equal((await apiRequest('/incidents', {
      method: 'POST', token: userToken, body: { type: 'unknown', severity: 'High', description: 'bad' },
    })).response.status, 400);
    assert.equal((await apiRequest('/incidents', {
      method: 'POST', token: userToken, body: { type: 'Phishing' },
    })).response.status, 400);
    assert.equal((await apiRequest('/incidents', {
      method: 'POST', token: userToken, body: { type: 'Phishing', severity: 'High', description: 'x'.repeat(5001) },
    })).response.status, 400);

    const concurrentResults = await Promise.all(Array.from({ length: 5 }, (_, index) => apiRequest('/incidents', {
      method: 'POST',
      token: userToken,
      body: { type: 'phishing', severity: 'Low', description: `Concurrent QA report ${index}` },
    })));
    assert.ok(concurrentResults.every((result) => result.response.status === 201));
    concurrentIncidents.push(...concurrentResults.map((result) => result.data.incident));
    assert.equal(new Set(concurrentResults.map((result) => result.data.incident.incidentId)).size, concurrentResults.length);
    for (const concurrentIncident of concurrentIncidents) {
      const deleted = await apiRequest(`/incidents/${concurrentIncident._id}`, { method: 'DELETE', token: adminToken });
      assert.equal(deleted.response.status, 200);
    }
    concurrentIncidents.length = 0;

    assert.equal((await apiRequest(`/incidents?search=${encodeURIComponent(incident.incidentId)}`, { token: adminToken })).data.length, 1);
    assert.equal((await apiRequest('/incidents?search=Isolated%20QA%20marker', { token: adminToken })).data.length, 1);
    assert.equal((await apiRequest('/incidents?severity=High', { token: adminToken })).data.length, 1);
    assert.equal((await apiRequest('/incidents?status=Pending', { token: adminToken })).data.length, 1);
    assert.equal((await apiRequest('/incidents?status=Resolved&severity=Low', { token: adminToken })).data.length, 0);
    assert.equal((await apiRequest('/incidents?search=%5B', { token: adminToken })).response.status, 200);
    assert.equal((await apiRequest('/incidents?search=Unknown', { token: adminToken })).data.length, 0);
    assert.equal((await apiRequest('/incidents?status=NotAStatus', { token: adminToken })).response.status, 400);
    assert.equal((await apiRequest(`/incidents?search=${'x'.repeat(101)}`, { token: adminToken })).response.status, 400);
  });

  await t.test('incident update, notes, and statistics', async () => {
    const originalId = incident._id;
    const originalReference = incident.incidentId;
    const userUpdate = await apiRequest(`/incidents/${incident._id}`, {
      method: 'PATCH',
      token: userToken,
      body: { description: 'Edited by owner', severity: 'Medium' },
    });
    assert.equal(userUpdate.response.status, 200);
    assert.equal(userUpdate.data.incident._id, originalId);
    assert.equal(userUpdate.data.incident.incidentId, originalReference);
    assert.equal(userUpdate.data.incident.description, 'Edited by owner');
    assert.equal(userUpdate.data.incident.severity, 'Medium');
    assert.equal(userUpdate.data.incident.status, 'Pending');
    assert.equal((await Incident.countDocuments({ _id: originalId })), 1);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, { token: userToken })).data.description, 'Edited by owner');
    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PATCH', token: otherUserToken, body: { description: 'Cross-user edit' },
    })).response.status, 403);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PATCH', token: userToken, body: { status: 'Resolved' },
    })).response.status, 403);
    assert.equal((await apiRequest(`/incidents/${incident._id}/status`, {
      method: 'PATCH', token: userToken, body: { status: 'Resolved' },
    })).response.status, 403);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PATCH', token: userToken, body: { reportedBy: '65f000000000000000000000' },
    })).response.status, 400);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PATCH', token: userToken, body: { severity: 'Invalid' },
    })).response.status, 400);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PATCH', token: userToken, body: { description: '' },
    })).response.status, 400);

    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PUT', token: userToken, body: { status: 'Resolved' },
    })).response.status, 403);
    assert.equal((await apiRequest(`/incidents/${incident._id}/notes`, {
      method: 'PUT', token: userToken, body: { investigationNotes: 'unauthorized' },
    })).response.status, 403);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PUT', token: adminToken, body: { status: 'Unknown' },
    })).response.status, 400);
    assert.equal((await apiRequest(`/incidents/${incident._id}/status`, {
      method: 'PATCH', token: adminToken, body: { status: 'Unknown' },
    })).response.status, 400);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, {
      method: 'PUT', token: adminToken, body: { investigationNotes: 'x'.repeat(5001) },
    })).response.status, 400);

    let update = await apiRequest(`/incidents/${incident._id}`, {
      method: 'PATCH',
      token: adminToken,
      body: { description: 'Edited by administrator', severity: 'High', status: 'Investigating', investigationNotes: 'Initial QA notes' },
    });
    assert.equal(update.response.status, 200);
    assert.equal(update.data.incident.description, 'Edited by administrator');
    assert.equal(update.data.incident.status, 'Investigating');
    assert.equal(update.data.incident.investigationNotes, 'Initial QA notes');
    update = await apiRequest(`/incidents/${incident._id}/status`, {
      method: 'PATCH', token: adminToken, body: { status: 'Resolved' },
    });
    assert.equal(update.response.status, 200);
    assert.equal(update.data.incident.status, 'Resolved');
    assert.equal((await apiRequest(`/incidents/${incident._id}`, { token: adminToken })).data.status, 'Resolved');
    update = await apiRequest(`/incidents/${incident._id}`, {
      method: 'PUT', token: adminToken, body: { status: 'Investigating', investigationNotes: 'Initial QA notes' },
    });
    assert.equal(update.response.status, 200);
    assert.equal(update.data.incident.status, 'Investigating');
    update = await apiRequest(`/incidents/${incident._id}`, {
      method: 'PUT', token: adminToken, body: { status: 'Resolved', investigationNotes: 'Final QA notes' },
    });
    assert.equal(update.data.incident.status, 'Resolved');
    assert.equal((await apiRequest(`/incidents/${incident._id}`, { token: adminToken })).data.investigationNotes, 'Final QA notes');

    const stats = await apiRequest('/admin/stats', { token: adminToken });
    assert.equal(stats.data.total, 1);
    assert.equal(stats.data.resolved, 1);
    assert.equal(stats.data.high, 1);
    const users = await apiRequest('/users', { token: adminToken });
    assert.ok(users.data.every((user) => !Object.hasOwn(user, 'password')));
  });

  await t.test('malformed IDs and authorized deletion', async () => {
    assert.equal((await apiRequest('/incidents/not-an-object-id', { token: adminToken })).response.status, 400);
    assert.equal((await apiRequest('/incidents/not-an-object-id', {
      method: 'PATCH', token: adminToken, body: { status: 'Resolved' },
    })).response.status, 400);
    assert.equal((await apiRequest('/incidents/not-an-object-id', {
      method: 'PUT', token: adminToken, body: { status: 'Resolved' },
    })).response.status, 400);
    assert.equal((await apiRequest('/incidents/not-an-object-id/notes', {
      method: 'PUT', token: adminToken, body: { investigationNotes: 'bad' },
    })).response.status, 400);
    assert.equal((await apiRequest(`/incidents/${incident._id}`, { method: 'DELETE', token: otherUserToken })).response.status, 403);

    const ownIncident = await apiRequest('/incidents', {
      method: 'POST',
      token: userToken,
      body: { type: 'phishing', severity: 'Low', description: 'Owner deletion QA incident' },
    });
    assert.equal(ownIncident.response.status, 201);
    const ownerDelete = await apiRequest(`/incidents/${ownIncident.data.incident._id}`, {
      method: 'DELETE',
      token: userToken,
    });
    assert.equal(ownerDelete.response.status, 200);
    assert.equal((await Incident.findById(ownIncident.data.incident._id)), null);

    assert.equal((await apiRequest(`/incidents/${incident._id}`, { method: 'DELETE', token: adminToken })).response.status, 200);
    incident = null;
    assert.equal((await apiRequest('/incidents', { token: adminToken })).data.length, 0);
    assert.equal((await apiRequest('/incidents/65f000000000000000000000', { method: 'DELETE', token: adminToken })).response.status, 404);
  });
});
