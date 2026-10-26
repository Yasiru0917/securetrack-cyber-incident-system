require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('node:crypto');

const Incident = require('./models/Incident');
const User = require('./models/User');

const app = express();
const PORT = Number(process.env.PORT) || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/securetrack';

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET must be configured before starting SecureTrack');
}

app.disable('x-powered-by');
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));

mongoose.set('strictQuery', true);

mongoose.connect(MONGODB_URI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch((error) => console.error('MongoDB connection error:', error.message));

function sanitizeText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeEmail(value) {
  return sanitizeText(value).toLowerCase();
}

function validateEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value || '');
}

const validIncidentTypes = [
  'phishing',
  'malware',
  'unauthorized',
  'data_breach',
  'suspicious',
  'Phishing',
  'Phishing Attack',
  'Malware Infection',
  'Unauthorized Access',
  'Data Breach',
  'Suspicious Activity',
];
const validSeverities = ['Low', 'Medium', 'High', 'Critical'];
const validStatuses = ['Pending', 'Investigating', 'Resolved'];

function ensureDatabase(req, res, next) {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ message: 'Database unavailable. Please try again later.' });
  }
  next();
}

function signToken(user) {
  return jwt.sign(
    {
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (error, user) => {
    if (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

function requireOwnerOrAdmin(req, res, next) {
  const resourceOwnerId = req.resourceOwnerId || null;

  if (!resourceOwnerId) {
    return next();
  }

  if (req.user.role === 'admin' || req.user.id === resourceOwnerId.toString()) {
    return next();
  }

  return res.status(403).json({ message: 'Access denied' });
}

app.get('/', (req, res) => {
  res.json({ name: 'SecureTrack API', status: 'running' });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

app.post('/register', ensureDatabase, async (req, res) => {
  const name = sanitizeText(req.body?.name);
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const confirmPassword = String(req.body?.confirmPassword || '');

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email and password are required' });
  }

  if (name.length > 100 || email.length > 254 || password.length > 128) {
    return res.status(400).json({ message: 'Name, email or password exceeds the allowed length' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ message: 'Please provide a valid email address' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long' });
  }

  if (password !== confirmPassword && confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: 'user',
    });

    const token = signToken(user);

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ message: 'Registration failed' });
  }
});

app.post('/login', ensureDatabase, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ message: 'Please provide a valid email address' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = signToken(user);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Login failed' });
  }
});

app.post('/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

app.get('/me', authenticateToken, ensureDatabase, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ message: 'Failed to load user profile' });
  }
});

app.get('/users', authenticateToken, requireAdmin, ensureDatabase, async (req, res) => {
  try {
    const users = await User.find({}).select('-password').sort({ createdAt: -1 });
    res.json(users.map((user) => ({
      id: user._id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
    })));
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ message: 'Failed to load users' });
  }
});

app.put('/users/:id', authenticateToken, ensureDatabase, async (req, res) => {
  const targetId = req.params.id;
  if (!mongoose.isValidObjectId(targetId)) {
    return res.status(400).json({ message: 'Invalid user ID' });
  }

  if (req.user.role !== 'admin' && req.user.id !== targetId) {
    return res.status(403).json({ message: 'You can only update your own profile' });
  }

  try {
    const updates = {};
    const newName = sanitizeText(req.body?.name);
    const newEmail = normalizeEmail(req.body?.email);

    if (newName.length > 100 || newEmail.length > 254) {
      return res.status(400).json({ message: 'Name or email exceeds the allowed length' });
    }

    if (newName) {
      updates.name = newName;
    }

    if (newEmail) {
      if (!validateEmail(newEmail)) {
        return res.status(400).json({ message: 'Please provide a valid email address' });
      }

      const duplicateUser = await User.findOne({ email: newEmail, _id: { $ne: targetId } });
      if (duplicateUser) {
        return res.status(409).json({ message: 'Email already registered' });
      }

      updates.email = newEmail;
    }

    if (req.user.role === 'admin' && req.body?.role) {
      const role = String(req.body.role).toLowerCase();
      if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({ message: 'Role must be either user or admin' });
      }
      updates.role = role;
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ message: 'No profile changes provided' });
    }

    const user = await User.findByIdAndUpdate(targetId, updates, { new: true }).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ message: 'Failed to update profile' });
  }
});

app.post('/incidents', authenticateToken, ensureDatabase, async (req, res) => {
  const type = sanitizeText(req.body?.type);
  const description = sanitizeText(req.body?.description);
  const severity = sanitizeText(req.body?.severity);

  if (!type || !description || !severity) {
    return res.status(400).json({ message: 'Type, description and severity are required' });
  }

  if (type.length > 100 || description.length > 5000) {
    return res.status(400).json({ message: 'Type must be 100 characters or fewer and description 5000 characters or fewer' });
  }

  if (!validIncidentTypes.includes(type)) {
    return res.status(400).json({ message: 'Invalid incident type' });
  }

  if (!validSeverities.includes(severity)) {
    return res.status(400).json({ message: 'Invalid severity value' });
  }

  try {
    let incident;
    for (let attempt = 0; attempt < 5 && !incident; attempt += 1) {
      const candidateId = `INC-${Date.now()}-${randomBytes(4).toString('hex').toUpperCase()}`;
      try {
        incident = await Incident.create({
          incidentId: candidateId,
          type,
          description,
          severity,
          reportedBy: req.user.id,
          status: 'Pending',
        });
      } catch (error) {
        if (error.code !== 11000 || !error.keyPattern?.incidentId) {
          throw error;
        }
      }
    }

    if (!incident) {
      return res.status(503).json({ message: 'Unable to allocate an incident reference. Please try again.' });
    }

    res.status(201).json({ message: 'Incident created successfully', incident });
  } catch (error) {
    console.error('Create incident error:', error);
    res.status(500).json({ message: 'Failed to create incident' });
  }
});

app.get('/incidents', authenticateToken, ensureDatabase, async (req, res) => {
  try {
    const query = {};
    if (req.user.role !== 'admin') {
      query.reportedBy = req.user.id;
    }

    const { status, severity, type, search } = req.query;
    if (status && !validStatuses.includes(String(status))) {
      return res.status(400).json({ message: 'Invalid status filter' });
    }
    if (severity && !validSeverities.includes(String(severity))) {
      return res.status(400).json({ message: 'Invalid severity filter' });
    }
    if ([type, search].some((value) => value && String(value).length > 100)) {
      return res.status(400).json({ message: 'Search filters must be 100 characters or fewer' });
    }

    const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (status) query.status = status;
    if (severity) query.severity = severity;
    if (type) query.type = new RegExp(escapeRegExp(type), 'i');
    if (search) {
      const searchPattern = new RegExp(escapeRegExp(search), 'i');
      query.$or = [
        { description: searchPattern },
        { type: searchPattern },
        { incidentId: searchPattern },
      ];
    }

    const incidents = await Incident.find(query)
      .sort({ createdAt: -1 })
      .populate('reportedBy', 'name email');

    res.json(incidents);
  } catch (error) {
    console.error('Fetch incidents error:', error);
    res.status(500).json({ message: 'Failed to fetch incidents' });
  }
});

app.get('/incidents/:id', authenticateToken, ensureDatabase, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: 'Invalid incident ID' });
  }

  try {
    const incident = await Incident.findById(req.params.id).populate('reportedBy', 'name email');
    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    if (req.user.role !== 'admin' && (!incident.reportedBy || incident.reportedBy._id.toString() !== req.user.id)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    res.json(incident);
  } catch (error) {
    console.error('Fetch incident error:', error);
    res.status(500).json({ message: 'Failed to fetch incident' });
  }
});

app.patch('/incidents/:id/status', authenticateToken, requireAdmin, ensureDatabase, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: 'Invalid incident ID' });
  }

  if (!req.body || Object.keys(req.body).length !== 1 || !Object.hasOwn(req.body, 'status')) {
    return res.status(400).json({ message: 'Provide only a status value' });
  }

  const status = sanitizeText(req.body.status);
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ message: 'Invalid status value' });
  }

  try {
    const incident = await Incident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    incident.status = status;
    await incident.save();
    res.json({ message: 'Incident status updated successfully', incident });
  } catch (error) {
    console.error('Update incident status error:', error);
    res.status(500).json({ message: 'Failed to update incident status' });
  }
});

app.patch('/incidents/:id', authenticateToken, ensureDatabase, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: 'Invalid incident ID' });
  }

  const updates = req.body && typeof req.body === 'object' && !Array.isArray(req.body)
    ? req.body
    : {};
  const permittedFields = req.user.role === 'admin'
    ? ['type', 'description', 'severity', 'status', 'investigationNotes']
    : ['type', 'description', 'severity'];
  const suppliedFields = Object.keys(updates);

  if (suppliedFields.some((field) => !permittedFields.includes(field))) {
    const restrictedField = suppliedFields.find((field) => !permittedFields.includes(field));
    if (req.user.role !== 'admin' && ['status', 'investigationNotes'].includes(restrictedField)) {
      return res.status(403).json({ message: 'Only administrators can update status or investigation notes' });
    }
    return res.status(400).json({ message: 'One or more incident fields cannot be updated' });
  }

  if (suppliedFields.length === 0) {
    return res.status(400).json({ message: 'No incident changes provided' });
  }

  const normalized = {};
  if (Object.hasOwn(updates, 'type')) {
    const type = sanitizeText(updates.type);
    if (!validIncidentTypes.includes(type)) {
      return res.status(400).json({ message: 'Invalid incident type' });
    }
    normalized.type = type;
  }
  if (Object.hasOwn(updates, 'description')) {
    const description = sanitizeText(updates.description);
    if (!description || description.length > 5000) {
      return res.status(400).json({ message: 'Description is required and must be 5000 characters or fewer' });
    }
    normalized.description = description;
  }
  if (Object.hasOwn(updates, 'severity')) {
    const severity = sanitizeText(updates.severity);
    if (!validSeverities.includes(severity)) {
      return res.status(400).json({ message: 'Invalid severity value' });
    }
    normalized.severity = severity;
  }
  if (Object.hasOwn(updates, 'status')) {
    const status = sanitizeText(updates.status);
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ message: 'Invalid status value' });
    }
    normalized.status = status;
  }
  if (Object.hasOwn(updates, 'investigationNotes')) {
    const investigationNotes = sanitizeText(updates.investigationNotes);
    if (investigationNotes.length > 5000) {
      return res.status(400).json({ message: 'Investigation notes must be 5000 characters or fewer' });
    }
    normalized.investigationNotes = investigationNotes;
  }

  try {
    const incident = await Incident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    if (req.user.role !== 'admin' && (!incident.reportedBy || incident.reportedBy.toString() !== req.user.id)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    Object.assign(incident, normalized);
    await incident.save();
    res.json({ message: 'Incident updated successfully', incident });
  } catch (error) {
    console.error('Patch incident error:', error);
    res.status(500).json({ message: 'Failed to update incident' });
  }
});

app.put('/incidents/:id', authenticateToken, requireAdmin, ensureDatabase, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: 'Invalid incident ID' });
  }

  const status = sanitizeText(req.body?.status);
  const investigationNotes = sanitizeText(req.body?.investigationNotes || '');

  if (investigationNotes.length > 5000) {
    return res.status(400).json({ message: 'Investigation notes must be 5000 characters or fewer' });
  }

  if (status && !validStatuses.includes(status)) {
    return res.status(400).json({ message: 'Invalid status value' });
  }

  try {
    const incident = await Incident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    if (status) incident.status = status;
    if (typeof req.body?.investigationNotes === 'string') {
      incident.investigationNotes = investigationNotes;
    }

    await incident.save();
    res.json({ message: 'Incident updated successfully', incident });
  } catch (error) {
    console.error('Update incident error:', error);
    res.status(500).json({ message: 'Failed to update incident' });
  }
});

app.put('/incidents/:id/notes', authenticateToken, requireAdmin, ensureDatabase, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: 'Invalid incident ID' });
  }

  const notes = sanitizeText(req.body?.investigationNotes || '');

  if (notes.length > 5000) {
    return res.status(400).json({ message: 'Investigation notes must be 5000 characters or fewer' });
  }

  try {
    const incident = await Incident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    incident.investigationNotes = notes;
    await incident.save();

    res.json({ message: 'Investigation notes updated', incident });
  } catch (error) {
    console.error('Update notes error:', error);
    res.status(500).json({ message: 'Failed to update notes' });
  }
});

app.delete('/incidents/:id', authenticateToken, ensureDatabase, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    return res.status(400).json({ message: 'Invalid incident ID' });
  }

  try {
    const incident = await Incident.findById(req.params.id);
    if (!incident) {
      return res.status(404).json({ message: 'Incident not found' });
    }

    if (req.user.role !== 'admin' && (!incident.reportedBy || incident.reportedBy.toString() !== req.user.id)) {
      return res.status(403).json({ message: 'You can only delete your own incidents' });
    }

    await incident.deleteOne();
    res.json({ message: 'Incident deleted successfully' });
  } catch (error) {
    console.error('Delete incident error:', error);
    res.status(500).json({ message: 'Failed to delete incident' });
  }
});

app.get('/admin/stats', authenticateToken, requireAdmin, ensureDatabase, async (req, res) => {
  try {
    const [total, pending, investigating, resolved, critical, high, medium, low, byType] = await Promise.all([
      Incident.countDocuments(),
      Incident.countDocuments({ status: 'Pending' }),
      Incident.countDocuments({ status: 'Investigating' }),
      Incident.countDocuments({ status: 'Resolved' }),
      Incident.countDocuments({ severity: 'Critical' }),
      Incident.countDocuments({ severity: 'High' }),
      Incident.countDocuments({ severity: 'Medium' }),
      Incident.countDocuments({ severity: 'Low' }),
      Incident.aggregate([
        { $group: { _id: '$type', count: { $sum: 1 } } },
        { $sort: { count: -1, _id: 1 } },
      ]),
    ]);

    res.json({
      total,
      pending,
      investigating,
      resolved,
      critical,
      high,
      medium,
      low,
      byType,
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ message: 'Failed to load statistics' });
  }
});

app.post('/create-admin', ensureDatabase, async (req, res) => {
  const name = sanitizeText(req.body?.name);
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  const bootstrapKey = String(req.body?.bootstrapKey ?? req.headers['x-bootstrap-key'] ?? '').trim();
  const expectedBootstrapKey = String(process.env.ADMIN_BOOTSTRAP_KEY || '').trim();

  if (!expectedBootstrapKey) {
    return res.status(503).json({ message: 'Admin bootstrap is not configured on this server' });
  }

  if (!bootstrapKey || bootstrapKey !== expectedBootstrapKey) {
    return res.status(403).json({ message: 'Bootstrap key required to create the initial admin account' });
  }

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email and password are required' });
  }

  if (name.length > 100 || email.length > 254 || password.length > 128) {
    return res.status(400).json({ message: 'Name, email or password exceeds the allowed length' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ message: 'Please provide a valid email address' });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long' });
  }

  try {
    const existingAdmin = await User.findOne({ role: 'admin' });
    if (existingAdmin) {
      return res.status(409).json({ message: 'An administrator already exists' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const admin = await User.create({
      name,
      email,
      password: hashedPassword,
      role: 'admin',
    });

    res.status(201).json({
      message: 'Admin created successfully',
      user: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        role: admin.role,
      },
    });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ message: 'Failed to create admin' });
  }
});

app.use((error, req, res, next) => {
  if (res.headersSent) {
    return next(error);
  }

  const status = Number(error.status) || 500;
  const message = status === 413
    ? 'Request body is too large'
    : status === 400
      ? 'Invalid JSON request body'
      : 'Request could not be processed';

  console.error('Request parsing error:', status);
  res.status(status).json({ message });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
