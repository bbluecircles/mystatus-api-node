/**
 * Secure Express.js API with Login and CRUD for Actions.
 * 
 * To run:
 *   node index.js
 *
 * For demonstration purposes, an in-memory user and actions store are used.
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3500;

// In production, store your secret key in an environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'your-very-secure-secret';

const dal = require('./dal.js')

const { readActions } = dal;

// Middleware Setup
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiter for the login route to mitigate brute-force attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per windowMs
  message: { error: 'Too many login attempts, please try again later.' }
});

// In-memory user store (for demonstration only)
// A real app would query a database. Here, we have one user: username "admin" with password "password".
const users = [
  {
    id: 1,
    username: 'admin',
    password: bcrypt.hashSync('password', 10) // Hash the password with bcrypt
  }
];

// In-memory actions store
let actions = [];
let nextActionId = 1;

// Middleware to authenticate JWT tokens on protected routes
function authenticateToken(req, res, next) {
  // Expect the token in the format: "Bearer <token>"
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token missing' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user; // Attach the decoded user to the request object
    next();
  });
}

// ====================
// ===  API Routes  ===
// ====================

// ---- Login Route ----
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  // Check if both username and password are provided
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  // Find the user by username
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Validate the password using bcrypt
  const passwordValid = await bcrypt.compare(password, user.password);
  if (!passwordValid) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Create a JWT token that expires in 1 hour
  const tokenPayload = { id: user.id, username: user.username };
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

  res.json({ token });
});

// ---- CRUD Routes for "Actions" ----

// Create a new Action
app.post('/actions', authenticateToken, (req, res) => {
  const { name, description } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Name is required for an Action.' });
  }

  const newAction = {
    id: nextActionId++,
    name,
    description: description || '',
    createdAt: new Date()
  };

  actions.push(newAction);
  res.status(201).json(newAction);
});

// Get all Actions
app.get('/actions/:username', authenticateToken, (req, res) => {
  const username = req.params.username;
  const userActions = readActions(username);
  res.json(actions);
});

// Get a single Action by id
app.get('/actions/:id', authenticateToken, (req, res) => {
  const id = parseInt(req.params.id);
  const action = actions.find(act => act.id === id);
  if (!action) {
    return res.status(404).json({ error: 'Action not found.' });
  }
  res.json(action);
});

// Update an Action by id
app.put('/actions/:id', authenticateToken, (req, res) => {
  const id = parseInt(req.params.id);
  const actionIndex = actions.findIndex(act => act.id === id);
  if (actionIndex === -1) {
    return res.status(404).json({ error: 'Action not found.' });
  }

  const { name, description } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Name is required for an Action.' });
  }

  // Update the action while preserving existing values if not provided
  actions[actionIndex] = {
    ...actions[actionIndex],
    name,
    description: description !== undefined ? description : actions[actionIndex].description,
    updatedAt: new Date()
  };

  res.json(actions[actionIndex]);
});

// Delete an Action by id
app.delete('/actions/:id', authenticateToken, (req, res) => {
  const id = parseInt(req.params.id);
  const actionIndex = actions.findIndex(act => act.id === id);
  if (actionIndex === -1) {
    return res.status(404).json({ error: 'Action not found.' });
  }

  const removedAction = actions.splice(actionIndex, 1);
  res.json({ message: 'Action deleted successfully.', action: removedAction[0] });
});

// ---- Global Error Handler (Optional) ----
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong.' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports = app;