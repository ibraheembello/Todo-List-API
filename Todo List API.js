// Dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const helmet = require('helmet');

const app = express();

// Middleware
app.use(express.json());
app.use(helmet()); // Security headers
app.use(morgan('dev')); // Logging

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// MongoDB connection
mongoose.connect('mongodb://localhost/todo-api', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Enhanced User Schema
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  refreshTokens: [{ type: String }], // Array to store refresh tokens
  createdAt: { type: Date, default: Date.now }
});

// Enhanced Todo Schema
const TodoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { 
    type: String, 
    enum: ['pending', 'in-progress', 'completed'], 
    default: 'pending'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  dueDate: { type: Date },
  tags: [{ type: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Update the updatedAt timestamp before saving
TodoSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

const User = mongoose.model('User', UserSchema);
const Todo = mongoose.model('Todo', TodoSchema);

// Validation middleware
const validateRegistration = [
  body('name').trim().isLength({ min: 2 }).withMessage('Name must be at least 2 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Invalid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
];

const validateTodo = [
  body('title').trim().isLength({ min: 1 }).withMessage('Title is required'),
  body('description').optional().trim(),
  body('status').optional().isIn(['pending', 'in-progress', 'completed']),
  body('priority').optional().isIn(['low', 'medium', 'high']),
  body('dueDate').optional().isISO8601().toDate(),
  body('tags').optional().isArray()
];

// Token generation functions
const generateAccessToken = (userId) => {
  return jwt.sign({ userId }, 'your-access-token-secret', { expiresIn: '1h' });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ userId }, 'your-refresh-token-secret', { expiresIn: '7d' });
};

// Enhanced authentication middleware
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const decoded = jwt.verify(token, 'your-access-token-secret');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    res.status(401).json({ message: 'Unauthorized' });
  }
};

// Register endpoint
app.post('/register', validateRegistration, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      name,
      email,
      password: hashedPassword
    });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Store refresh token
    user.refreshTokens.push(refreshToken);
    await user.save();

    res.status(201).json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshTokens.push(refreshToken);
    await user.save();

    res.json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Refresh token endpoint
app.post('/refresh-token', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token required' });
    }

    const decoded = jwt.verify(refreshToken, 'your-refresh-token-secret');
    const user = await User.findById(decoded.userId);

    if (!user || !user.refreshTokens.includes(refreshToken)) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // Generate new tokens
    const accessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    // Replace old refresh token with new one
    user.refreshTokens = user.refreshTokens.filter(t => t !== refreshToken);
    user.refreshTokens.push(newRefreshToken);
    await user.save();

    res.json({ accessToken, refreshToken: newRefreshToken });
  } catch (error) {
    res.status(401).json({ message: 'Invalid refresh token' });
  }
});

// Logout endpoint
app.post('/logout', auth, async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken;
    
    // Remove refresh token
    req.user.refreshTokens = req.user.refreshTokens.filter(t => t !== refreshToken);
    await req.user.save();

    res.status(204).send();
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Enhanced create todo endpoint
app.post('/todos', [auth, validateTodo], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const todo = await Todo.create({
      ...req.body,
      userId: req.user._id
    });

    res.status(201).json(todo);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Enhanced update todo endpoint
app.put('/todos/:id', [auth, validateTodo], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const todo = await Todo.findOne({ _id: req.params.id, userId: req.user._id });

    if (!todo) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    Object.assign(todo, req.body);
    await todo.save();

    res.json(todo);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Enhanced get todos endpoint with advanced filtering and sorting
app.get('/todos', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Build filter query
    const filter = { userId: req.user._id };
    
    if (req.query.title) {
      filter.title = new RegExp(req.query.title, 'i');
    }
    
    if (req.query.status) {
      filter.status = req.query.status;
    }
    
    if (req.query.priority) {
      filter.priority = req.query.priority;
    }
    
    if (req.query.tag) {
      filter.tags = req.query.tag;
    }
    
    if (req.query.dueBefore) {
      filter.dueDate = { ...filter.dueDate, $lte: new Date(req.query.dueBefore) };
    }
    
    if (req.query.dueAfter) {
      filter.dueDate = { ...filter.dueDate, $gte: new Date(req.query.dueAfter) };
    }

    // Build sort query
    const sortField = req.query.sortBy || 'createdAt';
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const sort = { [sortField]: sortOrder };

    const todos = await Todo.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(limit);

    const total = await Todo.countDocuments(filter);

    res.json({
      data: todos,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit)
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Batch update todos
app.patch('/todos/batch', auth, async (req, res) => {
  try {
    const { ids, update } = req.body;
    
    const result = await Todo.updateMany(
      { _id: { $in: ids }, userId: req.user._id },
      { $set: update }
    );

    res.json({ modified: result.nModified });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get todo statistics
app.get('/todos/stats', auth, async (req, res) => {
  try {
    const stats = await Todo.aggregate([
      { $match: { userId: req.user._id } },
      {
        $group: {
          _id: null,
          total: { $sum: 1 },
          completed: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          pending: {
            $sum: { $cond: [{ $eq: ['$status', 'pending'] }, 1, 0] }
          },
          inProgress: {
            $sum: { $cond: [{ $eq: ['$status', 'in-progress'] }, 1, 0] }
          },
          highPriority: {
            $sum: { $cond: [{ $eq: ['$priority', 'high'] }, 1, 0] }
          }
        }
      }
    ]);

    res.json(stats[0] || {
      total: 0,
      completed: 0,
      pending: 0,
      inProgress: 0,
      highPriority: 0
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Export for testing
module.exports = app;