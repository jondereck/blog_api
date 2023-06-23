const express = require('express');
const app = express();
const dotenv = require('dotenv');
dotenv.config();
const cors = require('cors');
const mongoose = require('mongoose');
const UserModel = require('./models/User');
const PostModel = require('./models/Post');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fs = require('fs');

const salt = bcrypt.genSaltSync(10);
const secret = process.env.JWT_SECRET; // Load the secret from environment variable

const corsOptions = {
  credentials: true,
  origin: ['https://jdnblog.netlify.app', 'http://localhost:3000'],
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

// Endpoint for picture location
app.use('/uploads', express.static(__dirname + '/uploads'));

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

// Define routes

// Global error handler middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'An error occurred' });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (username.length < 4) {
    return res.status(400).json({ error: 'Username should be at least 4 characters long' });
  }

  if (!/(?=.*\d)(?=.*[a-z])(?=.*[A-Z])/.test(password)) {
    return res.status(400).json({ error: 'Password should contain at least one lowercase, uppercase letter, and digit' });
  }

  try {
    const userDoc = await UserModel.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json({ success: 'Registration successful' });
  } catch (error) {
    switch (error.name) {
      case 'ValidationError':
        const errors = Object.values(error.errors).map((err) => err.message);
        res.status(400).json({ errors });
        break;
      case 'MongoError':
        if (error.code === 11000 && error.keyPattern && error.keyPattern.username) {
          res.status(400).json({ error: 'Username already taken' });
        } else {
          res.status(400).json({ error: 'Registration failed' });
        }
        break;
      default:
        res.status(400).json({ error: 'Registration failed' });
        break;
    }
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const userDoc = await UserModel.findOne({ username });

    if (!userDoc) {
      return res.status(404).json({ error: 'User not found' });
    }

    const passOk = bcrypt.compareSync(password, userDoc.password);

    if (passOk) {
      const payload = {
        username,
        id: userDoc._id,
      };

      jwt.sign(payload, secret, {}, (err, token) => {
        if (err) throw err;
        res.cookie('token', token).json({
          id: userDoc._id,
          username,
        });
      });
    } else {
      res.status(401).json({ error: 'Invalid password' });
    }
  } catch (error) {
    res.status(500).json({ error: 'An error occurred' });
  }
});

// Authentication middleware
function authenticate(req, res, next) {
  const { token } = req.cookies;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, secret, {}, (err, info) => {
    if (err) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = info;
    next();
  });
}

app.get('/profile', authenticate, (req, res) => {
  res.json(req.user);
});

app.post('/logout', (req, res) => {
  try {
    res.clearCookie('token').send('nice');
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json('Internal server error');
  }
});

app.post('/post', upload.single('file'), authenticate, async (req, res) => {
  const { title, summary, content } = req.body;
  const errors = {};
  
  if (!title || title.trim() === "") {
    errors.title = "Title cannot be empty";
  } else if (title.length < 4) {
    errors.title = "Title should be at least 4 characters long";
  }
  
  if (!summary || summary.trim() === "") {
    errors.summary = "Summary cannot be empty";
  } else if (summary.length < 10) {
    errors.summary = "Summary should be at least 10 characters long";
  }
  
  if (!content || content.trim() === "") {
    errors.content = "Content cannot be empty";
  } else if (content.length < 20) {
    errors.content = "Content should be at least 20 characters long";
  }
  
  if (!req.file) {
    errors.cover = "Cover image is required";
  }
  
  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ errors });
  }
  
  
  try {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    const newPath = path + '.' + ext;
    fs.renameSync(path, newPath);

    const { title, summary, content } = req.body;
    const { id } = req.user;

    const postDoc = await PostModel.create({
      title,
      summary,
      content,
      cover: newPath,
      author: id,
    });
    
    res.json({success:'Successfully created a post.'});
  } catch (error) {
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.put('/post', upload.single('file'), authenticate, async (req, res) => {
  try {
    let newPath = null;
    if (req.file) {
      const { originalname, path } = req.file;
      const parts = originalname.split('.');
      const ext = parts[parts.length - 1];
      newPath = path + '.' + ext;
      fs.renameSync(path, newPath);
    }

    const { id, title, summary, content } = req.body;
    const postDoc = await PostModel.findById(id);
    const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(req.user.id);

    if (!isAuthor) {
      return res.status(401).json({ error: 'You are not the author' });
    }

    await postDoc.updateOne({
      title,
      summary,
      content,
      cover: newPath ? newPath : postDoc.cover,
    });

     const updatedPost = await PostModel.findById(id);

  res.json({ success: 'Post updated successfully', post: updatedPost });

    res.json(postDoc);
  } catch (error) {
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/post', async (req, res) => {
  try {
    const posts = await PostModel.find()
      .populate('author', ['username'])
      .sort({ createdAt: -1 })
      .limit(20);

    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: 'An error occurred' });
  }
});

app.get('/post/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const postDoc = await PostModel.findById(id).populate('author', ['username']);
    res.json(postDoc);
  } catch (error) {
    res.status(500).json({ error: 'An error occurred' });
  }
});


app.delete('/post/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { user } = req;

  
      const postDoc = await PostModel.findById(id);
      if (!postDoc) {
        // Post not found
        return res.status(404).json({ error: 'Post not found' });
      }

      const isAuthor = JSON.stringify(postDoc.author) === JSON.stringify(user.id);
      if (!isAuthor) {
        // User is not the author of the post
        return res.status(401).json({ error: 'You are not the author of this post' });
      }

      await PostModel.findByIdAndRemove(id); // Use findByIdAndRemove to delete the post
      res.json({ success: 'Post deleted successfully' });
    
  } catch (error) {
    // Handle other potential errors
    res.status(500).json({ error: 'An error occurred' });
  }
});


const server = app.listen(process.env.API_PORT, () => {
  console.log(`Server is running on port ${server.address().port}`);
});
