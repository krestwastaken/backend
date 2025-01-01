// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
// const dotenv = require('dotenv');

const app = express();
const port = process.env.PORT || 5000;

//Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

require('dotenv').config();

const jwtSecret = process.env.JWT_SECRET;


// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch((error) => console.error('Error connecting to MongoDB:', error));


//Product schema
const productSchema = new mongoose.Schema({
  title: String,
  description: String,
  price: Number,
  category: String,
  stock: Number,
  image: String,
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  active: { type: Boolean, default: true }
});

const Product = mongoose.model('Product', productSchema);

//User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['buyer', 'seller'], required: true },
  name: { type: String, required: true },
});

//Hash password before saving user
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

const User = mongoose.model('User', userSchema);

//JWT Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract Bearer token
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token
    req.user = decoded; // Attach user data to the request
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Session expired. Please log in again.'});
    }
    return res.status(400).json({ message: 'Invalid token.' });
  }
};

//Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password, role, name } = req.body;

  try {
    const normalizedEmail = email.toLowerCase().trim();

    // Check if email is already in use
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email is already in use.' });
    }

    // Validate role
    if (!['buyer', 'seller'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role.' });
    }

    // Create a new user
    const newUser = new User({ username, email: normalizedEmail, password, role, name });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully', user: newUser });
  } catch (error) {
    console.error('Signup Error:', error);

    // Handle MongoDB unique constraint errors
    if (error.code === 11000) {
      return res.status(400).json({ message: 'Email is already in use.' });
    }
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});


//Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try{
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password'});
    }
    
    //Validate hashed passowrd
    const isValidPassword = await bcrypt. compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    //JWT Token
    const token = jwt.sign(
      { id: user._id, role: user.role },            // user data
      process.env.JWT_SECRET,               // secret key
      { expiresIn: process.env.JWT_EXPIRES_IN || '18h' } //Token expiry 
    );

    res.status(200).json({ 
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
      },
    });
  }catch (error) {
    console.log('Login error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
})

// Get products or by category
app.get('/products', async (req, res) => {
  try {
    const { category } = req.query;
    const products = category
      ? await Product.find({ category })
      : await Product.find();
    res.json(products);
    console.log(products);
    
    
  } catch (error) {
    console.error('Error fetching products', error)
    res.status(500).json({ message: 'Error fetching products.', error: error.message });
  }
});

// Get a product by ID
app.get('/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Error fetching product', error: error.message });
  }
});

// Get products added by logged user
app.get('/my-products', verifyToken, async (req, res) => {
  try {
    const products = await Product.find({ addedBy: req.user.id });
    res.json(products);
  } catch (error) {
    console.log('Error fetching user products:', error);
    res.status(500).json({ message: 'Error fetching products.'})
  }
})

// Add product (Protected Route)
app.post('/products', verifyToken, async (req, res) => {
  if (req.user.role !== 'seller') {
    return res.status(403).json({ message: 'Only sellers can add Products' });
  }

  const { title, description, price, category, stock, image } = req.body;

  // Validate the product fields
  if (!title || !description || !price || !category || !stock) {
    return res.status(400).json({ message: 'All fields are required (title, description, price, category, stock).' });
  }

  try {
    const newProduct = new Product({
      title, 
      description,
      price,
      category,
      stock,
      image,
      addedBy: req.user.id, // Associate the product with the logged-in user 
    });

    await newProduct.save();
    res.status(201).json({ message: 'Product added successfully', product: newProduct });
  } catch (error) {
    console.error('Error adding product:', error.message);
    res.status(500).json({ message: 'Failed to add product. Please try again.' });
  }
});

// Toggle Product status
app.put('/products/:id/toggle-status', verifyToken, async (req, res) => {
  if (req.user.role !== 'seller') {
    return res.status(403).json({ message: 'Only sellers can update products' });
  }

  try {
    const product = await Product.findById(req.params.id);

    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    if (product.addedBy.toString() !== req.user.id) {
      return res.status(403).json({ message: 'You can only update your own products' });
    }

    // Toggle the active status
    product.active = !product.active;
    await product.save();

    res.json ({ message: `Product ${product.active ? 'activated' : 'deactivated'} successfully`, product });
  } catch(error) {
    console.error('Error toggling product status:', error);
    res.status(500).json({ message: 'Error toggling product status', error: error.message });
  }
})

// User Profile (Protected Route)
app.get('/user-profile/:id', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
   
//Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
