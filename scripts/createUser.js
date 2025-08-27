require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const AuthUser = require('../models/authUser.model');
const config = require('../config/config');

const createUser = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(config.MONGO_URI, { 
      useNewUrlParser: true, 
      useUnifiedTopology: true 
    });
    console.log('Connected to MongoDB');

    // Check if user already exists
    const existingUser = await AuthUser.findOne({ email: 'anabellebruen42@gmail.com' });
    if (existingUser) {
      console.log('User already exists:', existingUser.email);
      console.log('You can use these credentials to login:');
      console.log('Email:', existingUser.email);
      console.log('Password: (check your database or recreate)');
      process.exit(0);
    }

    // Create user
    const userEmail = 'anabellebruen42@gmail.com';
    const userPassword = 'TestUser123';
    
    const hashedPassword = await bcrypt.hash(userPassword, 10);
    
    const user = new AuthUser({
      email: userEmail,
      password: hashedPassword,
      role: 'user'
    });

    await user.save();
    
    console.log('✅ User created successfully!');
    console.log('📧 Email:', userEmail);
    console.log('🔑 Password:', userPassword);
    console.log('👤 Role: user');
    console.log('\n🚀 You can now login at:', process.env.FRONTEND_URL ? `${process.env.FRONTEND_URL}/login` : '');
    
  } catch (error) {
    console.error('❌ Error creating user:', error.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
};

createUser();
