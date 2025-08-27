require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const AuthUser = require('../models/authUser.model');
const config = require('../config/config');

const createAdminUser = async () => {
  try {
    // Connect to MongoDB
    await mongoose.connect(config.MONGO_URI, { 
      useNewUrlParser: true, 
      useUnifiedTopology: true 
    });
    console.log('Connected to MongoDB');

    // Check if admin already exists
    const existingAdmin = await AuthUser.findOne({ role: 'admin' });
    if (existingAdmin) {
      console.log('Admin user already exists:', existingAdmin.email);
      console.log('You can use these credentials to login:');
      console.log('Email:', existingAdmin.email);
      console.log('Password: (check your database or recreate)');
      process.exit(0);
    }

    // Create admin user
    const adminEmail = 'admin@digitalidentityhub.com';
    const adminPassword = 'Admin@123';
    
    const hashedPassword = await bcrypt.hash(adminPassword, 10);
    
    const adminUser = new AuthUser({
      email: adminEmail,
      password: hashedPassword,
      role: 'admin'
    });

    await adminUser.save();
    
    console.log('✅ Admin user created successfully!');
    console.log('📧 Email:', adminEmail);
    console.log('🔑 Password:', adminPassword);
    console.log('👤 Role: admin');
    console.log('\n🚀 You can now login at:', process.env.FRONTEND_URL ? `${process.env.FRONTEND_URL}/admin/login` : '');
    
  } catch (error) {
    console.error('❌ Error creating admin user:', error.message);
  } finally {
    await mongoose.disconnect();
    process.exit(0);
  }
};

createAdminUser(); 