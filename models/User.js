// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  refreshToken: String,
});

module.exports = mongoose.model('User', userSchema);
