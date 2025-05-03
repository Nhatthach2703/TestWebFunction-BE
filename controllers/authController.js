const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const generateToken = (userId, secret, expiresIn) =>
  jwt.sign({ userId }, secret, { expiresIn });

exports.register = async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();
  res.status(201).json({ message: 'User created' });
};

exports.login = async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ message: 'Invalid credentials' });

  const accessToken = generateToken(user._id, process.env.JWT_SECRET, '15m');
  const refreshToken = generateToken(user._id, process.env.JWT_REFRESH_SECRET, '7d');

  user.refreshToken = refreshToken;
  await user.save();

  res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      sameSite: 'strict',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    }).json({ accessToken,
        user: {
            username: user.username,
            // thêm các field khác nếu cần
        }
     });
};

exports.profile = async (req, res) => {
  const user = await User.findById(req.userId, { password: 0 });
  res.json(user);
};

exports.refresh = async (req, res) => {
  const token = req.cookies.refreshToken;
  // console.log('Refresh token:', token);

  if (!token) {
    console.error('No refresh token provided');
    return res.status(401).json({ message: 'No refresh token provided' }); // Unauthorized
  }

  try {
    // Verify the refresh token 
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);

    // Check if the user exists and the refresh token matches
    const user = await User.findOne({ _id: payload.userId, refreshToken: token });
    if (!user) {
      console.error('User not found or refresh token does not match', {
        userId: payload.userId,
        token,
      });
      return res.status(403).json({ message: 'Invalid or expired refresh token' }); // Forbidden
    }

    // Generate a new access token
    const newAccessToken = generateToken(user._id, process.env.JWT_SECRET, '15m');

    // Send the new access token and user details
    res.json({
      accessToken: newAccessToken,
      user: {
        username: user.username,
        // Add other fields as needed
      },
    });
  } catch (err) {
    console.error('Error verifying refresh token:', {
      message: err.message,
      stack: err.stack,
      token,
    });
    res.status(403).json({ message: 'Invalid or expired refresh token' }); // Forbidden
  }
};

exports.logout = async (req, res) => {
  try {
    // The userId is already decoded and available in req.userId from the auth middleware
    const user = await User.findById(req.userId);
    if (!user) return res.sendStatus(403); // Forbidden if no user found

    user.refreshToken = null; // Clear the refresh token
    await user.save();

    res.clearCookie('refreshToken', {
      httpOnly: true,
      sameSite: 'strict',
    }).sendStatus(204); // No content
  } catch (err) {
    console.error('Error during logout:', {
      message: err.message,
      stack: err.stack,
    });
    res.status(500).json({ error: 'Internal server error', details: err.message }); // Internal server error with details
  }
};

