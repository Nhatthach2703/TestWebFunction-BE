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

exports.refresh = async (req, res) => { // Token lấy đang bị sai, cần fix lại
  const token = req.cookies.refreshToken;
  // console.log('Refresh token:', token);

  if (!token) return res.sendStatus(401); // Unauthorized if no token

  try {
    // Verify the token
    const payload = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    
    // Check for user existence and matching refresh token
    const user = await User.findOne({ _id: payload.userId, refreshToken: token }); //, refreshToken: token
    // console.log('User found:', user);
    if (!user) return res.sendStatus(403); // Forbidden if no user found

    // Generate a new access token
    const newAccessToken = generateToken(user._id, process.env.JWT_SECRET, '15m');

    // Send the new token and user details
    res.json({
      accessToken: newAccessToken,
      user: {
        username: user.username,
        // Add other fields as needed
      },
    });
  } catch (err) {
    console.error('Error verifying refresh token:', err);
    res.sendStatus(403); // Forbidden if token verification fails
  }
};

