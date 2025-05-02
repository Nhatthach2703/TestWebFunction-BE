# Test Function Web Server

This is a Node.js server application built with Express.js. It provides authentication and user management functionalities.

## Features

- User registration and login
- JWT-based authentication
- Refresh token mechanism
- MongoDB integration
- CORS support

## Project Structure

```
server/
├── app.js                # Main application file
├── bin/www               # Server entry point
├── controllers/          # Controller logic
├── middleware/           # Middleware functions
├── models/               # Mongoose models
├── public/               # Static files
├── routes/               # Route definitions
├── .env                  # Environment variables
├── package.json          # Project metadata and dependencies
└── .gitignore            # Ignored files
```

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```

2. Navigate to the server directory:
   ```bash
   cd server
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Set up the environment variables in a `.env` file:
   ```env
   PORT=5000
   MONGO_URI=mongodb://localhost:27017/testFunctionWeb
   JWT_SECRET=123
   JWT_REFRESH_SECRET=456
   ```

## Usage

1. Start the server:
   ```bash
   npm start
   ```

2. The server will run on `http://localhost:5000`.

## API Endpoints

### Authentication

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and receive an access token
- `GET /api/auth/profile` - Get user profile (protected)
- `POST /api/auth/refresh` - Refresh access token

### Users

- `GET /users` - Get a list of users

## License

This project is licensed under the MIT License.