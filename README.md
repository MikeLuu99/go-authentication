# Go Authentication Server

A simple authentication server written in Go that demonstrates basic user authentication and session management.

## Features

- User registration with password hashing
- User login with session management
- CSRF protection for sensitive operations
- Protected routes requiring authentication
- User logout functionality
- Simple user listing endpoint

## Server Structure

The project is organized into three main files:

1. **main.go** - Contains the HTTP handlers and server initialization:
   - User registration and login logic
   - Protected route implementation
   - Logout functionality
   - User display endpoint
   - Server configuration and startup

2. **session.go** - Handles authentication and authorization:
   - Session verification
   - CSRF token validation
   - Authorization middleware

3. **utils.go** - Provides utility functions:
   - Password hashing and verification
   - Secure token generation

## Prerequisites

- Go 1.24 or higher
- Required dependencies will be installed via Go modules

## Getting Started

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/MikeLuu99/go-authentication.git
   cd go-authentication
   ```

2. Install dependencies:
   ```
   go mod download
   ```

### Running the Server

Run the server with the following command:
```
go run .
```

The server will start on port 8080. You should see the message:
```
Server started on port 8080
```

## API Endpoints

### Register a New User
```
POST /register
Form data: username, password
```

### Login
```
POST /login
Form data: username, password
```

### Access Protected Route
```
POST /protected
Form data: username
Headers: X-CSRF-Token: [csrf_token]
Cookies: session_token=[session_token]
```

### Logout
```
POST /logout
Form data: username
Headers: X-CSRF-Token: [csrf_token]
Cookies: session_token=[session_token]
```

### Display All Users
```
GET /display
```

## Security Notes

This server implements:
- Password hashing using bcrypt
- Session management with secure cookies
- CSRF protection with tokens
