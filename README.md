# Todo List API

Project based on [Backend Todo List API Project](https://roadmap.sh/projects/todo-list-api)

## Features

- User Authentication (Register/Login)
- JWT & Refresh Token Implementation
- CRUD operations for Todo items
- Advanced filtering and pagination
- Rate limiting and security measures
- Data validation
- Comprehensive error handling

## API Endpoints

### Authentication

- `POST /register` - Register new user
- `POST /login` - User login
- `POST /refresh-token` - Refresh access token
- `POST /logout` - User logout

### Todo Operations

- `POST /todos` - Create todo
- `GET /todos` - List todos (with filtering & pagination)
- `PUT /todos/:id` - Update todo
- `DELETE /todos/:id` - Delete todo
- `PATCH /todos/batch` - Batch update todos
- `GET /todos/stats` - Get todo statistics

## Tech Stack

- Node.js & Express
- MongoDB & Mongoose
- JWT for authentication
- bcrypt for password hashing
- express-validator for validation
- express-rate-limit for rate limiting
- helmet for security headers

## Getting Started

1. Clone the repository
2. Install dependencies:

```bash
npm install
```

3. Start MongoDB locally
4. Run the server:

```bash
npm start
```

## Testing

Run the test suite:

```bash
npm test
```

## Security Features

- Password hashing
- JWT token authentication
- Rate limiting
- Security headers (Helmet)
- Input validation
- Refresh token rotation
