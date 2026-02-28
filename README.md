# Netflix Authentication Service

A secure authentication microservice built with Spring Boot, featuring JWT-based authentication with refresh token rotation.

## 🔐 Security Features

- **JWT Access & Refresh Tokens** - Short-lived access tokens with rotating refresh tokens
- **Refresh Token Rotation** - New refresh token issued on each use
- **Token Reuse Detection** - Automatic session revocation on token reuse (prevents token theft)
- **Brute Force Protection** - Account lockout after failed attempts
- **Multi-Device Session Management** - Track and manage sessions across devices
- **Secure Cookies** - HttpOnly & Secure flags on sensitive cookies
- **Anti-Enumeration** - Silent responses prevent user discovery attacks

## 🛠️ Tech Stack

- **Java 17+**
- **Spring Boot 3.x**
- **Spring Security**
- **Spring Data JPA**
- **PostgreSQL/MySQL**
- **JWT (JSON Web Tokens)**
- **Lombok**

## 📁 Project Structure

```
src/main/java/in/bm/netflix_auth_service/
├── CONTROLLER/     # REST API endpoints
├── SERVICE/        # Business logic
├── ENTITY/         # JPA entities
├── REPOSITORY/     # Data access layer
├── RequestDTO/     # Request payloads
├── ResponseDTO/    # Response payloads
├── EXCEPTION/      # Custom exceptions
└── CONFIGURATION/  # App configuration
```

## 🚀 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/signup` | Register new user |
| POST | `/api/auth/signin` | Login user |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Logout user |
| POST | `/api/auth/verify-email` | Verify email address |

## ⚙️ Setup

1. Clone the repository
2. Configure `application.properties` with your database
3. Run `mvn spring-boot:run`

## 👤 Author

Built by [Your Name] - Java Developer

## 📝 License

MIT License
