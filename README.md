# ISO Platform Backend

Spring Boot backend application for the ISO Platform, providing authentication, certificate management, and compliance tracking capabilities.

## Table of Contents

- [Features](#features)
- [Authentication](#authentication)
- [Technology Stack](#technology-stack)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Testing](#testing)
- [Deployment](#deployment)
- [Contributing](#contributing)

---

## Features

- **Dual Authentication System:**
  - Local authentication with email/password
  - OAuth2 Single Sign-On with Google
  - Mobile deep linking support for OAuth2

- **Secure Token Management:**
  - JWT access tokens (1-hour expiration)
  - Refresh tokens with automatic rotation (7-day expiration)
  - Single-use refresh tokens for enhanced security

- **Certificate Management:**
  - ISO certificate tracking and management
  - Compliance status monitoring

- **RESTful API:**
  - Well-documented REST endpoints
  - Consistent error handling
  - Request validation

- **Production-Ready:**
  - Comprehensive test coverage (78+ tests)
  - Security best practices
  - Database migration support
  - Health monitoring

---

## Authentication

The ISO Platform supports two authentication methods:

### 1. Local Authentication (Email/Password)

Traditional email and password authentication with JWT tokens.

**Endpoints:**
- `POST /api/auth/signup` - Register new user
- `POST /api/auth/login` - Login with credentials
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout and revoke refresh token

**Quick Example:**
```bash
# Sign up
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "name": "John Doe",
    "company": "Acme Corp"
  }'

# Response includes tokens:
# {
#   "accessToken": "eyJhbGc...",
#   "refreshToken": "a1b2c3d4...",
#   "tokenType": "Bearer",
#   "expiresIn": 3600000,
#   "userId": 1,
#   "email": "user@example.com",
#   "name": "John Doe",
#   "role": "USER"
# }

# Use access token for API requests
curl -X GET http://localhost:8080/api/certificates \
  -H "Authorization: Bearer eyJhbGc..."
```

### 2. OAuth2 Authentication (Google)

Single Sign-On with Google accounts, supporting both web and mobile applications.

**Flow:**
1. Redirect user to: `GET /api/auth/oauth2/authorization/google`
2. User authenticates with Google
3. System redirects back with tokens

**Web Redirect:**
```
http://localhost:3000#access_token=eyJhbGc...&refresh_token=a1b2c3d4...&token_type=Bearer
```

**Mobile Deep Link:**
```
totaload://oauth2/callback#access_token=eyJhbGc...&refresh_token=a1b2c3d4...&token_type=Bearer
```

**Example (React):**
```javascript
// Initiate OAuth2 login
window.location.href = 'http://localhost:8080/api/auth/oauth2/authorization/google';

// Handle callback (on your callback page)
const hash = window.location.hash.substring(1);
const params = new URLSearchParams(hash);
const accessToken = params.get('access_token');
const refreshToken = params.get('refresh_token');

// Store tokens and redirect to app
localStorage.setItem('accessToken', accessToken);
localStorage.setItem('refreshToken', refreshToken);
```

### Token Lifecycle

**Token Expiration:**
- Access Token: 1 hour (3600 seconds)
- Refresh Token: 7 days (604800 seconds)

**Automatic Token Refresh:**
```bash
# When access token expires (401), refresh it
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "a1b2c3d4..."}'

# New tokens are issued (old refresh token is revoked)
```

### Detailed Documentation

For complete API documentation including:
- Request/response schemas
- Error codes and handling
- Security best practices
- Configuration guide
- Testing examples

See: **[API_AUTHENTICATION.md](docs/API_AUTHENTICATION.md)**

---

## Technology Stack

- **Framework:** Spring Boot 3.5.4
- **Language:** Java 21
- **Security:** Spring Security 6.x with OAuth2
- **Database:** PostgreSQL with JPA/Hibernate
- **Authentication:** JWT (HS512) + OAuth2
- **Build Tool:** Gradle 8.x
- **Testing:** JUnit 5, MockMvc, Testcontainers
- **Documentation:** SpringDoc OpenAPI (Swagger)

---

## Prerequisites

- Java 21 or higher
- PostgreSQL 14 or higher
- Gradle 8.x (or use included wrapper)
- Docker (optional, for containerized setup)

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/iso-platform.git
cd iso-platform
```

### 2. Set Up Database

**Option A: Local PostgreSQL**
```bash
# Create database
createdb isoplatform

# Update connection in application-local.yml
```

**Option B: Docker PostgreSQL**
```bash
docker run -d \
  --name iso-postgres \
  -e POSTGRES_DB=isoplatform \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 \
  postgres:14
```

### 3. Configure Environment Variables

Create `.env` file in project root:

```bash
# JWT Configuration
JWT_SECRET=your-secret-key-minimum-256-bits-for-hs512-algorithm-required-please-change-this-in-production
JWT_EXPIRATION_TIME=3600000
JWT_REFRESH_EXPIRATION_TIME=604800000

# Database
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/isoplatform
SPRING_DATASOURCE_USERNAME=postgres
SPRING_DATASOURCE_PASSWORD=postgres

# OAuth2 (Optional - required only for Google login)
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Frontend
FRONTEND_URL=http://localhost:3000
```

### 4. Run Database Migrations

```bash
./gradlew flywayMigrate
```

### 5. Build and Run

```bash
# Build
./gradlew build

# Run
./gradlew bootRun

# Or run with specific profile
./gradlew bootRun --args='--spring.profiles.active=local'
```

The application will start on `http://localhost:8080`

### 6. Verify Installation

```bash
# Check health
curl http://localhost:8080/actuator/health

# Expected response:
# {"status":"UP"}

# Try signup
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "name": "Test User"
  }'
```

---

## Configuration

### Application Profiles

The application supports multiple profiles:

- **`local`** - Local development (default)
- **`test`** - Test environment (H2 in-memory database)
- **`prod`** - Production environment

**Activate profile:**
```bash
# Via command line
./gradlew bootRun --args='--spring.profiles.active=prod'

# Via environment variable
export SPRING_PROFILES_ACTIVE=prod
./gradlew bootRun
```

### Key Configuration Files

- `application.yml` - Base configuration
- `application-local.yml` - Local development settings
- `application-test.yml` - Test environment settings
- `application-prod.yml` - Production settings (create this)

### Google OAuth2 Setup

To enable Google login:

1. **Create Google Cloud Project:**
   - Visit [Google Cloud Console](https://console.cloud.google.com)
   - Create a new project

2. **Enable Google+ API:**
   - Navigate to "APIs & Services" > "Library"
   - Search for "Google+ API" and enable it

3. **Create OAuth2 Credentials:**
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Application type: "Web application"
   - Authorized redirect URIs:
     - `http://localhost:8080/login/oauth2/code/google` (development)
     - `https://api.yourdomain.com/login/oauth2/code/google` (production)

4. **Configure Application:**
   - Copy Client ID and Client Secret
   - Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` environment variables

---

## API Documentation

### Interactive API Documentation (Swagger)

When running locally, access interactive API documentation at:

**Swagger UI:** http://localhost:8080/swagger-ui.html

**OpenAPI JSON:** http://localhost:8080/v3/api-docs

### Authentication API

Comprehensive authentication API documentation:

**[docs/API_AUTHENTICATION.md](docs/API_AUTHENTICATION.md)**

Includes:
- All authentication endpoints
- Request/response examples
- Error codes and handling
- OAuth2 flow diagrams
- Security best practices
- cURL examples
- Client implementation guides

### Quick API Reference

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/api/auth/signup` | POST | Register new user | No |
| `/api/auth/login` | POST | Login with email/password | No |
| `/api/auth/refresh` | POST | Refresh access token | No |
| `/api/auth/logout` | POST | Logout and revoke token | No |
| `/api/auth/oauth2/authorization/google` | GET | Initiate Google login | No |
| `/api/certificates` | GET | List certificates | Yes (Bearer token) |
| `/api/certificates/{id}` | GET | Get certificate details | Yes (Bearer token) |
| `/actuator/health` | GET | Health check | No |

---

## Testing

### Run All Tests

```bash
./gradlew test
```

### Run Specific Test Class

```bash
./gradlew test --tests LocalAuthServiceTest
```

### Run Tests with Coverage

```bash
./gradlew test jacocoTestReport
```

Coverage report: `build/reports/jacoco/test/html/index.html`

### Test Structure

```
src/test/java/
├── com.isoplatform.api.auth/
│   ├── controller/
│   │   └── AuthControllerTest.java (REST API tests)
│   ├── service/
│   │   ├── LocalAuthServiceTest.java (Business logic tests)
│   │   └── RefreshTokenServiceTest.java
│   ├── security/
│   │   └── JwtAuthenticationFilterTest.java
│   └── handler/
│       ├── OAuth2UserServiceTest.java
│       └── OAuth2DeepLinkTest.java
└── com.isoplatform.api.config/
    └── GlobalExceptionHandlerTest.java
```

### Test Coverage

Current test coverage: **78 tests, 100% passing**

- Unit tests: 45
- Integration tests: 33
- Coverage: ~85% line coverage

---

## Deployment

### Production Checklist

Before deploying to production:

- [ ] Change `JWT_SECRET` to a secure random value (minimum 256 bits)
- [ ] Set up production database with connection pooling
- [ ] Configure HTTPS/SSL certificates
- [ ] Set `FRONTEND_URL` to production frontend URL
- [ ] Configure Google OAuth2 with production redirect URIs
- [ ] Enable database migration on startup or run manually
- [ ] Set up monitoring and logging
- [ ] Configure CORS for production domains
- [ ] Set up rate limiting for auth endpoints
- [ ] Enable production Spring profile
- [ ] Configure secure session management
- [ ] Set up database backups
- [ ] Configure reverse proxy (nginx/Apache)

### Docker Deployment

**Build Docker image:**
```bash
./gradlew bootBuildImage --imageName=iso-platform-backend:latest
```

**Run with Docker Compose:**
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: isoplatform
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data

  backend:
    image: iso-platform-backend:latest
    ports:
      - "8080:8080"
    environment:
      SPRING_PROFILES_ACTIVE: prod
      SPRING_DATASOURCE_URL: jdbc:postgresql://postgres:5432/isoplatform
      SPRING_DATASOURCE_USERNAME: postgres
      SPRING_DATASOURCE_PASSWORD: ${DB_PASSWORD}
      JWT_SECRET: ${JWT_SECRET}
      GOOGLE_CLIENT_ID: ${GOOGLE_CLIENT_ID}
      GOOGLE_CLIENT_SECRET: ${GOOGLE_CLIENT_SECRET}
      FRONTEND_URL: ${FRONTEND_URL}
    depends_on:
      - postgres

volumes:
  postgres-data:
```

**Run:**
```bash
docker-compose up -d
```

### Environment-Specific Configuration

**Development:**
- `JWT_SECRET`: Can be simple for testing
- Database: Local or Docker PostgreSQL
- HTTPS: Not required
- CORS: Allow localhost origins

**Production:**
- `JWT_SECRET`: Strong random value (use `openssl rand -base64 64`)
- Database: Managed PostgreSQL (RDS, Cloud SQL, etc.)
- HTTPS: Required (configure SSL certificates)
- CORS: Restrict to production domains only
- Rate Limiting: Enable for auth endpoints
- Monitoring: Set up logging and alerts

---

## Project Structure

```
iso-platform/
├── src/
│   ├── main/
│   │   ├── java/com/isoplatform/api/
│   │   │   ├── auth/
│   │   │   │   ├── controller/      # REST controllers
│   │   │   │   ├── dto/             # Request/response DTOs
│   │   │   │   ├── service/         # Business logic
│   │   │   │   ├── repository/      # Data access
│   │   │   │   ├── handler/         # OAuth2 handlers
│   │   │   │   ├── security/        # Security filters
│   │   │   │   ├── exception/       # Custom exceptions
│   │   │   │   └── User.java        # User entity
│   │   │   ├── certificate/         # Certificate module
│   │   │   └── config/              # Configuration
│   │   └── resources/
│   │       ├── application.yml
│   │       ├── application-local.yml
│   │       ├── application-test.yml
│   │       └── db/migration/        # Flyway migrations
│   └── test/                        # Test files
├── docs/
│   ├── API_AUTHENTICATION.md        # Authentication API docs
│   └── plans/                       # Implementation plans
├── build.gradle                     # Gradle build configuration
└── README.md                        # This file
```

---

## Contributing

### Development Workflow

1. Create feature branch from `main`
2. Implement feature with tests (TDD preferred)
3. Run tests: `./gradlew test`
4. Run linting: `./gradlew checkstyleMain`
5. Commit with conventional commit message
6. Push and create pull request

### Commit Message Convention

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or modifications
- `refactor`: Code refactoring
- `chore`: Build process or auxiliary tool changes

**Example:**
```
feat(auth): add OAuth2 mobile deep linking support

- Detect mobile user agent in OAuth2 success handler
- Redirect mobile users to custom deep link scheme
- Include tokens in URL fragment for security
- Add comprehensive tests for mobile flow
```

### Code Style

- Follow Java naming conventions
- Use Lombok for boilerplate reduction
- Write self-documenting code with clear names
- Add JavaDoc for public APIs
- Keep methods focused and small
- Use meaningful variable names

---

## Troubleshooting

### Common Issues

**1. Database Connection Error**
```
Error: Could not open JPA EntityManager for transaction
```
**Solution:** Verify PostgreSQL is running and connection details are correct in `application-local.yml`

**2. JWT Secret Error**
```
Error: The specified key byte array is 128 bits which is not secure enough
```
**Solution:** Use a longer JWT_SECRET (minimum 256 bits / 32 characters)

**3. OAuth2 Redirect Error**
```
Error: redirect_uri_mismatch
```
**Solution:** Add the exact redirect URI to Google Cloud Console OAuth2 settings

**4. Tests Failing**
```
Error: Port 8080 already in use
```
**Solution:** Stop running application before running tests, or tests will use random port

**5. Gradle Build Error**
```
Error: Could not find or load main class
```
**Solution:** Run `./gradlew clean build` to rebuild from scratch

### Getting Help

- Check [API_AUTHENTICATION.md](docs/API_AUTHENTICATION.md) for authentication issues
- Review logs: Application logs are in `logs/` directory
- Enable debug logging: Set `logging.level.com.isoplatform=DEBUG` in application.yml
- Check health endpoint: `curl http://localhost:8080/actuator/health`

---

## Security

### Reporting Security Issues

Please report security vulnerabilities to: security@isoplatform.com

**DO NOT** open public GitHub issues for security vulnerabilities.

### Security Features

- Password hashing with BCrypt (strength 10)
- JWT tokens with HS512 signature algorithm
- Refresh token rotation (single-use tokens)
- SQL injection protection (JPA parameterized queries)
- XSS protection (Spring Security defaults)
- CSRF protection for OAuth2 flow
- Rate limiting (recommended for production)
- Secure headers (configured in Spring Security)

---

## License

[Your License Here - e.g., MIT, Apache 2.0]

---

## Contact

- **Project Lead:** [Your Name]
- **Email:** [contact@isoplatform.com]
- **Website:** [https://isoplatform.com]
- **GitHub:** [https://github.com/your-org/iso-platform]

---

## Acknowledgments

- Spring Boot Team for the excellent framework
- Spring Security Team for robust security features
- Google for OAuth2 integration
- All contributors to this project

---

**Last Updated:** 2025-11-21
**Version:** 1.0.0
