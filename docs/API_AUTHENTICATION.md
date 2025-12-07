# Authentication API Documentation

## Overview

The ISO Platform provides both local authentication (email/password) and OAuth2 authentication (Google). All protected endpoints require a valid JWT access token in the Authorization header.

**Base URL:**
- Development: `http://localhost:8080`
- Production: `https://api.isoplatform.com`

**API Version:** v1

---

## Table of Contents

- [Authentication Methods](#authentication-methods)
- [Local Authentication Endpoints](#local-authentication-endpoints)
  - [Sign Up](#1-sign-up)
  - [Login](#2-login)
  - [Refresh Token](#3-refresh-token)
  - [Logout](#4-logout)
- [OAuth2 Authentication](#oauth2-authentication)
- [Using Access Tokens](#using-access-tokens)
- [Token Expiration](#token-expiration)
- [Error Responses](#error-responses)
- [Security Best Practices](#security-best-practices)
- [Configuration](#configuration)
- [Testing Examples](#testing-examples)

---

## Authentication Methods

The ISO Platform supports two authentication methods:

### 1. Local Authentication (Email/Password)
Traditional username/password authentication with JWT tokens.

**Features:**
- User registration with email verification
- Password-based login
- JWT access tokens (1 hour expiration)
- Refresh tokens (7 days expiration)
- Automatic token rotation on refresh
- Secure logout with token revocation

### 2. OAuth2 (Google)
Single Sign-On with Google accounts.

**Features:**
- One-click Google login
- Automatic user registration
- Mobile deep linking support
- Secure token delivery via URL fragments
- Same JWT token structure as local auth

---

## Local Authentication Endpoints

### 1. Sign Up

Register a new user account with email and password.

**Endpoint:** `POST /api/auth/signup`

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "name": "John Doe",
  "company": "Example Corp"
}
```

**Field Requirements:**
| Field | Type | Required | Validation |
|-------|------|----------|------------|
| email | string | Yes | Valid email format, must be unique |
| password | string | Yes | 8-100 characters, must contain at least one letter and one number |
| name | string | Yes | 2-100 characters |
| company | string | No | Optional company name |

**Success Response (201 Created):**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.signature",
  "refreshToken": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
  "tokenType": "Bearer",
  "expiresIn": 3600000,
  "userId": 1,
  "email": "user@example.com",
  "name": "John Doe",
  "role": "USER"
}
```

**Error Responses:**

**409 Conflict** - Email already exists:
```json
{
  "error": "EMAIL_EXISTS",
  "message": "Email already registered",
  "timestamp": "2025-11-21T10:30:00"
}
```

**400 Bad Request** - Validation errors:
```json
{
  "error": "VALIDATION_ERROR",
  "message": "email: Invalid email format, password: Password must be between 8 and 100 characters",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Example cURL:**
```bash
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePass123!",
    "name": "John Doe",
    "company": "Acme Corp"
  }'
```

---

### 2. Login

Authenticate with existing credentials.

**Endpoint:** `POST /api/auth/login`

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Field Requirements:**
| Field | Type | Required | Validation |
|-------|------|----------|------------|
| email | string | Yes | Valid email format |
| password | string | Yes | Not blank |

**Success Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.signature",
  "refreshToken": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
  "tokenType": "Bearer",
  "expiresIn": 3600000,
  "userId": 1,
  "email": "user@example.com",
  "name": "John Doe",
  "role": "USER"
}
```

**Error Responses:**

**401 Unauthorized** - Invalid credentials:
```json
{
  "error": "INVALID_CREDENTIALS",
  "message": "Invalid email or password",
  "timestamp": "2025-11-21T10:30:00"
}
```

**400 Bad Request** - OAuth2 user cannot login locally:
```json
{
  "error": "OAUTH2_USER",
  "message": "This account uses Google login. Please login with Google.",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Example cURL:**
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "SecurePass123!"
  }'
```

---

### 3. Refresh Token

Obtain a new access token using a valid refresh token.

**Endpoint:** `POST /api/auth/refresh`

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body:**
```json
{
  "refreshToken": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6"
}
```

**Success Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzAwMDA2MDAwLCJleHAiOjE3MDAwMDk2MDB9.signature",
  "refreshToken": "x7y8z9w0-v1u2-t3s4-r5q6-p7o8n9m0l1k2",
  "tokenType": "Bearer",
  "expiresIn": 3600000,
  "userId": 1,
  "email": "user@example.com",
  "name": "John Doe",
  "role": "USER"
}
```

**Important Notes:**
- The old refresh token is automatically revoked (single-use tokens)
- A new refresh token is issued with each refresh
- This implements automatic token rotation for enhanced security
- Reusing an old refresh token will result in an error

**Error Responses:**

**401 Unauthorized** - Invalid or expired token:
```json
{
  "error": "INVALID_TOKEN",
  "message": "Refresh token has expired",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Example cURL:**
```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6"
  }'
```

---

### 4. Logout

Revoke the refresh token to invalidate future token refreshes.

**Endpoint:** `POST /api/auth/logout`

**Request Headers:**
```http
Content-Type: application/json
```

**Request Body:**
```json
{
  "refreshToken": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6"
}
```

**Success Response (200 OK):**
```
No content
```

**Important Notes:**
- Logout only revokes the refresh token
- The access token remains valid until it expires (up to 1 hour)
- For immediate session invalidation, clients should clear local storage
- The server maintains a revoked tokens list to prevent reuse

**Error Responses:**

**401 Unauthorized** - Invalid token:
```json
{
  "error": "INVALID_TOKEN",
  "message": "Invalid refresh token",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Example cURL:**
```bash
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6"
  }'
```

---

## OAuth2 Authentication

### Google OAuth2 Login Flow

The ISO Platform supports OAuth2 authentication with Google, including mobile deep linking.

#### Flow Diagram

```
1. Client initiates OAuth2
   ↓
2. Redirect to Google login
   ↓
3. User authenticates with Google
   ↓
4. Google redirects back with authorization code
   ↓
5. Server exchanges code for user info
   ↓
6. Server creates/updates user in database
   ↓
7. Server generates JWT tokens
   ↓
8. Server redirects to client with tokens
```

#### Endpoints

**1. Initiate OAuth2 Login**

**Web Login:**
```
GET /api/auth/oauth2/authorization/google
```

Redirects the user to Google's login page.

**Mobile Login with Deep Link:**
```
GET /api/auth/oauth2/authorization/google?redirectUrl=totaload://oauth2/callback
```

The `redirectUrl` parameter specifies where to redirect after successful authentication.

**Allowed Redirect URL Schemes:**
- `totaload://` - Default mobile app scheme
- `myapp://` - Custom app scheme
- Any HTTP/HTTPS URL matching `allowed-redirect-domains` configuration

**2. OAuth2 Callback (Automatic)**

This endpoint is called automatically by Google after successful authentication.

```
GET /login/oauth2/code/google?code=...&state=...
```

The server:
1. Exchanges the authorization code for user information
2. Creates a new user account if email doesn't exist (OAuth2 provider: GOOGLE)
3. Updates user information if account already exists
4. Generates JWT access token and refresh token
5. Redirects to the appropriate target URL with tokens

**3. Token Delivery**

Tokens are delivered via URL fragment (hash) for security.

**Web Redirect:**
```
http://localhost:3000#access_token=eyJhbGc...&refresh_token=a1b2c3d4...&token_type=Bearer
```

**Mobile Deep Link:**
```
totaload://oauth2/callback#access_token=eyJhbGc...&refresh_token=a1b2c3d4...&token_type=Bearer
```

**Fragment Parameters:**
| Parameter | Description | Example |
|-----------|-------------|---------|
| access_token | JWT access token (1 hour) | eyJhbGciOiJIUzUxMiJ9... |
| refresh_token | Refresh token (7 days) | a1b2c3d4-e5f6-g7h8... |
| token_type | Token type (always "Bearer") | Bearer |

#### Security Features

1. **URL Fragment Delivery**: Tokens are delivered in URL fragment (after `#`), which is not sent to the server
2. **Allowed Domains**: Only pre-configured domains/schemes can be used for redirect
3. **Scheme Validation**: Custom URL schemes are validated against whitelist
4. **State Parameter**: CSRF protection via state parameter (handled by Spring Security)

#### Example Implementation

**Web Application (React/Vue/Angular):**
```javascript
// Initiate login
window.location.href = 'http://localhost:8080/api/auth/oauth2/authorization/google';

// Handle callback (in your callback page)
const handleOAuth2Callback = () => {
  const hash = window.location.hash.substring(1);
  const params = new URLSearchParams(hash);

  const accessToken = params.get('access_token');
  const refreshToken = params.get('refresh_token');

  if (accessToken && refreshToken) {
    // Store tokens securely
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);

    // Redirect to app
    window.location.href = '/dashboard';
  }
};
```

**Mobile Application (React Native / Flutter):**
```javascript
// 1. Open OAuth2 URL with deep link
const deepLink = encodeURIComponent('totaload://oauth2/callback');
const authUrl = `http://localhost:8080/api/auth/oauth2/authorization/google?redirectUrl=${deepLink}`;

// Open in system browser
Linking.openURL(authUrl);

// 2. Handle deep link callback
Linking.addEventListener('url', (event) => {
  const url = event.url;

  if (url.startsWith('totaload://oauth2/callback')) {
    const hash = url.split('#')[1];
    const params = new URLSearchParams(hash);

    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');

    // Store in secure storage (Keychain/KeyStore)
    await SecureStore.setItemAsync('accessToken', accessToken);
    await SecureStore.setItemAsync('refreshToken', refreshToken);
  }
});
```

---

## Using Access Tokens

### Authorization Header

All protected endpoints require the access token in the `Authorization` header using the Bearer scheme.

**Format:**
```http
Authorization: Bearer <access_token>
```

### Example Protected Request

**Request:**
```bash
curl -X GET http://localhost:8080/api/certificates \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.signature"
```

**Success Response (200 OK):**
```json
{
  "certificates": [
    {
      "id": 1,
      "name": "ISO 9001:2015",
      "status": "active"
    }
  ]
}
```

**Error Response (401 Unauthorized):**
```json
{
  "error": "UNAUTHORIZED",
  "message": "Invalid or expired token",
  "timestamp": "2025-11-21T10:30:00"
}
```

---

## Token Expiration

### Token Lifetimes

| Token Type | Lifetime | Purpose |
|------------|----------|---------|
| Access Token | 1 hour (3600 seconds) | API authentication |
| Refresh Token | 7 days (604800 seconds) | Token renewal |

### Handling Token Expiration

**Recommended Flow:**

1. **Client makes API request with access token**
2. **If server returns 401 Unauthorized:**
   - Check if error indicates expired token
   - Call `/api/auth/refresh` with refresh token
   - Store new tokens
   - Retry original request with new access token
3. **If refresh fails:**
   - Clear stored tokens
   - Redirect user to login page

**Example Implementation (JavaScript):**
```javascript
async function apiRequest(url, options = {}) {
  // Add access token to request
  options.headers = {
    ...options.headers,
    'Authorization': `Bearer ${getAccessToken()}`
  };

  let response = await fetch(url, options);

  // If 401, try to refresh token
  if (response.status === 401) {
    const refreshed = await refreshAccessToken();

    if (refreshed) {
      // Retry with new token
      options.headers['Authorization'] = `Bearer ${getAccessToken()}`;
      response = await fetch(url, options);
    } else {
      // Refresh failed, redirect to login
      redirectToLogin();
      return null;
    }
  }

  return response;
}

async function refreshAccessToken() {
  try {
    const response = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        refreshToken: getRefreshToken()
      })
    });

    if (response.ok) {
      const data = await response.json();
      setAccessToken(data.accessToken);
      setRefreshToken(data.refreshToken);
      return true;
    }

    return false;
  } catch (error) {
    console.error('Token refresh failed:', error);
    return false;
  }
}
```

---

## Error Responses

All error responses follow a consistent format:

```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable error message",
  "timestamp": "2025-11-21T10:30:00"
}
```

### Error Codes Reference

| HTTP Status | Error Code | Description | Common Causes |
|-------------|------------|-------------|---------------|
| 400 | VALIDATION_ERROR | Request validation failed | Invalid email format, password too short, missing required fields |
| 400 | BAD_REQUEST | Malformed request | Invalid JSON, illegal arguments |
| 400 | OAUTH2_USER | OAuth2 user cannot login locally | User registered with Google trying to use password login |
| 401 | INVALID_CREDENTIALS | Authentication failed | Wrong email or password |
| 401 | INVALID_TOKEN | Token validation failed | Expired token, invalid token, revoked token |
| 401 | UNAUTHORIZED | Not authenticated | Missing or invalid Authorization header |
| 409 | EMAIL_EXISTS | Email already registered | Signup with existing email |
| 500 | INTERNAL_ERROR | Server error | Unexpected server-side error |

### Detailed Error Examples

**Validation Error (400):**
```json
{
  "error": "VALIDATION_ERROR",
  "message": "email: Invalid email format, password: Password must contain at least one letter and one number",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Authentication Failed (401):**
```json
{
  "error": "INVALID_CREDENTIALS",
  "message": "Invalid email or password",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Token Expired (401):**
```json
{
  "error": "INVALID_TOKEN",
  "message": "Refresh token has expired",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Email Already Exists (409):**
```json
{
  "error": "EMAIL_EXISTS",
  "message": "Email already registered",
  "timestamp": "2025-11-21T10:30:00"
}
```

**OAuth2 User Login Attempt (400):**
```json
{
  "error": "OAUTH2_USER",
  "message": "This account uses Google login. Please login with Google.",
  "timestamp": "2025-11-21T10:30:00"
}
```

---

## Security Best Practices

### For Client Applications

#### 1. Token Storage

**Web Applications:**
- **DO NOT** store tokens in localStorage (vulnerable to XSS)
- **DO** use httpOnly cookies (managed by backend) OR
- **DO** use sessionStorage for short-term storage
- **DO** implement proper CSRF protection if using cookies

**Mobile Applications:**
- **DO** use platform secure storage:
  - iOS: Keychain Services
  - Android: Android KeyStore
- **DO NOT** store tokens in SharedPreferences/UserDefaults
- **DO NOT** store tokens in app sandbox without encryption

#### 2. Token Transmission

- **ALWAYS** use HTTPS in production
- **DO** send access tokens in Authorization header
- **DO NOT** send tokens in URL query parameters (except OAuth2 callback)
- **DO NOT** log tokens in console or analytics
- **DO** clear tokens from memory after use when possible

#### 3. Token Lifecycle

**Proactive Refresh:**
```javascript
// Refresh token before it expires (e.g., 5 minutes before)
const TOKEN_LIFETIME = 3600; // 1 hour
const REFRESH_BEFORE = 300; // 5 minutes

setInterval(() => {
  const tokenAge = getTokenAge();
  if (tokenAge > TOKEN_LIFETIME - REFRESH_BEFORE) {
    refreshAccessToken();
  }
}, 60000); // Check every minute
```

**Logout on Security Events:**
- User-initiated logout
- Token compromise detected
- Multiple failed refresh attempts
- App backgrounded for extended period (mobile)

#### 4. Error Handling

- **DO** handle 401 errors gracefully with automatic refresh
- **DO** redirect to login after refresh failure
- **DO NOT** retry failed requests indefinitely
- **DO** show user-friendly error messages

#### 5. Session Management

- **DO** implement automatic logout on inactivity
- **DO** warn users before session expires
- **DO** provide "remember me" option (extended refresh token)
- **DO** log out from all devices feature (server-side token revocation)

### For Server/Backend

The server implements these security measures:

1. **JWT Signature Validation**: All tokens are signed with HS512 algorithm
2. **Token Expiration**: Short-lived access tokens (1 hour), longer refresh tokens (7 days)
3. **Refresh Token Rotation**: New refresh token issued on each refresh
4. **Single-Use Refresh Tokens**: Old tokens revoked immediately after use
5. **Secure Password Storage**: Passwords hashed with BCrypt
6. **Rate Limiting**: Protection against brute force attacks (recommended in production)
7. **CORS Configuration**: Restricted to allowed origins
8. **OAuth2 State Parameter**: CSRF protection in OAuth2 flow
9. **Redirect URL Validation**: Only allowed domains/schemes accepted

---

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET=your-secret-key-minimum-256-bits-for-hs512-algorithm-required
JWT_EXPIRATION_TIME=3600000  # 1 hour in milliseconds
JWT_REFRESH_EXPIRATION_TIME=604800000  # 7 days in milliseconds

# OAuth2 Google Configuration
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Frontend Configuration
FRONTEND_URL=http://localhost:3000

# Allowed Redirect Domains (comma-separated)
AUTH_ALLOWED_REDIRECT_DOMAINS=localhost:3000,app.example.com

# Database Configuration
SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/isoplatform
SPRING_DATASOURCE_USERNAME=postgres
SPRING_DATASOURCE_PASSWORD=your-db-password
```

### Application Configuration (application.yml)

```yaml
spring:
  datasource:
    url: ${SPRING_DATASOURCE_URL}
    username: ${SPRING_DATASOURCE_USERNAME}
    password: ${SPRING_DATASOURCE_PASSWORD}

  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false

  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope:
              - email
              - profile
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"

jwt:
  secret: ${JWT_SECRET}
  expiration-time: ${JWT_EXPIRATION_TIME:3600000}
  refresh-expiration-time: ${JWT_REFRESH_EXPIRATION_TIME:604800000}

frontend:
  url: ${FRONTEND_URL:http://localhost:3000}

auth:
  allowed-redirect-domains:
    - ${AUTH_ALLOWED_REDIRECT_DOMAINS:localhost:3000}
```

### Google OAuth2 Setup

1. **Create Google Cloud Project:**
   - Visit [Google Cloud Console](https://console.cloud.google.com)
   - Create new project or select existing

2. **Enable Google+ API:**
   - Navigate to APIs & Services > Library
   - Search for "Google+ API"
   - Click Enable

3. **Create OAuth2 Credentials:**
   - Navigate to APIs & Services > Credentials
   - Click "Create Credentials" > "OAuth client ID"
   - Select "Web application"
   - Add authorized redirect URIs:
     - `http://localhost:8080/login/oauth2/code/google` (development)
     - `https://api.yourdomain.com/login/oauth2/code/google` (production)

4. **Configure Client ID and Secret:**
   - Copy Client ID and Client Secret
   - Add to environment variables or application configuration

---

## Testing Examples

### Manual Testing with cURL

#### 1. Complete Authentication Flow

**Sign Up:**
```bash
curl -v -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!",
    "name": "Test User",
    "company": "Test Corp"
  }'
```

**Expected Response:**
```json
{
  "accessToken": "eyJhbGc...",
  "refreshToken": "a1b2c3d4...",
  "tokenType": "Bearer",
  "expiresIn": 3600000,
  "userId": 1,
  "email": "test@example.com",
  "name": "Test User",
  "role": "USER"
}
```

**Login:**
```bash
curl -v -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!"
  }'
```

**Access Protected Resource:**
```bash
# Replace YOUR_ACCESS_TOKEN with actual token from signup/login response
curl -v -X GET http://localhost:8080/api/certificates \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Refresh Token:**
```bash
# Replace YOUR_REFRESH_TOKEN with actual refresh token
curl -v -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

**Logout:**
```bash
# Replace YOUR_REFRESH_TOKEN with actual refresh token
curl -v -X POST http://localhost:8080/api/auth/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

#### 2. Error Scenarios

**Validation Error (Invalid Email):**
```bash
curl -v -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "invalid-email",
    "password": "short",
    "name": "A"
  }'
```

**Expected Response (400):**
```json
{
  "error": "VALIDATION_ERROR",
  "message": "email: Invalid email format, password: Password must be between 8 and 100 characters, name: Name must be between 2 and 100 characters",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Invalid Credentials:**
```bash
curl -v -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "WrongPassword123!"
  }'
```

**Expected Response (401):**
```json
{
  "error": "INVALID_CREDENTIALS",
  "message": "Invalid email or password",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Expired Token:**
```bash
curl -v -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "expired-or-invalid-token"
  }'
```

**Expected Response (401):**
```json
{
  "error": "INVALID_TOKEN",
  "message": "Refresh token has expired",
  "timestamp": "2025-11-21T10:30:00"
}
```

**Duplicate Email:**
```bash
# First signup
curl -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "duplicate@example.com",
    "password": "Password123!",
    "name": "User One"
  }'

# Second signup with same email
curl -v -X POST http://localhost:8080/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "duplicate@example.com",
    "password": "DifferentPass456!",
    "name": "User Two"
  }'
```

**Expected Response (409):**
```json
{
  "error": "EMAIL_EXISTS",
  "message": "Email already registered",
  "timestamp": "2025-11-21T10:30:00"
}
```

---

## Postman Collection

For easier testing, you can import this Postman collection:

**Collection Structure:**
```
ISO Platform Auth API
├── Local Auth
│   ├── Sign Up
│   ├── Login
│   ├── Refresh Token
│   └── Logout
├── OAuth2
│   └── Google Login (Browser)
└── Protected Resources
    └── Get Certificates (with Bearer token)
```

**Environment Variables:**
```json
{
  "base_url": "http://localhost:8080",
  "access_token": "{{access_token}}",
  "refresh_token": "{{refresh_token}}"
}
```

---

## Additional Resources

- [Spring Security OAuth2 Documentation](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Google OAuth2 Documentation](https://developers.google.com/identity/protocols/oauth2)

---

## Support

For issues or questions:
- GitHub Issues: [Create an issue]
- Email: support@isoplatform.com
- Documentation: [Full documentation]

---

**Last Updated:** 2025-11-21
**API Version:** 1.0.0
**Authentication System Version:** 1.0.0
