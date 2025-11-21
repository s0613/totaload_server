# Authentication System Enhancement Design

**Date:** 2025-11-21
**Author:** Claude Code
**Status:** Design Approved

## Executive Summary

This design enhances the ISO Platform authentication system by adding three critical features:
1. JWT verification filter for API authentication
2. Local email/password authentication
3. Secure token delivery mechanism for mobile apps

The solution uses a hybrid approach that preserves existing OAuth2 functionality while adding new capabilities with minimal disruption to the current codebase.

## Background

### Current State
- OAuth2 (Google) authentication implemented
- JWT tokens generated but not validated on subsequent requests
- Tokens delivered via query parameters (security concern)
- No local authentication option

### Requirements Gathered
1. **JWT Verification Filter**: Validate tokens on every API request using Authorization header
2. **Local Authentication**: Basic signup/login with email/password (no email verification needed)
3. **Token Management**: Access Token (1 hour) + Refresh Token (7 days) stored in database
4. **Mobile OAuth2**: Deep link delivery using custom scheme (`totaload://`)
5. **Auto-refresh**: Automatic token refresh attempt on Access Token expiration
6. **Error Handling**: Detailed error codes for different token validation failures

## Architecture Overview

### Hybrid Approach Rationale

We chose a hybrid architecture that:
- **Preserves** existing `SecurityConfig` and OAuth2 implementation
- **Adds** new `JwtAuthenticationFilter` for token validation
- **Separates** OAuth2 and local authentication services
- **Unifies** token generation and refresh mechanisms

This minimizes code changes while following Spring Security best practices where it matters most.

### High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                       Client Requests                        │
│  (Authorization: Bearer <token> header)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              JwtAuthenticationFilter                         │
│  - Extract token from Authorization header                   │
│  - Validate signature, expiration                            │
│  - Load user and set SecurityContext                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Spring Security Filter Chain                    │
│  - Existing OAuth2 configuration preserved                   │
│  - Authorization checks                                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Controllers                                │
│  - AuthController (signup, login, refresh)                   │
│  - OAuth2Controller (existing)                               │
│  - Other API controllers                                     │
└─────────────────────────────────────────────────────────────┘
```

### Authentication Flows

#### OAuth2 Flow (Enhanced)
```
1. User clicks "Google Login" in app
2. App opens browser → /oauth2/authorization/google
3. User authenticates with Google
4. OAuth2AuthenticationSuccessHandler:
   - Creates/updates User entity
   - Generates Access Token (JWT, 1h)
   - Generates Refresh Token (UUID, 7d)
   - Saves Refresh Token to database
5. Redirects to: totaload://oauth2/callback?accessToken={jwt}&refreshToken={uuid}
6. App captures deep link and stores tokens securely
```

#### Local Authentication Flow (New)
```
1. Signup: POST /api/auth/signup
   - Input: { email, password, name }
   - Validate: email uniqueness, password strength
   - Create User (provider=LOCAL, BCrypt password)
   - Generate token pair
   - Return: { accessToken, refreshToken, expiresIn }

2. Login: POST /api/auth/login
   - Input: { email, password }
   - Validate: email exists, password matches
   - Update lastLoginAt
   - Generate token pair
   - Return: { accessToken, refreshToken, expiresIn }
```

#### API Request Flow
```
1. Client sends request with header: Authorization: Bearer {accessToken}
2. JwtAuthenticationFilter intercepts
3. If token valid:
   - Load User from database
   - Set SecurityContext
   - Continue to controller
4. If token expired:
   - Return 401 with errorCode=TOKEN_EXPIRED
   - Client auto-retries with refresh token
5. If token invalid:
   - Return 401 with errorCode=TOKEN_INVALID
   - Client redirects to login
```

#### Token Refresh Flow
```
1. Client receives 401 with TOKEN_EXPIRED
2. POST /api/auth/refresh { refreshToken: "uuid" }
3. Backend:
   - Find RefreshToken in database
   - Check expiresAt > now
   - Check user.isActive = true
   - Generate new Access Token
4. Return: { accessToken, refreshToken (same), expiresIn }
5. If refresh token invalid/expired:
   - Return 401
   - Client redirects to login
```

## Detailed Component Design

### 1. JWT Authentication Filter

**Class:** `JwtAuthenticationFilter extends OncePerRequestFilter`

**Location:** `src/main/java/com/isoplatform/api/auth/filter/JwtAuthenticationFilter.java`

**Dependencies:**
- `JwtTokenProvider`: Token parsing and validation
- `UserRepository`: User lookup by email

**Filter Logic:**
```java
@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain) {
    try {
        // 1. Extract token from Authorization header
        String token = extractTokenFromHeader(request);

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 2. Validate token (signature, expiration, format)
        if (!jwtTokenProvider.validateToken(token)) {
            throw new JwtException("Invalid token");
        }

        // 3. Extract email from token claims
        String email = jwtTokenProvider.getEmailFromToken(token);

        // 4. Load user from database
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // 5. Check if user is active
        if (!user.getIsActive()) {
            throw new DisabledException("User account is disabled");
        }

        // 6. Create authentication object
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                user, null, getAuthorities(user.getRole())
            );

        // 7. Set authentication in SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 8. Continue filter chain
        filterChain.doFilter(request, response);

    } catch (ExpiredJwtException e) {
        handleExpiredToken(response);
    } catch (JwtException e) {
        handleInvalidToken(response);
    } catch (Exception e) {
        handleAuthenticationError(response, e);
    }
}
```

**Excluded Paths:**
- `/api/auth/signup`
- `/api/auth/login`
- `/api/auth/refresh`
- `/api/health`
- `/oauth2/**`
- `/login/oauth2/**`
- `/swagger-ui/**`
- `/v3/api-docs/**`

### 2. Local Authentication Service

**Class:** `LocalAuthService`

**Location:** `src/main/java/com/isoplatform/api/auth/service/LocalAuthService.java`

**Methods:**

#### signup(SignupRequest)
```java
public AuthResponse signup(SignupRequest request) {
    // 1. Validate email format
    if (!EmailValidator.isValid(request.getEmail())) {
        throw new ValidationException("Invalid email format");
    }

    // 2. Check email uniqueness
    if (userRepository.existsByEmail(request.getEmail())) {
        throw new DuplicateEmailException("Email already registered");
    }

    // 3. Validate password strength (min 8 chars, alphanumeric)
    if (!PasswordValidator.isStrong(request.getPassword())) {
        throw new WeakPasswordException("Password must be at least 8 characters with letters and numbers");
    }

    // 4. Create user entity
    User user = User.builder()
        .email(request.getEmail())
        .name(request.getName())
        .password(passwordEncoder.encode(request.getPassword()))
        .provider("LOCAL")
        .providerId(request.getEmail())
        .role(Role.USER)
        .company("SELF")
        .isActive(true)
        .createdAt(LocalDateTime.now())
        .updatedAt(LocalDateTime.now())
        .lastLoginAt(LocalDateTime.now())
        .build();

    user = userRepository.save(user);

    // 5. Generate token pair
    return generateAuthResponse(user);
}
```

#### login(LoginRequest)
```java
public AuthResponse login(LoginRequest request) {
    // 1. Find user by email
    User user = userRepository.findByEmail(request.getEmail())
        .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

    // 2. Check if account is active
    if (!user.getIsActive()) {
        throw new DisabledException("Account is disabled");
    }

    // 3. Verify password
    if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
        throw new BadCredentialsException("Invalid email or password");
    }

    // 4. Update last login timestamp
    user.setLastLoginAt(LocalDateTime.now());
    userRepository.save(user);

    // 5. Generate token pair
    return generateAuthResponse(user);
}
```

### 3. Refresh Token Management

**Entity:** `RefreshToken`

**Location:** `src/main/java/com/isoplatform/api/auth/entity/RefreshToken.java`

**Schema:**
```java
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_token", columnList = "token"),
    @Index(name = "idx_user_id", columnList = "user_id")
})
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true, length = 255)
    private String token;  // UUID.randomUUID().toString()

    @Column(nullable = false)
    private LocalDateTime expiresAt;  // createdAt + 7 days

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(length = 500)
    private String deviceInfo;  // Optional: User-Agent for tracking

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}
```

**Service:** `RefreshTokenService`

**Methods:**

#### createRefreshToken(User)
```java
public RefreshToken createRefreshToken(User user) {
    RefreshToken refreshToken = RefreshToken.builder()
        .user(user)
        .token(UUID.randomUUID().toString())
        .expiresAt(LocalDateTime.now().plusDays(7))
        .createdAt(LocalDateTime.now())
        .build();

    return refreshTokenRepository.save(refreshToken);
}
```

#### refreshAccessToken(String)
```java
public AuthResponse refreshAccessToken(String refreshTokenString) {
    // 1. Find refresh token in database
    RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenString)
        .orElseThrow(() -> new TokenNotFoundException("Refresh token not found"));

    // 2. Check expiration
    if (refreshToken.isExpired()) {
        refreshTokenRepository.delete(refreshToken);
        throw new TokenExpiredException("Refresh token expired");
    }

    // 3. Check user is active
    User user = refreshToken.getUser();
    if (!user.getIsActive()) {
        throw new DisabledException("User account is disabled");
    }

    // 4. Generate new access token (refresh token stays the same)
    String accessToken = jwtTokenProvider.generateToken(user);

    return AuthResponse.builder()
        .accessToken(accessToken)
        .refreshToken(refreshTokenString)
        .tokenType("Bearer")
        .expiresIn(3600)
        .build();
}
```

#### deleteByUser(User)
```java
public void deleteByUser(User user) {
    refreshTokenRepository.deleteByUser(user);
}
```

### 4. JWT Token Provider Enhancement

**Updates to:** `src/main/java/com/isoplatform/api/auth/service/JwtTokenProvider.java`

**New Methods:**

#### validateToken(String)
```java
public boolean validateToken(String token) {
    try {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token);
        return true;
    } catch (JwtException | IllegalArgumentException e) {
        log.error("Invalid JWT token: {}", e.getMessage());
        return false;
    }
}
```

#### getEmailFromToken(String)
```java
public String getEmailFromToken(String token) {
    SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    Claims claims = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token)
        .getBody();
    return claims.getSubject();
}
```

### 5. OAuth2 Success Handler Enhancement

**Updates to:** `src/main/java/com/isoplatform/api/auth/handler/OAuth2AuthenticationSuccessHandler.java`

**Changes:**
```java
@Override
public void onAuthenticationSuccess(HttpServletRequest request,
                                   HttpServletResponse response,
                                   Authentication authentication) throws IOException {
    OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
    String email = oauth2User.getAttribute("email");

    User user = userRepository.findByEmail(email)
        .orElseThrow(() -> new RuntimeException("User not found after OAuth2 login"));

    // Generate token pair
    String accessToken = jwtTokenProvider.generateToken(user);
    RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

    // Redirect with deep link
    String targetUrl = UriComponentsBuilder
        .fromUriString("totaload://oauth2/callback")
        .queryParam("accessToken", accessToken)
        .queryParam("refreshToken", refreshToken.getToken())
        .queryParam("tokenType", "Bearer")
        .queryParam("expiresIn", 3600)
        .encode()
        .toUriString();

    log.info("Redirecting to mobile app: {}", targetUrl);
    getRedirectStrategy().sendRedirect(request, response, targetUrl);
}
```

### 6. Controllers

#### AuthController (New)

**Location:** `src/main/java/com/isoplatform/api/auth/controller/AuthController.java`

**Endpoints:**

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {
        AuthResponse response = localAuthService.signup(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = localAuthService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        AuthResponse response = refreshTokenService.refreshAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal User user,
                                       @Valid @RequestBody LogoutRequest request) {
        refreshTokenService.deleteByToken(request.getRefreshToken());
        return ResponseEntity.noContent().build();
    }
}
```

### 7. Security Configuration Updates

**Updates to:** `src/main/java/com/isoplatform/api/config/SecurityConfig.java`

**Changes:**
```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers(
                "/api/health",
                "/api/auth/signup",
                "/api/auth/login",
                "/api/auth/refresh",
                "/login/oauth2/**",
                "/oauth2/**",
                "/swagger-ui/**",
                "/v3/api-docs/**"
            ).permitAll()
            .anyRequest().authenticated()
        )
        .oauth2Login(oauth2 -> oauth2
            .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
            .successHandler(oAuth2AuthenticationSuccessHandler)
            .failureHandler(oAuth2AuthenticationFailureHandler)
        )
        // Add JWT filter before UsernamePasswordAuthenticationFilter
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .exceptionHandling(exception -> {
            exception.accessDeniedHandler(new Http403Handler(objectMapper));
            exception.authenticationEntryPoint(new Http401Handler(objectMapper));
        })
        .csrf(csrf -> csrf.disable());

    return http.build();
}

@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

## Error Handling

### Error Response Format

All authentication errors return this JSON structure:
```json
{
  "error": "UNAUTHORIZED",
  "errorCode": "TOKEN_EXPIRED",
  "message": "Access token has expired",
  "timestamp": "2025-11-21T10:30:00Z",
  "path": "/api/some-endpoint"
}
```

### Error Codes

| Error Code | HTTP Status | Description | Client Action |
|-----------|-------------|-------------|---------------|
| `TOKEN_EXPIRED` | 401 | Access token expired | Auto-refresh with refresh token |
| `TOKEN_INVALID` | 401 | Token signature/format invalid | Redirect to login |
| `TOKEN_MISSING` | 401 | No Authorization header | Redirect to login |
| `REFRESH_TOKEN_EXPIRED` | 401 | Refresh token expired | Redirect to login |
| `REFRESH_TOKEN_NOT_FOUND` | 401 | Refresh token not in database | Redirect to login |
| `USER_NOT_FOUND` | 401 | User deleted but token valid | Redirect to login |
| `USER_DISABLED` | 403 | User account deactivated | Show "Account disabled" message |
| `INVALID_CREDENTIALS` | 401 | Wrong email/password | Show error on login form |
| `EMAIL_ALREADY_EXISTS` | 400 | Duplicate email on signup | Show error on signup form |
| `WEAK_PASSWORD` | 400 | Password doesn't meet requirements | Show validation error |

### Exception Handler

**Class:** `GlobalAuthenticationExceptionHandler`

**Location:** `src/main/java/com/isoplatform/api/auth/exception/GlobalAuthenticationExceptionHandler.java`

```java
@RestControllerAdvice
public class GlobalAuthenticationExceptionHandler {

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ErrorResponse> handleExpiredToken(ExpiredJwtException ex) {
        ErrorResponse error = ErrorResponse.builder()
            .error("UNAUTHORIZED")
            .errorCode("TOKEN_EXPIRED")
            .message("Access token has expired")
            .timestamp(LocalDateTime.now())
            .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(BadCredentialsException ex) {
        ErrorResponse error = ErrorResponse.builder()
            .error("UNAUTHORIZED")
            .errorCode("INVALID_CREDENTIALS")
            .message("Invalid email or password")
            .timestamp(LocalDateTime.now())
            .build();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }

    // ... other exception handlers
}
```

## Security Considerations

### 1. Password Security
- **Hashing**: BCrypt with default strength (10 rounds)
- **Validation**: Minimum 8 characters, must contain letters and numbers
- **Storage**: Never store plaintext passwords

### 2. Token Security
- **Access Token**: Short-lived (1 hour), stateless JWT
- **Refresh Token**: Long-lived (7 days), stored in database with UUID (not JWT)
- **Transmission**: Always via Authorization header over HTTPS
- **Storage**: Mobile apps use Keychain (iOS) / Keystore (Android)

### 3. CORS Configuration
- Maintain existing CORS settings
- Allow only trusted frontend domains
- Credentials allowed for cookie-based session (if needed)

### 4. Rate Limiting (Future Enhancement)
- Login endpoint: 5 attempts per 5 minutes per IP
- Signup endpoint: 3 attempts per hour per IP
- Refresh endpoint: 10 attempts per minute per user

### 5. Audit Logging
- Log all authentication attempts (success/failure)
- Log refresh token generation and usage
- Log suspicious activities (e.g., rapid refresh attempts)

### 6. Token Revocation
- Immediate: Delete refresh tokens from database
- Eventual: Access tokens expire naturally (can't be revoked until expiry)
- User logout: Delete all refresh tokens for that user
- Account deactivation: Delete all refresh tokens + block at filter level

## Database Schema Changes

### New Table: refresh_tokens

```sql
CREATE TABLE refresh_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    device_info VARCHAR(500),

    INDEX idx_token (token),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at),

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### Modifications to users table

No schema changes needed. Existing fields support both LOCAL and OAuth2 users:
- `provider`: "LOCAL" or "GOOGLE"
- `providerId`: email (for LOCAL) or Google sub (for OAuth2)
- `password`: BCrypt hash (for LOCAL) or "OAUTH2_USER" (for OAuth2)

## API Specification

### POST /api/auth/signup

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "name": "홍길동"
}
```

**Response (201):**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

**Errors:**
- 400: Email already exists, weak password, invalid email format

### POST /api/auth/login

**Request:**
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```

**Response (200):**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

**Errors:**
- 401: Invalid credentials
- 403: Account disabled

### POST /api/auth/refresh

**Request:**
```json
{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200):**
```json
{
  "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

**Errors:**
- 401: Refresh token not found, expired, or user disabled

### POST /api/auth/logout

**Request:**
```json
{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response (204):** No content

**Errors:**
- 401: Not authenticated

## Testing Strategy

### Unit Tests

1. **JwtTokenProvider**
   - Token generation with correct claims
   - Token validation (valid, expired, invalid signature)
   - Email extraction from token

2. **LocalAuthService**
   - Signup with valid/invalid data
   - Login with correct/incorrect credentials
   - Password encoding verification

3. **RefreshTokenService**
   - Token creation with correct expiration
   - Token refresh with valid/expired tokens
   - Token deletion

### Integration Tests

1. **JwtAuthenticationFilter**
   - Request with valid token → authentication set
   - Request with expired token → 401 response
   - Request without token → passes through for permitAll paths

2. **Auth Endpoints**
   - Signup → verify user created, tokens returned
   - Login → verify tokens returned, lastLoginAt updated
   - Refresh → verify new access token generated
   - Logout → verify refresh token deleted

3. **Security Configuration**
   - Public endpoints accessible without token
   - Protected endpoints require valid token
   - Invalid token returns 401 with correct error code

### Manual Testing (Mobile App)

1. **OAuth2 Flow**
   - Google login redirects to `totaload://` with tokens
   - App can parse and store tokens

2. **Local Auth Flow**
   - Signup creates account and returns tokens
   - Login returns tokens for existing account

3. **Token Usage**
   - API calls with valid token succeed
   - API calls with expired token trigger auto-refresh
   - API calls after refresh succeed with new token

## Implementation Checklist

### Phase 1: Core Infrastructure
- [ ] Create `RefreshToken` entity and repository
- [ ] Create `RefreshTokenService` with CRUD operations
- [ ] Enhance `JwtTokenProvider` with validation methods
- [ ] Create `LocalAuthService` with signup/login logic
- [ ] Add `PasswordEncoder` bean to SecurityConfig

### Phase 2: Filter and Security
- [ ] Implement `JwtAuthenticationFilter`
- [ ] Update `SecurityConfig` to add filter and new public paths
- [ ] Create `GlobalAuthenticationExceptionHandler`

### Phase 3: Controllers
- [ ] Create `AuthController` with signup/login/refresh/logout endpoints
- [ ] Update `OAuth2AuthenticationSuccessHandler` for token pair + deep link

### Phase 4: Testing
- [ ] Write unit tests for all services
- [ ] Write integration tests for auth endpoints
- [ ] Write integration tests for filter
- [ ] Manual testing with mobile app

### Phase 5: Documentation
- [ ] Update API documentation (Swagger)
- [ ] Update README with new auth flows
- [ ] Create deployment notes for environment variables

## Configuration

### Environment Variables

Add to `.env`:
```bash
# JWT Configuration (existing)
JWT_SECRET=your_jwt_secret_key_min_256_bits
JWT_EXPIRATION_TIME=3600000

# Refresh Token Configuration (new)
REFRESH_TOKEN_EXPIRATION_DAYS=7

# Mobile App Configuration (new)
MOBILE_APP_SCHEME=totaload

# Google OAuth2 Configuration (existing)
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

# Frontend URL (existing)
FRONTEND_URL=http://localhost:3000
```

### application.yml Updates

```yaml
jwt:
  secret: ${JWT_SECRET}
  expiration-time: ${JWT_EXPIRATION_TIME:3600000}

refresh-token:
  expiration-days: ${REFRESH_TOKEN_EXPIRATION_DAYS:7}

mobile:
  app-scheme: ${MOBILE_APP_SCHEME:totaload}
```

## Deployment Considerations

### Database Migration
- Run migration script to create `refresh_tokens` table
- No data migration needed (fresh start for tokens)

### Backward Compatibility
- Existing OAuth2 users continue to work
- Old tokens (without refresh) will expire naturally
- No breaking changes to existing endpoints

### Rollback Plan
- Remove `JwtAuthenticationFilter` from SecurityConfig
- Revert `OAuth2AuthenticationSuccessHandler` changes
- Keep database tables (no harm in having them)

## Future Enhancements

### Short-term (Next Sprint)
- Email verification for local signups
- Password reset functionality
- Rate limiting on auth endpoints

### Medium-term (Next Quarter)
- Multi-factor authentication (TOTP)
- Social login providers (Apple, Kakao)
- Device management (list/revoke sessions)

### Long-term (6+ Months)
- Biometric authentication
- Passwordless login (magic links)
- OAuth2 provider (allow third-party apps to use our auth)

## Conclusion

This design enhances the authentication system with industry-standard practices:
- **JWT validation** ensures API security
- **Refresh tokens** provide smooth user experience without compromising security
- **Local authentication** gives users more signup options
- **Secure token delivery** protects mobile app users

The hybrid approach balances pragmatism with best practices, delivering value quickly while maintaining code quality and extensibility.
