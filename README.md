# mini_auth

A simple authentication microservice using Spring Boot with JWT-based user authentication and API key management for service authentication.

---

## Features

- User signup and login with JWT token generation
- JWT validation and authentication filter
- API key creation, validation, and revocation for service-to-service authentication
- Secure password hashing with BCrypt
- Stateless session management
- Role-based authorization support
- RESTful API design

---

## Tech Stack

- Java 17+
- Spring Boot 3.x
- Spring Security
- JWT (JSON Web Tokens) via jjwt library
- Hibernate / JPA
- PostgreSQL (or any JPA-supported database)
- Lombok
- Maven or Gradle (build tool)

---

## Getting Started

### Prerequisites

- Java 17 or higher
- Maven or Gradle
- PostgreSQL (or any compatible database)
- Postman or similar API client for testing

### Configuration

Create an `application.properties` or `application.yml` file in `src/main/resources` with the following minimum configuration:

```properties
# JWT secret key (keep it secure)
app.jwt.secret=your-very-secure-random-secret-key-of-appropriate-length

# JWT expiration time in milliseconds (default: 1 hour)
app.jwt.exp-ms=3600000

# Database connection (example for PostgreSQL)
spring.datasource.url=jdbc:postgresql://localhost:5432/mini_auth_db
spring.datasource.username=your_db_username
spring.datasource.password=your_db_password
spring.jpa.hibernate.ddl-auto=create-drop
```

## Running the Application

```properties
"mvn clean install"
"mvn spring-boot:run"

Application will start on http://localhost:8080
```

## API Endpoints

```properties
POST  ***/auth/signup
Registers a new user.

Request body (JSON):

{
"email": "user@example.com",
"password": "yourpassword",
"name": "User Name"
}
```

```properties
POST ***/auth/login
Logs in a user and returns a JWT token.

Request body (JSON):
{
  "email": "user@example.com",
  "password": "yourpassword"
}

Response:

{
  "token": "jwt-token-string"
}
```

```properties
API Keys

POST /keys/create?serviceName=your-service
Create a new API key for service authentication (requires SERVICE_ADMIN authority).

POST /keys/revoke/{keyId}
Revoke an API key by UUID (requires SERVICE_ADMIN authority).
```


## Security

- Passwords are securely hashed with BCrypt before storage.

- JWT tokens are signed and verified with a secure secret key.

- Stateless authentication to allow easy scaling.

- API key authentication supports service-to-service calls with revocation and expiration.



