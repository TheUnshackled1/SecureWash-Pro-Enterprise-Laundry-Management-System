# Secure WashBar Laundry Management System

## Features

### Security Enhancements
- **Password Encryption**: PBKDF2 with SHA-256 hashing and salt
- **Password Complexity**: Enforced strong password requirements
- **Session Management**: Automatic timeout and token-based sessions
- **Input Sanitization**: Protection against injection attacks
- **Audit Logging**: Complete activity tracking
- **Account Lockout**: Protection against brute force attacks
- **Role-Based Access Control (RBAC)**: Admin and Customer roles

### Database Migration
- **SQLite3**: Replaced JSON files with secure database
- **Encrypted Storage**: Sensitive data encryption
- **Data Integrity**: Foreign key constraints and validation
- **Backup Support**: Database-level backup capabilities

### RBAC Implementation
- **Admin Role**: Full system access, user management, inventory control
- **Customer Role**: Limited to own orders and basic operations
- **Permission Checking**: Method-level access control
- **Session-based Authentication**: Secure login/logout system

### Additional Security Features
- **File Permissions**: Restricted access to configuration files
- **Security Questions**: Password recovery mechanism
- **Failed Login Tracking**: Automatic account lockout
- **Session Tokens**: Secure session management
- **Audit Trail**: Complete action logging

## Installation

1. Install required dependencies:
\`\`\`bash
pip install cryptography
\`\`\`

2. Run the application:
\`\`\`bash
python secure-laundry-system.py
\`\`\`

## Default Admin Account
- Username: admin
- Password: admin123!
- Security Question: What is your favorite drink?
- Security Answer: coke

## Security Configuration

The system includes configurable security settings in the `SecurityConfig` class:
- Session timeout: 30 minutes
- Max login attempts: 3
- Account lockout duration: 15 minutes
- Password requirements: 8+ characters, uppercase, lowercase, numbers, special chars

## Database Schema

The system uses SQLite3 with the following tables:
- `users`: User accounts with encrypted passwords
- `orders`: Laundry orders with audit trail
- `inventory`: Supply tracking with update history
- `audit_log`: Complete activity logging
- `user_sessions`: Session management

## File Structure

- `secure-laundry-system.py`: Main application
- `laundry_system.db`: SQLite database (auto-created)
- `security.key`: Encryption key (auto-generated)
- `security_audit.log`: Security event log

## Usage

2. **Login**: Secure authentication with session management
3. **Order Management**: Add, view, and manage laundry orders
4. **Inventory Control**: Admin-only inventory management
5. **Reports**: Generate sales and activity reports
6. **User Management**: Admin tools for user administration

## Security Best Practices Implemented

1. **Password Security**: Strong hashing with salt and iterations
2. **Session Security**: Token-based with automatic expiration
3. **Input Validation**: Sanitization and length limits
4. **Access Control**: Role-based permissions
5. **Audit Logging**: Complete activity tracking
6. **Error Handling**: Secure error messages
7. **File Security**: Restricted file permissions
8. **Database Security**: Parameterized queries and constraints
