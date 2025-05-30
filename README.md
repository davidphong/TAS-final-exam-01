# TAS Final Exam - Vulnerable Web Application

This Flask application was created for cybersecurity education purposes as a final exam project. It intentionally contains multiple vulnerabilities forming a complete attack chain.

## Intentional Vulnerabilities

The application contains the following intentional vulnerabilities:

1. **Information Disclosure** - An exposed backup file with MD5 hashed passwords
2. **SQL Injection** - Vulnerable search functionality 
3. **Broken Access Control (IDOR)** - Vulnerable email update feature
4. **SSRF** - Vulnerable URL fetcher in admin panel

## Setup Instructions

### Option 1: Run directly with Python

```bash
# Clone the repository
git clone [repository-url]
cd TAS-final-exam-01

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Option 2: Run with Docker

```bash
# Clone the repository
git clone [repository-url]
cd TAS-final-exam-01

# Build and run with Docker Compose
docker-compose up
```

The application will be available at http://localhost:1111.

## Database

The application uses SQLite for its database. The database is initialized automatically when you start the application for the first time. If you need to reset the database, simply delete the `database.db` file and restart the application.

## User Accounts

The application comes with several pre-configured user accounts:

- **Regular User**: username: `flag`, password: `qwerty123`
- **Admin User**: username: `admin`, password: `TAS{IDOR_vuln3r4b1l1ty_l34ds_t0_pr1v1l3g3_3sc4l4t10n}`
- **Other Users**: Several other regular users are created (user1, user2, etc. with passwords password1, password2, etc.)

## Attack Chain

This application is designed to be exploited through a series of steps:

1. **Discover Information Disclosure**: Find the exposed backup file containing MD5 hashed passwords
2. **Crack MD5 Hashes**: Use the exposed password hashes to gain access to user accounts
3. **Exploit SQL Injection**: Use the vulnerable search functionality to extract sensitive information
4. **Exploit IDOR**: Use the broken access control in the email update feature to escalate privileges
5. **Exploit SSRF**: Use the vulnerable URL fetcher in the admin panel to access internal resources

## Features

- User authentication system
- Blog posts with comments
- User profiles
- Search functionality
- Admin panel with URL fetcher

## Technologies

- Flask (Python web framework)
- SQLite (Database)
- Bootstrap (Frontend)
- JavaScript/jQuery

## Warning

This application is intentionally vulnerable and should **NEVER** be deployed in a production environment or exposed to the public internet. It is designed solely for educational purposes in a controlled environment.

## Educational Resources

To learn more about these vulnerabilities, check out:

- [OWASP Top 10](https://owasp.org/www-project-top-10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [SANS Internet Storm Center](https://isc.sans.edu/)

## License

This project is licensed under the MIT License - see the LICENSE file for details. 