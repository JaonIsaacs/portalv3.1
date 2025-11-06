# Customer Portal (React + Express + MongoDB)



A secure web application featuring user authentication and protected routes using React, Express.js, and MongoDB.

 Overview

This project implements a modern web application with a secure authentication system with demonstrating industry best practices for web security and user management.

 Features

- Secure user authentication system
- Protected routes and resources
- Comprehensive security measures against common web attacks
- Rate limiting and brute force protection
- CSRF protection
- XSS prevention
- Input validation and sanitization



 Setup Instructions

 Prerequisites

- Node.js (v14 or higher)
- MongoDB
- npm or yarn

 Backend Setup

1. Navigate to the backend directory:
   
   cd backend
  

2. Install dependencies:
   
   npm install
   

3. Create a `.env` file with the following variables:

   PORT=3000
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_jwt_secret
   CORS_ORIGIN=http://localhost:5173
  

 Frontend Setup

1. Navigate to the frontend directory:
   
   cd frontend
   

2. Install dependencies:
  
   npm install
   

3. Start the development server:
   
   npm run dev
  
  Credentials:

  Email: Test@Admin.com
  Password:Jason123

Security Implementation

- Password hashing and salting with bcrypt
- Input whitelisting with regex (server and client)
- HTTPS support with instructions for self-signed certificates
- Comprehensive security middleware stack
- CORS and CSRF protection
- Rate limiting and DDoS protection


Important note:

if issues arrise please change revbiews section in dependabot.yml to matching user
 References and Resources

 Security Implementation
[OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
[Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

 Authentication
[JWT.io Documentation](https://jwt.io/introduction)
 [OAuth 2.0 Specifications](https://oauth.net/2/)
[Passport.js Documentation](http://www.passportjs.org/docs/)

Frontend Framework
[React Documentation](https://react.dev/reference/react)
[Vite Documentation](https://vitejs.dev/guide/)
[React Router Documentation](https://reactrouter.com/en/main)

 Backend Framework
[Express.js Documentation](https://expressjs.com/)
[Node.js Security Checklist](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
[MongoDB Best Practices](https://www.mongodb.com/docs/manual/administration/security-checklist/)
