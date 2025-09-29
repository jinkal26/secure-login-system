# Secure Login System with User Role Management

## Project Overview
This project is a secure web-based login system that implements user authentication, authorization, and role-based access control (RBAC). It provides a practical way to apply cybersecurity concepts in a development environment.

---

## Features

- **User Registration & Login:** Users can register and log in with secure credentials.  
- **Role-Based Access Control:** Admins can manage users; regular users have restricted access.  
- **Security Features:**  
  - Password hashing using bcrypt  
  - Input validation to prevent SQL injection  
  - CAPTCHA verification (optional)  
  - Account lockout after multiple failed login attempts  

---

## Technology Stack

- **Backend:** Python, Flask  
- **Database:** SQLite (via SQLAlchemy ORM)  
- **Frontend:** HTML, CSS  
- **Security:** Bcrypt for password hashing, JWT for authentication  

---

## Setup Instructions

1. Clone Repository
git clone <your-github-repo-url>
cd secure-login-system

2. Create Virtual Environment
python -m venv venv
.\venv\Scripts\activate  # Windows

# source venv/bin/activate  # macOS/Linux

3. Install Dependencies
pip install -r requirements.txt

4. Set Environment Variables
$env:ENABLE_CAPTCHA="1"
$env:RECAPTCHA_SECRET="your_secret_here"
$env:LOGIN_FAILED_LIMIT="5"
$env:LOCK_TIME_MINUTES="15"

5. Initialize Database
python init_db.py

6. Run Application
python sun.py

Open http://127.0.0.1:5000
 in your browser.

 | Challenge                 | Solution                                             |
| ------------------------- | ---------------------------------------------------- |
| Account lockout handling  | Added `failed_attempts` and `lock_until` in database |
| Password security         | Used bcrypt for hashing and verification             |
| Role-based access control | Middleware to restrict access based on user roles    |
| Brute force protection    | CAPTCHA and account lockout implemented              |
| Database errors           | Re-created database with required columns            |
