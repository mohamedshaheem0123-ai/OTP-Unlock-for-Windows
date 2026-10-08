# 🔐 OTP-Based Laptop Authentication System

A secure authentication system built with **Python** and **FastAPI**, using **One-Time Password (OTP)** verification to provide an additional layer of security during user authentication.

The project is designed to demonstrate secure user registration, password-based login, authenticator-based OTP verification, and password recovery functionality.

---

## 🚀 Features

- 🔑 Secure user registration and login
- 🔐 Password-based authentication
- 📱 Authenticator-based OTP / TOTP verification
- 🔢 6-digit time-based OTP authentication
- 🔄 Forgot Password functionality
- 🛡️ Session-based authentication
- 🔒 Encrypted security data using Fernet
- 🗄️ SQLite database support
- 📚 Interactive FastAPI Swagger documentation
- ⚡ Lightweight and easy to run locally

---

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| FastAPI | REST API framework |
| SQLite | Database |
| TOTP | One-Time Password authentication |
| Authenticator App | OTP generation |
| Fernet | Data encryption |
| Uvicorn | Application server |
| HTML/CSS | Web interface |

---

## 📁 Project Structure


OTP/
│
├── main.py              # FastAPI application and authentication logic
├── requirements.txt     # Python dependencies
├── otp_auth.db          # SQLite database (generated locally)
├── .venv/               # Python virtual environment
│
└── templates/           # Web interface templates
