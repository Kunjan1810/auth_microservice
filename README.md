# Django Authentication Microservice

A simple and modular Django-based authentication microservice that supports:
- User registration with SMS-based OTP verification
- Login with phone number OTP
- Password reset via email
- Role-based access control using JWT (Admin, Manager, Employee)
- Account updates

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Kunjan1810/auth_microservice.git
cd auth_microservice
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
# Activate on Windows
venv\Scripts\activate
# Activate on macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Apply Migrations

```bash
python manage.py migrate
```

### 5. Run the Development Server

```bash
python manage.py runserver
```

---

## ⚙️ Email Configuration

To enable password reset via email, update the following in `auth_microservice/settings.py`:

```python
EMAIL_HOST_USER = '<your-email>'
EMAIL_HOST_PASSWORD = '<your-email-password>'
```

---

## 🧪 API Endpoints

Use [Postman](https://www.postman.com/) or `cURL` to test the following endpoints:

### 🔐 Authentication

| Method | Endpoint                      | Description                          |
|--------|-------------------------------|--------------------------------------|
| POST   | `/api/auth/register/`         | Register a new user                  |
| POST   | `/api/auth/login-request/`    | Request an OTP for login             |
| POST   | `/api/auth/login-verify/`     | Verify OTP and log in                |
| POST   | `/api/auth/password-reset/`   | Request a password reset link        |
| POST   | `/api/auth/set-new-password/` | Set a new password using reset link  |

### 🔑 Role-Based Access

| Method | Endpoint                   | Access Level           |
|--------|----------------------------|------------------------|
| GET    | `/api/auth/admin-only/`    | Admin only             |
| GET    | `/api/auth/manager-only/`  | Manager only           |
| GET    | `/api/auth/employee-only/` | Employee only          |
| GET    | `/api/auth/admin-manager/` | Admin and Manager only |

### 👤 Account Management

| Method | Endpoint                    | Description              |
|--------|-----------------------------|--------------------------|
| PUT    | `/api/auth/account-update/` | Update user account info |

---

## 📁 Project Structure

```
auth_microservice/
├── auth_microservice/         # Project settings and configuration
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
│   └── asgi.py
├── auth_app/                  # Authentication app
│   ├── models.py              # User models
│   ├── views.py               # API logic
│   ├── urls.py                # Routes for auth app
│   ├── permissions.py         # Role-based permissions
│   ├── utils.py               # Helper functions
│   ├── serializers.py         # DRF serializers (optional)
│   └── tests.py               # Unit tests
├── manage.py                  # Django management script
└── requirements.txt           # Python dependencies
```

---

## 📦 Dependencies

- Django
- Django REST Framework
- Django REST Framework Simple JWT

Install all using:

```bash
pip install -r requirements.txt
```

---

## 📄 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for more details.


---

## 📬 Submission Details

- **Repository:** https://github.com/your-username/auth_microservice  
- **⏱️ Time Spent:** ~6 hours  
- **🧱 Boilerplate Used:** None / You can mention if you used one like [jwt-django-starter](https://github.com/example/jwt-django-starter)
