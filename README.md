# 🐾 Puppy Vet - Veterinary Clinic Management System

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-green)
![DB](https://img.shields.io/badge/Database-SQL%20Server-red)
![Status](https://img.shields.io/badge/Status-Active-success)

**Puppy Vet** is a robust web application designed to digitize the workflow of a modern veterinary clinic. Built with **Python (Flask)** and **Microsoft SQL Server**, it serves as a complete solution for managing patients, medical history, appointments, and billing.

The application focuses on a seamless user experience for both veterinary staff and pet owners, featuring real-time notifications, secure authentication, and automated document generation.

---

## 📸 Application Gallery

### 1. Clinic Dashboard
*A comprehensive overview featuring real-time counters for patients, owners, and consultations, along with data visualization for species distribution.*
![Dashboard View](screenshots/dashboard.png)

### 2. Appointment Management
*Staff can view pending requests. The system uses a visual workflow: Yellow (Pending), Green (Confirmed), and Red (Cancelled).*
![Appointments List](screenshots/appointments.png)

### 4. Medical History & Invoicing
*Detailed tracking of every visit (Weight, Temp, Diagnosis) and automated PDF invoice generation for payments.*
![Medical History](screenshots/istoricmedical.png)


---

## 🗓️ Project Management & Workflow

To keep the development focused and avoid "feature creep," I adopted an **Agile/Kanban** workflow. This allowed me to prioritize critical features (like the Medical History) over "nice-to-have" ones (like SMS reminders).

![Workflow](screenshots/github_project_ideas.png)

### 🚀 Development Roadmap Status

#### ✅ Phase 1: The Foundation (Core)
* **Completed:** Setup Flask Environment, SQL Connection, and User Authentication (Login/Register/Google).
* *Why:* Without a secure base, building features is risky.

#### ✅ Phase 2: Data Logic (The "Brain")
* **Completed:** Database Schema, Patient CRUD, Medical History, Vaccination Logic.
* *Why:* This is the core business logic. I spent the most time here ensuring the SQL relationships were correct.

#### ✅ Phase 3: Interactivity (The "Flow")
* **Completed:** Appointment Requests, Confirmation Workflow (Modals), Notifications.
* *Why:* This connects the data to the daily human workflow of the clinic.

#### ✅ Phase 4: Business Intelligence (The "Value")
* **Completed:** Dashboard Analytics, PDF Invoicing.
* *Why:* Converting raw data into insights (Charts) and documents (Invoices) adds real business value.

#### 🚧 Phase 5: Future Iterations (Backlog & In Progress)
* [ ] **Automated SMS Reminders** `in-progress` - Working on Twilio integration.
* [ ] **Inventory Management** `planned` - To track medicine stock.
* [ ] **Mobile App API** `future` - Exposing endpoints for a React Native app.


## ✨ Key Features

### 🔐 Security & Authentication
* **Custom Auth System:** Secure registration and login using **Bcrypt** hashing.
* **Google OAuth Integration:** One-click login using Google accounts.
* **Password Recovery:** Full email-based flow for resetting forgotten passwords.
* **Session Security:** "Remember Me" functionality with secure, HTTP-only cookies.

### 🏥 Patient & Medical Management
* **Digital Health Cards:** Store consultation logs, diagnostics, treatments, weight, and temperature.
* **Vaccination Tracking:** Manage vaccine records and automatically calculate booster (Rapel) dates.
* **Owners Database:** Link multiple animals to a single owner profile.
* **Smart Search:** Quickly find patients by name or owner details.

### 📅 Advanced Appointment System
* **Request System:** Owners can request appointments via a dedicated form.
* **Notification Center:** Real-time bell notifications in the top bar for new pending requests and today's schedule.
* **Approval Workflow:** Admins/Doctors can **Confirm** or **Reject** appointments using interactive buttons.

### 💰 Financial Module
* **Payment Tracking:** Log payments and view financial history per client.
* **PDF Invoicing:** Automatic generation of professional PDF invoices using the `FPDF` library.

---

## 🛠️ Tech Stack

### Backend
* **Language:** Python 3.x
* **Framework:** Flask
* **Database:** Microsoft SQL Server (MSSQL)
* **ORM:** SQLAlchemy + PyODBC
* **Authentication:** Authlib (OAuth), Bcrypt
* **PDF Engine:** FPDF

### Frontend
* **UI Framework:** Bootstrap 4 (SB Admin 2 Theme)
* **Templating:** Jinja2
* **Scripting:** jQuery & Chart.js (for analytics)

---

## 🚀 Installation & Setup

Follow these steps to run the project locally:

### 1. Clone the repository
```bash
git clone [https://github.com/your-username/puppy-vet.git](https://github.com/your-username/puppy-vet.git)
cd puppy-vet
