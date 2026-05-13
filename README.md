# AnomalyFi : AI-Driven Insider Threat Detection System

AnomalyFi is a cybersecurity-focused web application designed to detect suspicious insider activities using Machine Learning and behavioral analysis. The system monitors user file operations, analyzes activity patterns, calculates an Insider Threat Score (ITS), and automatically classifies users into risk categories.

The project combines Flask-based web development, SQLite database management, session tracking, and Isolation Forest anomaly detection to simulate a modern insider threat detection environment.

- Features
* User Authentication System
* Role-Based Access Control (Admin/User)
* Real-Time Session Monitoring
* File Activity Tracking
  * Open files
  * Copy files
  * Delete files
* Machine Learning–Based Anomaly Detection
* Insider Threat Score (ITS) Generation
* Risk Classification (Low / Medium / High)
* Automatic User Blocking for High-Risk Sessions
* Admin Dashboard APIs
* Activity Logging in SQLite + CSV
* Simulated Enterprise File Environment

- Technology Stack
(Backend)
* Python
* Flask
- Machine Learning
* Scikit-learn
* Isolation Forest
* Pandas
* NumPy

- Database
* SQLite3

- Frontend
* HTML
* CSS
* JavaScript

- Security
* SHA-256 Password Hashing
* Session Management
* Role-Based Authentication

# Project Architecture
User Activity
→ Session Monitoring
→ Feature Engineering
→ Isolation Forest ML Model
→ ITS Score Generation
→ Risk Classification
→ Automated Response & Dashboard Visualization

- Machine Learning Model
The project uses the Isolation Forest algorithm for unsupervised anomaly detection.

= Features Used
* Login Time
* Files Accessed
* Files Deleted
* Files Copied
* Session Duration
* Copy Rate
* Delete Rate
* Access Rate
* Activity Rate

- Risk Levels
* Low Risk: 0–39
* Medium Risk: 40–69
* High Risk: 70–100


- Admin Dashboard Capabilities
* Monitor all user activities
* View ITS score trends
* Analyze login hour distribution
* Detect suspicious activity patterns
* View risk classification
* Monitor blocked users

- Future Enhancements
* Real-Time OS-Level File Monitoring
* SIEM Integration
* Multi-Factor Authentication
* Advanced Analytics Dashboard
* Live Alert Notifications
* Cloud Deployment
* RBAC Expansion

- Academic Purpose
This project was developed for academic and educational purposes to demonstrate the implementation of AI-driven behavioral analysis and insider threat detection concepts in cybersecurity.

# Team Members
* Priya
* Taniya
* Priyani

Project Guide: Ms. Shyna Babbar

- License

This project is intended for educational and research purposes only.
