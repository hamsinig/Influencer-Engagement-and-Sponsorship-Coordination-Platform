# Influencer Engagement & Sponsorship Coordination Platform

## Overview

The **Influencer Engagement & Sponsorship Coordination Platform** connects sponsors with influencers, allowing sponsors to advertise products/services while influencers earn monetary benefits through campaigns and ad requests.

This project implements role-based workflows, campaign management, asynchronous tasks, and a dynamic frontend.

---

## Tech Stack

### Core Frameworks

- **Flask** – Backend API  
- **SQLite** – Database (mandatory)  
- **Bootstrap** – Responsive UI styling  
- **Redis & Celery** – Caching + asynchronous background jobs  
- **Vue.js** – Frontend rendering and SPA behavior  

---

## User Roles

### Admin
- Full monitoring of users, campaigns, and ad requests  
- Approves sponsor signups  
- Flags inappropriate content  

### Sponsor
- Creates and manages campaigns  
- Sends ad requests to influencers  
- Tracks campaign performance  
- Searches influencers by niche, reach, and followers  

### Influencer
- Accepts/rejects ad requests  
- Negotiates terms  
- Participates in public campaigns  
- Searches campaigns by relevance  

---

## Key Terminologies

- **Campaign** – Sponsor-created initiative managing multiple ad requests  
- **Ad Request** – Contract between sponsor campaign and influencer defining requirements and payment  

---

## Core Features

### Role-Based Access Control (RBAC)
- Secure login/register system for Admin, Sponsor, and Influencer

### Admin Dashboard
- View statistics on users, campaigns, and flagged content  
- Approve sponsor registrations  

### Campaign Management (Sponsors)
- Create, update, delete campaigns  
- Set goals and visibility (public/private)  

### Ad Request Management
- Create, update, delete ad requests  
- Accept/reject requests  
- Negotiate terms  

### Search
- Sponsors search influencers  
- Influencers search public campaigns  

---

## Database Design

### Key Relationships

1. User ↔ Role (Many-to-many via `roles_users`)
2. Sponsor ↔ User (One-to-one)
3. Influencer ↔ User (One-to-one)
4. Campaign ↔ Sponsor (Many-to-one)
5. AdRequest ↔ Campaign (Many-to-one)
6. AdRequest ↔ Influencer (Many-to-one)
7. Flag ↔ Campaign / AdRequest / User (Tracks reported items)

---

## Asynchronous Tasks (Celery + Redis)

### monthly_report
- Generates sponsor performance reports  
- Converts to PDF  
- Emails reports to sponsors  

### send_daily_reminder
- Sends daily email reminders to influencers for pending ad requests  

### generate_campaign_csv
- Exports sponsor campaign data to CSV  
- Includes name, description, budget, goals  
- Provides downloadable file  

---

## Vue.js Integration

- Dynamic rendering using Axios API calls  
- Component-based UI (tables, modals, forms)  
- Reactive state management  
- Real-time form validation  
- Vue Router for SPA navigation  
- Event handling (`@click`, `@submit`) for user actions  

---

## Author

**G Hamsini**  
Registration No: 22F3000767  

---

## Project Purpose

Academic project demonstrating full-stack development with:

- Flask backend  
- Vue.js frontend  
- RBAC  
- Background job processing  
- Real-world sponsorship workflows  

---
