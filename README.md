# Master Canteen — Smart QR Ordering, Digital Meal Tokens & KDS

A full-stack real-time Food Ordering, Digital Meal Token, and Kitchen Display System (KDS) built with **Node.js**, **Express**, **EJS**, and a hybrid **PostgreSQL / MySQL / In-Memory** data layer.

## Key Features
- **Table & Express Takeaway QR Ordering (`/order/t01` ... `/order/takeaway`)**: Category-filtered menu, live cart, simulated multi-mode checkout, scannable Pickup QR Meal Tokens, and real-time order tracking.
- **Real-Time Kitchen Display System (`/kitchen/screen`)**: Live ticket polling with audio chime notifications, status transitions (`Pending -> Preparing -> Ready -> Delivered`), configurable auto-hide timers, and IP whitelist firewall.
- **Live 15-Second Canteen PIN Display (`/canteen/display`)**: Rotating 6-digit TOTP-style display screen to optionally verify physical presence in campus/corporate dining halls.
- **Admin HQ Dashboard (`/admin`)**:
  - Live revenue/order stats, KOT & active cart monitoring, food menu & table QR poster generator.
  - Configurable sequential order/KOT numbering (`ORD-`, `KOT-`, zero-padding, counter reset).
  - Admin Login Credentials manager (change Admin ID & Password from Settings with `scrypt` hashing & DB persistence).
  - No-autofill login forms with show/hide eye toggles on ID & Password fields.

## Quick Start (Local)
```bash
npm install
cp .env.example .env
npm start
```
Open:
- Customer Menu: `http://localhost:3000/order/1`
- Admin Portal: `http://localhost:3000/admin/login`
- Kitchen Display: `http://localhost:3000/kitchen/screen`
- Live TV PIN Display: `http://localhost:3000/canteen/display`

## Render / Cloud Deployment
1. Set `DATABASE_URL` (PostgreSQL), `SESSION_SECRET`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD` in environment variables.
2. Build Command: `npm install`
3. Start Command: `npm start`
4. On first boot, `server.js` runs `schema_postgres.sql`, seeds initial tables/settings, and persists any updated Admin credentials & toggles in `system_settings`.
