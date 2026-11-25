# Master Canteen — Smart QR Ordering, Digital Meal Tokens & KDS

A full-stack, mobile-responsive **QR Table Food Ordering**, **Digital Meal Token**, and **Real-Time Kitchen Display System (KDS)** built with **Node.js**, **Express**, **EJS**, and a hybrid **PostgreSQL / MySQL / In-Memory** architecture.

🌐 **Live Demo:** https://master-canteen.onrender.com

---

## Live Routes & Demo Screens

| Module | Live Route | Description |
| :--- | :--- | :--- |
| **Customer Table Ordering** | [`/order/1`](https://master-canteen.onrender.com/order/1) | Category-filtered menu, cart, checkout simulation, scannable Pickup QR Meal Token & live status tracking |
| **Express Takeaway Ordering** | [`/order/takeaway`](https://master-canteen.onrender.com/order/takeaway) | Standee QR ordering flow for takeaway / counter pickup |
| **Admin HQ Dashboard** | [`/admin/login`](https://master-canteen.onrender.com/admin/login) | Responsive sidebar dashboard for orders, KOT, active carts, menu CRUD, QR poster printing, IP whitelist & settings |
| **Kitchen Display Screen (KDS)** | [`/kitchen/screen`](https://master-canteen.onrender.com/kitchen/screen) | Real-time ticket board with audio chime alerts, status progression & IP whitelist firewall |
| **Live TV PIN Display** | [`/canteen/display`](https://master-canteen.onrender.com/canteen/display) | Rotating 15-second 6-digit security PIN screen for optional physical-presence verification |

---

## Tech Stack

| Layer | Technologies Used |
| :--- | :--- |
| **Backend & Runtime** | Node.js, Express.js (`4.x`), `express-session`, `cookie-parser`, `cors`, `dotenv`, `uuid` |
| **Security & Auth** | `crypto` (`scryptSync` + `timingSafeEqual` password hashing), `passport` & `passport-google-oauth20`, IP Whitelist Firewall, 15s Rotating TOTP-style PIN |
| **Database Layer** | PostgreSQL (`pg`) for Cloud/Render, MySQL (`mysql2`) fallback, In-Memory `Map`/Array fallback for zero-setup demos |
| **Frontend & UI** | EJS Templates, Responsive HTML5/CSS3 (Mobile Drawer + Tablet + Desktop), Vanilla JS Real-Time Polling, Web Audio API, `canvas-confetti`, QR Code API |
| **Deployment** | GitHub + Render Web Service + Neon PostgreSQL |

---

## Key Features

- **Responsive Multi-Device UI:** Designed cleanly for Phone, Tablet, and Laptop with a slide-over mobile admin drawer and scrollable data tables.
- **Scannable Pickup QR Meal Tokens:** Every placed order renders a digital token card with a scannable pickup QR code and real-time kitchen status updates.
- **Sequential Order & KOT Numbering:** Configurable prefix, suffix, zero-padding (`ORD-001000` / `KOT-001000`), and counter reset persisted in PostgreSQL.
- **Dynamic Admin Security & Credentials:** No-autofill login forms with show/hide eye toggles on ID & Password fields, plus an Admin Settings panel to update Admin ID & Password (persisted in `system_settings`).
- **Kitchen IP Whitelist & Auto-Hide:** Restricts `/kitchen/screen` to whitelisted device IPs (or `*` for demo mode) and auto-hides completed tickets after a configurable duration.

---

## Core REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/menu/categories` | Fetch active food categories |
| `GET` | `/api/v1/menu/items` | Fetch active menu items |
| `POST` | `/api/v1/cart/items` | Add or update cart items |
| `POST` | `/api/v1/cart/payments/cashfree/verify` | Verify checkout, generate sequential `ORD-`/`KOT-`, and dispatch ticket |
| `GET` | `/api/v1/orders/:uuid/tracking` | Poll live order status |
| `GET` | `/kitchen/api/tickets` | Fetch KDS tickets and `auto_hide_minutes` setting |
| `PATCH` | `/kitchen/api/tickets/:uuid/status` | Update order/ticket status (`preparing`, `ready`, `delivered`, `cancelled`) |
| `POST` | `/api/v1/admin/settings/credentials` | Update Admin ID & Password (authenticated) |
| `GET` | `/api/v1/admin/kitchen-ips` | Fetch allowed kitchen IP whitelist |

---

## Local Setup

```bash
npm install
cp .env.example .env
npm start
```

Open `http://localhost:3000/order/1` or `http://localhost:3000/admin/login`.

> Runs out of the box with in-memory fallback even if PostgreSQL/MySQL is not running locally.

---

## Render Deployment

1. Create a **Web Service** on Render connected to this repository.
2. **Build Command:** `npm install`
3. **Start Command:** `npm start`
4. **Environment Variables:**
   - `DATABASE_URL` — PostgreSQL connection string (`schema_postgres.sql` runs automatically on startup)
   - `SESSION_SECRET` — Strong random session secret
   - `ADMIN_USERNAME` / `ADMIN_PASSWORD` — Initial admin credentials (can be changed later from Admin Settings)
