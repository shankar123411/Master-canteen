const express = require('express');
const mysql = require('mysql2/promise');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const session = require('express-session');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'master_canteen_session_secret_2026',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// -------------------------------------------------------------
// GOOGLE OAUTH 2.0 AUTHENTICATION & PASSPORT SETUP
// -------------------------------------------------------------
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'DEMO_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'DEMO_GOOGLE_CLIENT_SECRET';
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `http://localhost:${PORT}/auth/google/callback`;

if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL
    },
    function(accessToken, refreshToken, profile, done) {
      const email = profile.emails && profile.emails[0] ? profile.emails[0].value : '';
      const name = profile.displayName || 'Campus Student';
      const avatar = profile.photos && profile.photos[0] ? profile.photos[0].value : '';
      const googleId = profile.id;

      // Restrict to campus email domain if configured in Admin settings or env (e.g. campus.edu)
      const activeDomain = orderNumberSettings.restrict_email_domain || process.env.RESTRICT_EMAIL_DOMAIN || '';
      if (activeDomain && activeDomain !== 'all' && activeDomain !== 'none' && !email.toLowerCase().endsWith(`@${activeDomain.toLowerCase()}`)) {
        return done(null, false, { message: `Only @${activeDomain} campus email addresses are allowed!` });
      }

      const studentUser = { googleId, email, name, avatar, provider: 'google' };
      return done(null, studentUser);
    }
  ));
}

// Google OAuth Routes
app.get('/auth/google', (req, res, next) => {
  if (req.headers.referer && !req.headers.referer.includes('/auth/')) {
    req.session.returnToOrderUrl = req.headers.referer;
  }
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.redirect('/auth/google/demo');
  }
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/order/1?auth_error=domain_restricted' }),
  (req, res) => {
    req.session.studentUser = req.user;
    const returnUrl = req.session.returnToOrderUrl || '/order/1';
    res.redirect(returnUrl + (returnUrl.includes('?') ? '&' : '?') + 'auth_success=1');
  }
);

// Demo 1-Click Google Sign-In (For Testing & Production Fallback)
app.get('/auth/google/demo', (req, res) => {
  const demoStudent = {
    googleId: 'demo_google_1001',
    email: 'demo.student@campus.edu',
    name: 'Demo Student (Campus User)',
    avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    provider: 'google_demo'
  };
  req.session.studentUser = demoStudent;
  const returnUrl = req.session.returnToOrderUrl || '/order/1';
  res.redirect(returnUrl + (returnUrl.includes('?') ? '&' : '?') + 'auth_success=1');
});

// Logout Student
app.get('/auth/logout', (req, res) => {
  req.session.studentUser = null;
  req.logout && req.logout(() => {});
  const returnUrl = req.session.returnToOrderUrl || '/order/1';
  res.redirect(returnUrl);
});

// User API
app.get('/api/v1/auth/user', (req, res) => {
  if (req.session && req.session.studentUser) {
    return res.json({ authenticated: true, user: req.session.studentUser });
  }
  return res.json({ authenticated: false, user: null });
});


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Admin Credentials Store (Configurable via .env & Admin Settings -> Persisted in DB)
const adminCredentials = {
  username: (process.env.ADMIN_USERNAME || 'admin').trim(),
  passwordPlainFallback: process.env.ADMIN_PASSWORD || 'canteenapp',
  passwordHash: null
};

function hashAdminPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(plain), salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyAdminPassword(plain, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, keyHex] = storedHash.split(':');
  const keyBuf = Buffer.from(keyHex, 'hex');
  const derived = crypto.scryptSync(String(plain), salt, 64);
  if (keyBuf.length !== derived.length) return false;
  return crypto.timingSafeEqual(keyBuf, derived);
}

function checkAdminCredentials(username, password) {
  const cleanUser = String(username || '').trim().toLowerCase();
  const cleanPass = String(password || '').trim();
  const expectedUser = String(adminCredentials.username || 'admin').trim().toLowerCase();

  if (!cleanUser || cleanUser !== expectedUser) return false;
  if (adminCredentials.passwordHash) {
    return verifyAdminPassword(cleanPass, adminCredentials.passwordHash);
  }
  return cleanPass === adminCredentials.passwordPlainFallback;
}

// Middleware to check admin session
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ message: 'Admin authentication required' });
  }
  res.redirect('/admin/login');
}

// ADMIN AUTHENTICATION & LOGIN ROUTES
app.get('/admin/login', (req, res) => {
  if (req.session && req.session.isAdmin) {
    return res.redirect('/admin');
  }
  res.render('admin-login');
});

// Alias Redirects to prevent "Cannot GET /order/admin/login" errors
app.get(['/order/admin/login', '/order/admin'], (req, res) => {
  res.redirect('/admin/login');
});

app.post('/api/v1/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (checkAdminCredentials(username, password)) {
      req.session.isAdmin = true;
      return res.json({ success: true, message: 'Admin login successful!', redirect: '/admin' });
    }
    return res.status(401).json({ message: 'Invalid Admin ID or Password!' });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.get('/admin/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(() => {
      res.redirect('/admin/login');
    });
  } else {
    res.redirect('/admin/login');
  }
});

// -------------------------------------------------------------
// KITCHEN DEVICE IP SECURITY WHITELIST (Strict Device IP Firewall)
// -------------------------------------------------------------
const allowedKitchenIps = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return (req.ip || req.connection.remoteAddress || '127.0.0.1').replace('::ffff:', '');
}

function checkKitchenIpAccess(req, res, next) {
  const clientIp = getClientIp(req);
  if (allowedKitchenIps.has('*') || allowedKitchenIps.has(clientIp)) {
    return next();
  }
  res.status(403).render('kitchen-access-denied', { clientIp });
}

// -------------------------------------------------------------
// DYNAMIC 15-SECOND CANTEEN SECURITY PIN (TOTP ORDER VERIFICATION)
// -------------------------------------------------------------
function generatePinForWindow(windowId) {
  const seed = (windowId * 9301 + 49297) % 233280;
  const pinNum = Math.floor((seed / 233280) * 900000) + 100000;
  return String(pinNum);
}

function getLiveCanteenPin() {
  const now = Date.now();
  const windowId = Math.floor(now / 15000); // 15-second window
  const secondsRemaining = Math.max(1, Math.floor((15000 - (now % 15000)) / 1000));
  const currentPin = generatePinForWindow(windowId);
  return { pin: currentPin, secondsRemaining, windowId };
}

function verifyCanteenPin(submittedPin) {
  if (!submittedPin) return false;
  const cleanPin = String(submittedPin).replace(/\s+/g, '').trim();
  const now = Date.now();
  const currentWindow = Math.floor(now / 15000);
  
  // Allow Current Window PIN, Previous Window PIN (15s grace), or Next Window PIN
  const validPins = [
    generatePinForWindow(currentWindow),
    generatePinForWindow(currentWindow - 1),
    generatePinForWindow(currentWindow + 1)
  ];
  return validPins.includes(cleanPin);
}

// -------------------------------------------------------------
// SEQUENTIAL ORDER / INVOICE & KOT NUMBERING CONFIGURATION
// -------------------------------------------------------------
let orderNumberSettings = {
  prefix: 'ORD-',
  suffix: '',
  digit_count: 6,
  current_counter: 1000,
  kot_prefix: 'KOT-',
  auto_hide_minutes: 0,
  allow_remote_preorder: true,
  require_google_auth: false,
  require_canteen_pin: false, // true = Canteen TV PIN check required, false = 1-click checkout
  restrict_email_domain: '' // '' = all emails allowed, 'campus.edu' = restricted to @campus.edu
};

function generateSequentialOrderNumber() {
  const currentNum = orderNumberSettings.current_counter;
  orderNumberSettings.current_counter += 1;
  const paddedNum = String(currentNum).padStart(parseInt(orderNumberSettings.digit_count || 6), '0');
  return `${orderNumberSettings.prefix || 'ORD-'}${paddedNum}${orderNumberSettings.suffix || ''}`;
}

function generateSequentialKotNumber(orderNum) {
  if (orderNum) {
    const rawDigits = orderNum.replace(/^[A-Za-z]+-?/, '').replace(/-?[A-Za-z]+$/, '');
    return `KOT-${rawDigits}`;
  }
  const currentNum = orderNumberSettings.current_counter - 1;
  const paddedNum = String(Math.max(1, currentNum)).padStart(parseInt(orderNumberSettings.digit_count || 6), '0');
  return `${orderNumberSettings.kot_prefix || 'KOT-'}${paddedNum}`;
}

function getNextPreviewOrderNumber() {
  const paddedNum = String(orderNumberSettings.current_counter).padStart(parseInt(orderNumberSettings.digit_count || 6), '0');
  return `${orderNumberSettings.prefix || 'ORD-'}${paddedNum}${orderNumberSettings.suffix || ''}`;
}

// -------------------------------------------------------------
// HYBRID DATABASE ADAPTER (PostgreSQL / MySQL / Fallback Cache)
// -------------------------------------------------------------
let dbEngine = 'mysql';
let pool;

// Dynamic Carts & Items Memory Cache (Only real live customer draft carts populate this map)
const memoryCarts = new Map();
const memoryOrderItems = new Map();

function getMemoryCart(cartUuid) {
  const key = String(cartUuid || 'default_cart').trim();
  if (!memoryCarts.has(key)) {
    memoryCarts.set(key, {
      uuid: key,
      table_name: 'Table 1',
      items: [],
      subtotal: 0.00,
      tax_amount: 0.00,
      total_amount: 0.00,
      updated_at: new Date().toISOString()
    });
  }
  return memoryCarts.get(key);
}

// Clean memoryTickets array (Only real live customer orders will populate this array)
const memoryTickets = [];

// Fallback Master Seed Arrays if DB is empty
const defaultFoodCategories = [
  { id: 1, name: 'South Indian Main', code: 'CAT01', status: 'active' },
  { id: 2, name: 'Biryani & Rice Special', code: 'CAT02', status: 'active' },
  { id: 3, name: 'Snacks & Starters', code: 'CAT03', status: 'active' },
  { id: 4, name: 'North Indian Curries', code: 'CAT04', status: 'active' },
  { id: 5, name: 'Beverages & Drinks', code: 'CAT05', status: 'active' },
  { id: 6, name: 'Desserts & Ice Cream', code: 'CAT06', status: 'active' }
];

const defaultFoodItems = [
  { id: 1, food_category_id: 1, category_name: 'South Indian Main', code: 'FD101', name: 'Ghee Masala Dosa', description: 'Crispy Golden Dosa served with Madras Sambar & 3 Chutneys', base_price: 120.00, is_available: 1, status: 'active' },
  { id: 2, food_category_id: 1, category_name: 'South Indian Main', code: 'FD102', name: 'Idli Sambar Set (3 Pcs)', description: 'Steamed Fluffy Rice Cakes with Special Sambar', base_price: 70.00, is_available: 1, status: 'active' },
  { id: 3, food_category_id: 1, category_name: 'South Indian Main', code: 'FD103', name: 'Special Rava Onion Dosa', description: 'Crispy Semolina Dosa studded with onions and cashews', base_price: 140.00, is_available: 1, status: 'active' },
  { id: 4, food_category_id: 2, category_name: 'Biryani & Rice Special', code: 'FD201', name: 'Hyderabadi Veg Biryani', description: 'Aromatic Basmati Rice dum cooked with exotic vegetables & spices', base_price: 190.00, is_available: 1, status: 'active' },
  { id: 5, food_category_id: 2, category_name: 'Biryani & Rice Special', code: 'FD202', name: 'Paneer Tikka Biryani', description: 'Char-grilled Paneer Cubes layered in fragrant saffron rice', base_price: 220.00, is_available: 1, status: 'active' },
  { id: 6, food_category_id: 2, category_name: 'Biryani & Rice Special', code: 'FD203', name: 'Schezwan Fried Rice', description: 'Spicy Indo-Chinese fried rice loaded with crunchy veggies', base_price: 160.00, is_available: 1, status: 'active' },
  { id: 7, food_category_id: 3, category_name: 'Snacks & Starters', code: 'FD301', name: 'Paneer 65 Crispy', description: 'Deep fried spiced cottage cheese cubes with curry leaves', base_price: 160.00, is_available: 1, status: 'active' },
  { id: 8, food_category_id: 3, category_name: 'Snacks & Starters', code: 'FD302', name: 'Gobi Manchurian Dry', description: 'Crispy cauliflower florets tossed in tangy soya garlic sauce', base_price: 150.00, is_available: 1, status: 'active' },
  { id: 9, food_category_id: 4, category_name: 'North Indian Curries', code: 'FD401', name: 'Paneer Butter Masala', description: 'Rich cashew gravy with tender paneer cubes & butter', base_price: 210.00, is_available: 1, status: 'active' },
  { id: 10, food_category_id: 4, category_name: 'North Indian Curries', code: 'FD402', name: 'Butter Naan (2 Pcs)', description: 'Soft tandoori leavened flatbread brushed with fresh butter', base_price: 60.00, is_available: 1, status: 'active' },
  { id: 11, food_category_id: 5, category_name: 'Beverages & Drinks', code: 'FD501', name: 'Filter Coffee (Special)', description: 'Traditional South Indian Brass Tumbler Brewed Coffee', base_price: 35.00, is_available: 1, status: 'active' },
  { id: 12, food_category_id: 5, category_name: 'Beverages & Drinks', code: 'FD502', name: 'Mango Lassi Thick', description: 'Sweet creamy yogurt shake infused with Alphonso mango pulp', base_price: 85.00, is_available: 1, status: 'active' },
  { id: 13, food_category_id: 5, category_name: 'Beverages & Drinks', code: 'FD503', name: 'Cold Coffee Milkshake', description: 'Chilled espresso blended with thick milk and vanilla ice cream', base_price: 110.00, is_available: 1, status: 'active' },
  { id: 14, food_category_id: 6, category_name: 'Desserts & Ice Cream', code: 'FD601', name: 'Gulab Jamun with Ice Cream', description: 'Warm mawa dumplings served with vanillla ice cream', base_price: 90.00, is_available: 1, status: 'active' }
];

const defaultTables = [
  { id: 1, uuid: 't01', name: 'Table 1', code: 'T01', seat_capacity: 4 },
  { id: 2, uuid: 't02', name: 'Table 2', code: 'T02', seat_capacity: 4 },
  { id: 3, uuid: 't03', name: 'Table 3', code: 'T03', seat_capacity: 6 },
  { id: 4, uuid: 't04', name: 'Table 4', code: 'T04', seat_capacity: 4 },
  { id: 5, uuid: 't05', name: 'Table 5', code: 'T05', seat_capacity: 4 },
  { id: 6, uuid: 't06', name: 'Table 6', code: 'T06', seat_capacity: 6 },
  { id: 7, uuid: 't07', name: 'Table 7', code: 'T07', seat_capacity: 4 },
  { id: 8, uuid: 't08', name: 'Table 8', code: 'T08', seat_capacity: 4 },
  { id: 9, uuid: 't09', name: 'Table 9', code: 'T09', seat_capacity: 6 },
  { id: 10, uuid: 't10', name: 'Table 10', code: 'T10', seat_capacity: 8 }
];

const defaultUsers = [
  { id: 1, name: 'Admin HQ Manager', email: 'admin@mastercanteen.com', user_type: 'admin' },
  { id: 2, name: 'Head Chief Chef', email: 'chef@mastercanteen.com', user_type: 'chef' },
  { id: 3, name: 'Billing Cashier Staff', email: 'cashier@mastercanteen.com', user_type: 'staff' }
];

const defaultCoupons = [
  { id: 1, code: 'WELCOME50', discount: '50% OFF', max_limit: '₹100', status: 'Active' },
  { id: 2, code: 'CANTEEN20', discount: '20% OFF', max_limit: '₹50', status: 'Active' },
  { id: 3, code: 'FLAT100', discount: 'Flat ₹100 OFF', max_limit: '₹100', status: 'Active' }
];

const defaultStocks = [
  { id: 1, name: 'Basmati Rice (Aromatic)', quantity: '150 KG', status: 'In Stock' },
  { id: 2, name: 'Dosa & Idli Batter Mixture', quantity: '80 Litres', status: 'In Stock' },
  { id: 3, name: 'South Indian Filter Coffee Powder', quantity: '25 KG', status: 'In Stock' },
  { id: 4, name: 'Fresh Cottage Cheese (Paneer)', quantity: '40 KG', status: 'In Stock' },
  { id: 5, name: 'Full Cream Fresh Milk', quantity: '100 Litres', status: 'In Stock' }
];

if (process.env.DATABASE_URL) {
  dbEngine = 'pg';
  console.log('--- Initializing PostgreSQL Pool for CanteenApp ---');
  const pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  pool = {
    async query(sql, params = []) {
      let paramIdx = 1;
      let pgSql = sql.replace(/\?/g, () => `$${paramIdx++}`);
      pgSql = pgSql.replace(/NOW\(\)/gi, 'CURRENT_TIMESTAMP');

      try {
        const res = await pgPool.query(pgSql, params);
        return [res.rows];
      } catch (err) {
        console.error('PostgreSQL Query Error:', err.message);
        return [[]];
      }
    }
  };

  // Store pgPool reference for startup await
  global.__pgPool = pgPool;
  initPgDatabase(pgPool);
} else {
  const mysqlPool = mysql.createPool({
    host: process.env.DB_HOST || '127.0.0.1',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'canteenappdb',
    waitForConnections: true,
    connectionLimit: 10,
  });

  pool = {
    async query(sql, params = []) {
      try {
        return await mysqlPool.query(sql, params);
      } catch (err) {
        return [[]];
      }
    }
  };
}

async function initPgDatabase(pgPool) {
  // STEP 1: Run schema SQL (CREATE TABLE IF NOT EXISTS - safe to re-run)
  try {
    const schemaSql = fs.readFileSync(path.join(__dirname, 'schema_postgres.sql'), 'utf8');
    await pgPool.query(schemaSql);
    console.log('✅ Schema tables created/verified.');
  } catch (schemaErr) {
    console.error('Schema creation warning (tables may already exist):', schemaErr.message);
  }

  // STEP 2: Seed foreign key records (each INSERT individually so one failure doesn't block others)
  const seeds = [
    "INSERT INTO companies (id, name, created_at, updated_at) VALUES (1, 'Master Canteen', NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
    "INSERT INTO branches (id, company_id, name, code, created_at, updated_at) VALUES (1, 1, 'Main Branch', 'BR001', NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
    "INSERT INTO kitchens (id, company_id, branch_id, name, code, created_at, updated_at) VALUES (1, 1, 1, 'Main Kitchen', 'K01', NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
    "INSERT INTO dining_tables (id, uuid, branch_id, name, code, seat_capacity, created_at, updated_at) VALUES (1, 'tab_001', 1, 'Table 1', 'T01', 4, NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
    "INSERT INTO dining_tables (id, uuid, branch_id, name, code, seat_capacity, created_at, updated_at) VALUES (2, 'tab_002', 1, 'Table 2', 'T02', 4, NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
    "INSERT INTO dining_tables (id, uuid, branch_id, name, code, seat_capacity, created_at, updated_at) VALUES (3, 'tab_003', 1, 'Table 3', 'T03', 4, NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
    "INSERT INTO dining_tables (id, uuid, branch_id, name, code, seat_capacity, created_at, updated_at) VALUES (999, 'tab_999', 1, 'Takeaway / Home Delivery 🛵', 'DELIVERY', 0, NOW(), NOW()) ON CONFLICT (id) DO NOTHING"
  ];
  for (const seedSql of seeds) {
    try { await pgPool.query(seedSql); } catch(e) { /* already exists, safe to skip */ }
  }
  console.log('✅ FK seed records verified.');

  // STEP 3: Sync sequences
  try { await pgPool.query("SELECT setval(pg_get_serial_sequence('orders', 'id'), GREATEST((SELECT MAX(id) FROM orders), 10));"); } catch(e) {}
  try { await pgPool.query("SELECT setval(pg_get_serial_sequence('kitchen_order_tickets', 'id'), GREATEST((SELECT MAX(id) FROM kitchen_order_tickets), 10));"); } catch(e) {}

  // STEP 4: CRITICAL - Sync counter with MAX order ID (THIS MUST SUCCEED!)
  try {
    const res = await pgPool.query("SELECT MAX(id) as max_id FROM orders;");
    if (res && res.rows && res.rows[0] && res.rows[0].max_id) {
      orderNumberSettings.current_counter = parseInt(res.rows[0].max_id) + 1;
      console.log('✅ Counter synced from DB MAX(id):', orderNumberSettings.current_counter);
    } else {
      console.log('✅ No orders in DB yet, keeping counter at:', orderNumberSettings.current_counter);
    }
  } catch(cntErr) {
    console.error('❌ CRITICAL: Counter sync failed:', cntErr.message);
  }

  // STEP 5: Also sync by MAX order_number numeric part (belt-and-suspenders)
  try {
    const res2 = await pgPool.query("SELECT order_number FROM orders ORDER BY id DESC LIMIT 1;");
    if (res2 && res2.rows && res2.rows[0] && res2.rows[0].order_number) {
      const lastNum = res2.rows[0].order_number;
      const digits = lastNum.replace(/[^0-9]/g, '');
      if (digits) {
        const parsed = parseInt(digits) + 1;
        if (parsed > orderNumberSettings.current_counter) {
          orderNumberSettings.current_counter = parsed;
          console.log('✅ Counter adjusted from last order_number:', orderNumberSettings.current_counter);
        }
      }
    }
  } catch(e) {}

  // STEP 6: Restore system settings & Admin credentials from PostgreSQL
  try {
    await pgPool.query("CREATE TABLE IF NOT EXISTS system_settings (key VARCHAR(100) PRIMARY KEY, value TEXT, updated_at TIMESTAMP DEFAULT NOW());");
    const resAll = await pgPool.query("SELECT key, value FROM system_settings;");
    if (resAll && resAll.rows) {
      for (const row of resAll.rows) {
        if (row.key === 'allow_remote_preorder') {
          orderNumberSettings.allow_remote_preorder = (row.value === 'true');
        } else if (row.key === 'restrict_email_domain') {
          orderNumberSettings.restrict_email_domain = row.value || '';
        } else if (row.key === 'require_google_auth') {
          orderNumberSettings.require_google_auth = (row.value === 'true');
        } else if (row.key === 'require_canteen_pin') {
          orderNumberSettings.require_canteen_pin = (row.value === 'true');
        } else if (row.key === 'admin_username' && row.value) {
          adminCredentials.username = row.value.trim();
        } else if (row.key === 'admin_password_hash' && row.value) {
          adminCredentials.passwordHash = row.value;
          adminCredentials.passwordPlainFallback = null;
        }
      }
      console.log('✅ Restored system_settings & admin credentials from DB.');
    }
  } catch(e) {}

  // STEP 7: 24/7 Keep-Alive Self-Ping Loop (Prevents Render Server & Neon.tech DB Cold Starts/Sleeps)
  setInterval(async () => {
    try {
      await pgPool.query('SELECT 1;');
    } catch(e) {}
  }, 4 * 60 * 1000); // Runs silently every 4 minutes (240,000 ms)

  console.log('✅ PostgreSQL Init Complete! Next Order Counter:', orderNumberSettings.current_counter);
}

function formatDate(date) {
  if (!date) return null;
  const d = new Date(date);
  return d.toISOString();
}

// -------------------------------------------------------------
// UI ROUTES
// -------------------------------------------------------------
app.get('/', (req, res) => {
  const tableParam = req.query.table || '1';
  res.redirect(`/order/${tableParam}`);
});

app.get('/order', (req, res) => {
  const tableParam = req.query.table || '1';
  const queryStr = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
  res.redirect(`/order/${tableParam}${queryStr}`);
});

// CANTEEN PUBLIC TV / TABLET LIVE 15-SECOND PIN DISPLAY SCREEN
app.get('/canteen/display', (req, res) => {
  res.render('canteen-display');
});

app.get('/api/v1/canteen/live-pin', (req, res) => {
  res.json(getLiveCanteenPin());
});

app.post('/api/v1/canteen/verify-pin', (req, res) => {
  const { pin } = req.body;
  const isValid = verifyCanteenPin(pin);
  res.json({
    valid: isValid,
    message: isValid 
      ? '✅ PIN Verified! (Matches Canteen Live TV Display)' 
      : '❌ Invalid or Expired Canteen PIN! Please look at the Canteen TV Display Screen for the current PIN.'
  });
});

app.get('/order/:tableUuid', async (req, res) => {
  try {
    const { tableUuid } = req.params;
    const cleanParam = String(tableUuid || '').trim().toLowerCase();

    let isTakeaway = cleanParam === 'takeaway' || cleanParam === 'delivery' || cleanParam === 'online';

    const [tables] = await pool.query(
      'SELECT * FROM dining_tables WHERE LOWER(uuid) = ? OR LOWER(code) = ? OR CAST(id AS TEXT) = ? LIMIT 1',
      [cleanParam, cleanParam, cleanParam]
    );

    let table;
    if (isTakeaway) {
      table = { id: 999, uuid: 'takeaway', name: 'Takeaway / Home Delivery 🛵', code: 'DELIVERY', seat_capacity: 0, is_takeaway: true };
    } else if (tables && tables.length) {
      table = tables[0];
    } else {
      const matchMem = defaultTables.find(t => t.uuid.toLowerCase() === cleanParam || t.code.toLowerCase() === cleanParam);
      table = matchMem || defaultTables[0];
    }

    res.render('table-order', {
      table,
      apiBase: '',
      cashfreeEnv: process.env.CASHFREE_ENV || 'sandbox',
      studentUser: req.session.studentUser || null,
      authError: req.query.auth_error || null,
      authSuccess: req.query.auth_success || null,
      orderSettings: orderNumberSettings
    });
  } catch (err) {
    res.status(500).send('Server Error: ' + err.message);
  }
});

// KITCHEN DISPLAY SCREEN (Accessible for Kitchen TV, Tablet & Mobile - Enforces IP Whitelist Access)
app.get('/kitchen/screen', checkKitchenIpAccess, async (req, res) => {
  try {
    res.render('kitchen-screen', { branchUuid: 'BR001' });
  } catch (err) {
    res.status(500).send('Server Error: ' + err.message);
  }
});

// -------------------------------------------------------------
// CUSTOMER ORDERING API ENDPOINTS
// -------------------------------------------------------------
app.get('/api/v1/menu/categories', async (req, res) => {
  try {
    const [categories] = await pool.query("SELECT * FROM food_categories WHERE status = 'active' OR status = 'Active' ORDER BY id ASC");
    res.json({ data: (categories && categories.length) ? categories : defaultFoodCategories });
  } catch (err) {
    res.json({ data: defaultFoodCategories });
  }
});

app.get('/api/v1/menu/items', async (req, res) => {
  try {
    const [items] = await pool.query(`
      SELECT fi.*, fi.base_price as price, fc.name as category_name 
      FROM food_items fi
      LEFT JOIN food_categories fc ON fi.food_category_id = fc.id
      WHERE fi.status = 'active'
      ORDER BY fi.id ASC
    `);
    res.json({ data: (items && items.length) ? items : defaultFoodItems });
  } catch (err) {
    res.json({ data: defaultFoodItems });
  }
});

// Create Cart Session
app.post('/api/v1/cart/session', async (req, res) => {
  try {
    const { table_name } = req.body || {};
    const cartUuid = uuidv4();
    const memCart = getMemoryCart(cartUuid);
    if (table_name) memCart.table_name = table_name;
    res.json({ data: memCart });
  } catch (err) {
    const cartUuid = uuidv4();
    res.json({ data: getMemoryCart(req.params.cartUuid) });
  }
});

// Fetch Cart
app.get('/api/v1/cart/:cartUuid', async (req, res) => {
  try {
    const { cartUuid } = req.params;
    const table_name = req.query.table_name;
    const memCart = getMemoryCart(cartUuid);
    if (table_name) memCart.table_name = table_name;
    res.json({ data: memCart });
  } catch (err) {
    res.json({ data: getMemoryCart(req.params.cartUuid) });
  }
});

// Add / Set Item in Cart
app.post('/api/v1/cart/items', async (req, res) => {
  try {
    const { cart_uuid, food_item_id, quantity, table_name } = req.body;
    const qty = parseInt(quantity || 1);
    const memCart = getMemoryCart(cart_uuid);
    if (table_name) memCart.table_name = table_name;

    const [foodItems] = await pool.query('SELECT * FROM food_items WHERE id = ?', [food_item_id]);
    let foodItemName = 'Delicious Dish';
    let unitPrice = 100.00;

    if (foodItems && foodItems.length) {
      foodItemName = foodItems[0].name;
      unitPrice = parseFloat(foodItems[0].base_price);
    } else {
      const matchDefault = defaultFoodItems.find(i => String(i.id) === String(food_item_id));
      if (matchDefault) {
        foodItemName = matchDefault.name;
        unitPrice = parseFloat(matchDefault.base_price);
      }
    }

    const existingIdx = memCart.items.findIndex(i => String(i.food_item_id) === String(food_item_id));
    if (existingIdx >= 0) {
      if (qty <= 0) {
        memCart.items.splice(existingIdx, 1);
      } else {
        memCart.items[existingIdx].quantity = qty;
        memCart.items[existingIdx].total_price = unitPrice * qty;
      }
    } else if (qty > 0) {
      memCart.items.push({
        id: food_item_id,
        food_item_id: food_item_id,
        item_name: foodItemName,
        unit_price: unitPrice,
        quantity: qty,
        total_price: unitPrice * qty
      });
    }

    let subtotal = 0;
    memCart.items.forEach(i => subtotal += (parseFloat(i.unit_price) * parseInt(i.quantity)));
    memCart.subtotal = subtotal;
    memCart.tax_amount = subtotal * 0.05;
    memCart.total_amount = subtotal + memCart.tax_amount;

    res.json({ message: 'Cart updated successfully', data: memCart });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Fetch Active Carts for Admin Dashboard
app.get('/api/v1/admin/active-carts', async (req, res) => {
  try {
    const activeList = [];
    for (const [key, cart] of memoryCarts.entries()) {
      if (cart && Array.isArray(cart.items) && cart.items.length > 0) {
        const totalItems = cart.items.reduce((sum, i) => sum + (parseInt(i.quantity) || 1), 0);
        activeList.push({
          uuid: cart.uuid || key,
          table_name: cart.table_name || 'Table 1',
          items_count: totalItems,
          items: cart.items,
          total_amount: parseFloat(cart.total_amount || 0),
          updated_at: cart.updated_at || new Date().toISOString()
        });
      }
    }
    res.json({ data: activeList });
  } catch (err) {
    res.json({ data: [] });
  }
});

// Update Item Quantity
app.patch('/api/v1/cart/items/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { quantity, cart_uuid } = req.body;
    const qty = parseInt(quantity);

    if (cart_uuid && memoryCarts.has(cart_uuid)) {
      const memCart = memoryCarts.get(cart_uuid);
      const idx = memCart.items.findIndex(i => String(i.id) === String(id) || String(i.food_item_id) === String(id));
      if (idx >= 0) {
        if (qty <= 0) {
          memCart.items.splice(idx, 1);
        } else {
          memCart.items[idx].quantity = qty;
          memCart.items[idx].total_price = memCart.items[idx].unit_price * qty;
        }
      }
    }
    res.json({ message: 'Cart item updated' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Checkout Verification & SEQUENTIAL MULTI-ORDER / KOT GENERATOR
app.post('/api/v1/cart/payments/cashfree/verify', async (req, res) => {
  try {
    const { cart_uuid, customer_name, customer_phone, special_instructions, table_name, is_takeaway, cart_items, canteen_pin } = req.body;

    // VERIFY 15-SECOND DYNAMIC CANTEEN SECURITY PIN
    if (canteen_pin !== undefined && canteen_pin !== null && canteen_pin !== '') {
      if (!verifyCanteenPin(canteen_pin)) {
        return res.status(400).json({ message: '❌ Invalid or expired 15-Second Canteen PIN! Please look at the Canteen TV Display Screen for the latest live PIN.' });
      }
    }

    const memCart = getMemoryCart(cart_uuid);

    const orderUuid = uuidv4();

    // GENERATE SEQUENTIAL ORDER / INVOICE NUMBER (RESPECTS ADMIN CONFIGURATION EXACTLY!)
    const orderNumber = generateSequentialOrderNumber();
    
    let itemsToSave = [];
    if (Array.isArray(cart_items) && cart_items.length > 0) {
      itemsToSave = cart_items.map(i => ({
        food_item_id: i.food_item_id || i.id || 1,
        item_name: i.item_name || i.name || 'Delicious Dish',
        quantity: parseInt(i.quantity || 1),
        unit_price: parseFloat(i.unit_price || i.price || i.base_price || 100.00)
      }));
    } else if (memCart && memCart.items && memCart.items.length > 0) {
      itemsToSave = [...memCart.items];
    } else {
      itemsToSave = [{ food_item_id: 1, item_name: 'Ghee Masala Dosa', quantity: 1, unit_price: 120.00 }];
    }

    let calculatedSubtotal = 0;
    itemsToSave.forEach(i => calculatedSubtotal += (parseFloat(i.unit_price) * parseInt(i.quantity)));
    const calculatedTax = calculatedSubtotal * 0.05;
    const totalAmount = parseFloat((calculatedSubtotal + calculatedTax).toFixed(2));
    const studentUser = req.session && req.session.studentUser ? req.session.studentUser : null;
    const custName = (customer_name && customer_name.trim() && customer_name.trim() !== 'Guest Customer') ? customer_name.trim() : (studentUser && studentUser.name ? studentUser.name : 'Guest Student');
    const custPhone = (studentUser && studentUser.email) ? studentUser.email : ((customer_phone && customer_phone.trim()) ? customer_phone.trim() : '9999999999');

    let tableLabel = (table_name && table_name.trim()) ? table_name.trim() : (memCart.table_name || 'Table 1');
    let orderType = 'dine_in';

    if (is_takeaway || tableLabel.toLowerCase().includes('takeaway') || tableLabel.toLowerCase().includes('delivery') || tableLabel.toLowerCase().includes('home')) {
      tableLabel = 'Takeaway / Home Delivery 🛵';
      orderType = 'takeaway';
    }

    // SERVER-SIDE PRE-ORDER LOCK CHECK
    if (orderNumberSettings.allow_remote_preorder === false && (orderType === 'takeaway' || is_takeaway)) {
      return res.status(403).json({ message: 'Classroom remote ordering & Takeaway links are currently paused by Canteen Admin. Please scan a physical Canteen Table QR code to place your order!' });
    }

    // Dynamic Dining Table ID Resolution (NEVER HARDCODED TO 1!)
    let dbTableId = 1;
    if (orderType === 'takeaway') {
      dbTableId = 999;
    } else if (tableLabel) {
      try {
        const cleanTableStr = tableLabel.toLowerCase().replace('table', '').trim();
        const [matchedTables] = await pool.query(
          "SELECT id FROM dining_tables WHERE LOWER(name) = ? OR LOWER(code) = ? OR LOWER(uuid) = ? OR CAST(id AS TEXT) = ? LIMIT 1",
          [tableLabel.toLowerCase(), cleanTableStr, cleanTableStr, cleanTableStr]
        );
        if (matchedTables && matchedTables[0]) {
          dbTableId = matchedTables[0].id;
        } else {
          // Auto-create dining table dynamically if it doesn't exist in DB yet!
          const newTableId = parseInt(cleanTableStr) || Date.now();
          const tableCode = 'T' + String(newTableId).padStart(2, '0');
          try {
            await pool.query(
              "INSERT INTO dining_tables (id, uuid, branch_id, name, code, seat_capacity, created_at, updated_at) VALUES (?, ?, 1, ?, ?, 4, NOW(), NOW()) ON CONFLICT (id) DO NOTHING",
              [newTableId, `tab_${newTableId}`, tableLabel, tableCode]
            );
            dbTableId = newTableId;
          } catch(tblErr) {
            dbTableId = 1;
          }
        }
      } catch(e) {
        dbTableId = 1;
      }
    }

    let orderId = Date.now();
    let finalOrderNumber = orderNumber;

    // SMART AUTO-INCREMENT: If generated order_number already exists in DB, keep incrementing until unique!
    let insertSuccess = false;
    let maxAttempts = 50; // Safety limit
    while (!insertSuccess && maxAttempts > 0) {
      maxAttempts--;
      try {
        // Check if this order_number already exists in DB
        const [existing] = await pool.query('SELECT id FROM orders WHERE order_number = ?', [finalOrderNumber]);
        if (existing && existing.length > 0) {
          // This order_number is taken - generate next one
          console.log(`Order number ${finalOrderNumber} already exists in DB, trying next...`);
          finalOrderNumber = generateSequentialOrderNumber();
          continue;
        }

        // Order number is available - INSERT it with DYNAMIC dbTableId
        await pool.query(
          "INSERT INTO orders (uuid, company_id, branch_id, dining_table_id, order_number, customer_name, customer_phone, special_instructions, total_amount, status, ordered_at, created_at, updated_at) VALUES (?, 1, 1, ?, ?, ?, ?, ?, ?, 'pending', NOW(), NOW(), NOW())",
          [orderUuid, dbTableId, finalOrderNumber, custName, custPhone, special_instructions || null, totalAmount]
        );

        const [orders] = await pool.query('SELECT * FROM orders WHERE uuid = ?', [orderUuid]);
        if (orders && orders[0]) {
          orderId = orders[0].id;
        }
        insertSuccess = true;
        console.log(`✅ Order ${finalOrderNumber} created with DB id ${orderId}`);
      } catch(e) {
        console.error('Order Insert Error:', e.message);
        // If unique constraint violation, try next number
        if (e.message && (e.message.includes('unique') || e.message.includes('duplicate') || e.message.includes('UNIQUE'))) {
          finalOrderNumber = generateSequentialOrderNumber();
          continue;
        }
        // Other error - use timestamp-based fallback
        finalOrderNumber = `${orderNumber}-${Date.now().toString().slice(-6)}`;
        try {
          await pool.query(
            "INSERT INTO orders (uuid, company_id, branch_id, dining_table_id, order_number, customer_name, customer_phone, special_instructions, total_amount, status, ordered_at, created_at, updated_at) VALUES (?, 1, 1, ?, ?, ?, ?, ?, ?, 'pending', NOW(), NOW(), NOW())",
            [orderUuid, dbTableId, finalOrderNumber, custName, custPhone, special_instructions || null, totalAmount]
          );
          const [orders] = await pool.query('SELECT * FROM orders WHERE uuid = ?', [orderUuid]);
          if (orders && orders[0]) orderId = orders[0].id;
          insertSuccess = true;
        } catch(err2) {
          console.error('Order Insert Final Fallback Error:', err2.message);
          orderId = Date.now();
          insertSuccess = true; // Break out of loop, use memory only
        }
      }
    }

    memoryOrderItems.set(orderId, itemsToSave);
    memoryOrderItems.set(orderUuid, itemsToSave);

    for (let item of itemsToSave) {
      try {
        await pool.query(
          "INSERT INTO order_items (uuid, order_id, food_item_id, item_name, quantity, unit_price, line_total, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
          [uuidv4(), orderId, item.food_item_id || item.id || 1, item.item_name, item.quantity, item.unit_price, (item.unit_price * item.quantity)]
        );
      } catch(e) {
        console.error('Order item insert error:', e.message);
      }
    }

    const ticketUuid = uuidv4();
    // GENERATE SEQUENTIAL KOT NUMBER (SYNCHRONIZED WITH ORDER NUMBER)
    const ticketNumber = generateSequentialKotNumber(finalOrderNumber);

    const newTicket = {
      id: orderId,
      uuid: ticketUuid,
      order_id: orderId,
      order_uuid: orderUuid,
      ticket_number: ticketNumber,
      order_number: finalOrderNumber,
      customer_name: custName,
      customer_phone: custPhone,
      table_number: tableLabel,
      order_type: orderType,
      total_amount: totalAmount,
      status: 'pending',
      items: itemsToSave,
      created_at: new Date().toISOString()
    };

    // UNSHIFT TO VERY TOP OF MEMORY TICKETS (DYNAMICALLY INCREASES COUNT & RENDERS IMMEDIATELY)
    memoryTickets.unshift(newTicket);

    try {
      await pool.query(
        "INSERT INTO kitchen_order_tickets (uuid, company_id, branch_id, kitchen_id, order_id, ticket_number, status, created_at, updated_at) VALUES (?, 1, 1, 1, ?, ?, 'pending', NOW(), NOW())",
        [ticketUuid, orderId, ticketNumber]
      );
    } catch(e) {}

    memoryCarts.delete(cart_uuid);

    const newOrder = {
      uuid: orderUuid,
      order_number: finalOrderNumber,
      customer_name: custName,
      customer_phone: custPhone,
      total_amount: totalAmount,
      status: 'pending',
      table_number: tableLabel,
      order_type: orderType,
      ordered_at: new Date().toISOString()
    };

    res.json({ data: newOrder });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Order Tracking Status API
app.get('/api/v1/orders/:uuid/tracking', async (req, res) => {
  try {
    const { uuid } = req.params;
    const searchTarget = String(uuid || '').trim().toLowerCase();

    // 1. Search in Memory Tickets
    const memTicket = memoryTickets.find(t => 
      (t.uuid && t.uuid.toLowerCase() === searchTarget) || 
      (t.order_uuid && t.order_uuid.toLowerCase() === searchTarget) || 
      (t.order_number && t.order_number.toLowerCase() === searchTarget) || 
      (t.ticket_number && t.ticket_number.toLowerCase() === searchTarget) || 
      String(t.order_id) === searchTarget || 
      String(t.id) === searchTarget
    );

    if (memTicket) {
      return res.json({
        data: {
          order_number: memTicket.order_number || memTicket.ticket_number || 'ORD-LIVE',
          status: memTicket.status || 'pending',
          ordered_at: formatDate(memTicket.created_at),
        }
      });
    }

    // 2. Search in Database
    const [orders] = await pool.query('SELECT * FROM orders WHERE LOWER(uuid) = ? OR LOWER(order_number) = ? OR CAST(id AS TEXT) = ?', [searchTarget, searchTarget, searchTarget]);
    if (orders && orders.length > 0) {
      const order = orders[0];
      const [tickets] = await pool.query('SELECT * FROM kitchen_order_tickets WHERE order_id = ? ORDER BY id DESC LIMIT 1', [order.id]);
      const ticket = (tickets && tickets[0]) ? tickets[0] : {};

      return res.json({
        data: {
          order_number: order.order_number,
          status: ticket.status || order.status || 'pending',
          ordered_at: formatDate(order.ordered_at),
        }
      });
    }

    res.json({ data: { order_number: searchTarget, status: 'pending' } });
  } catch (err) {
    res.json({ data: { order_number: 'ORD-LIVE', status: 'pending' } });
  }
});

// -------------------------------------------------------------
// KITCHEN DISPLAY SCREEN API ENDPOINTS (Includes Auto-Hide Duration!)
// -------------------------------------------------------------
app.get('/kitchen/api/tickets', async (req, res) => {
  try {
    let combinedList = [];

    // Query DB orders directly using LEFT JOIN so zero orders are missed
    const [dbOrders] = await pool.query(`
      SELECT o.*, 
             COALESCE(dt.name, 'Table 1') as resolved_table_name,
             kt.ticket_number as resolved_ticket_number,
             COALESCE(kt.status, o.status, 'pending') as resolved_status,
             kt.uuid as resolved_ticket_uuid
      FROM orders o
      LEFT JOIN dining_tables dt ON o.dining_table_id = dt.id
      LEFT JOIN kitchen_order_tickets kt ON kt.order_id = o.id
      ORDER BY o.id DESC
    `);

    if (dbOrders && dbOrders.length > 0) {
      for (let order of dbOrders) {
        const [items] = await pool.query('SELECT * FROM order_items WHERE order_id = ?', [order.id]);
        const orderItems = (items && items.length) ? items : (memoryOrderItems.get(order.id) || memoryOrderItems.get(order.uuid) || []);

        const orderType = (order.resolved_table_name && order.resolved_table_name.toLowerCase().includes('takeaway')) || (order.table_number && order.table_number.toLowerCase().includes('takeaway')) ? 'takeaway' : 'dine_in';

        combinedList.push({
          id: order.id,
          uuid: order.resolved_ticket_uuid || order.uuid,
          order_id: order.id,
          order_uuid: order.uuid,
          ticket_number: order.resolved_ticket_number || `KOT-${String(order.id).padStart(6, '0')}`,
          order_number: order.order_number || `ORD-${String(order.id).padStart(6, '0')}`,
          customer_name: order.customer_name || 'Guest Student',
          customer_phone: order.customer_phone || '',
          table_number: order.resolved_table_name || order.table_number || 'Table 1',
          order_type: orderType,
          total_amount: parseFloat(order.total_amount || 0),
          status: order.resolved_status || order.status || 'pending',
          items: orderItems,
          created_at: formatDate(order.ordered_at || order.created_at)
        });
      }
    }

    // Merge memoryTickets for any transient in-memory orders not in DB yet
    for (let memTicket of memoryTickets) {
      const exists = combinedList.some(t => 
        (t.order_number && memTicket.order_number && t.order_number === memTicket.order_number) ||
        (t.ticket_number && memTicket.ticket_number && t.ticket_number === memTicket.ticket_number) ||
        (t.order_id && memTicket.order_id && String(t.order_id) === String(memTicket.order_id))
      );
      if (!exists) {
        combinedList.push(memTicket);
      }
    }

    // ALWAYS SORT NEWEST FIRST (ORDER_ID DESC / CREATED_AT DESC)
    combinedList.sort((a, b) => {
      const timeA = new Date(a.created_at || 0).getTime();
      const timeB = new Date(b.created_at || 0).getTime();
      if (timeB !== timeA) return timeB - timeA;
      return (b.id || b.order_id || 0) - (a.id || a.order_id || 0);
    });

    res.json({
      auto_hide_minutes: (orderNumberSettings.auto_hide_minutes !== undefined && orderNumberSettings.auto_hide_minutes !== null) ? orderNumberSettings.auto_hide_minutes : 0,
      data: combinedList
    });
  } catch (err) {
    const fallbackList = [...memoryTickets].sort((a, b) => {
      const timeA = new Date(a.created_at || 0).getTime();
      const timeB = new Date(b.created_at || 0).getTime();
      if (timeB !== timeA) return timeB - timeA;
      return (b.id || 0) - (a.id || 0);
    });
    res.json({
      auto_hide_minutes: (orderNumberSettings.auto_hide_minutes !== undefined && orderNumberSettings.auto_hide_minutes !== null) ? orderNumberSettings.auto_hide_minutes : 0,
      data: fallbackList
    });
  }
});

app.patch('/kitchen/api/tickets/:uuid/status', async (req, res) => {
  try {
    const { uuid } = req.params;
    const { status } = req.body;
    const searchTarget = String(uuid || '').trim().toLowerCase();

    memoryTickets.forEach(t => {
      if (
        (t.uuid && t.uuid.toLowerCase() === searchTarget) || 
        (t.order_uuid && t.order_uuid.toLowerCase() === searchTarget) || 
        (t.order_number && t.order_number.toLowerCase() === searchTarget) || 
        (t.ticket_number && t.ticket_number.toLowerCase() === searchTarget) || 
        String(t.order_id) === searchTarget || 
        String(t.id) === searchTarget
      ) {
        t.status = status;
      }
    });

    try {
      await pool.query("UPDATE kitchen_order_tickets SET status = ?, updated_at = NOW() WHERE LOWER(uuid) = ? OR LOWER(ticket_number) = ?", [status, searchTarget, searchTarget]);
      await pool.query("UPDATE orders SET status = ?, updated_at = NOW() WHERE LOWER(uuid) = ? OR LOWER(order_number) = ?", [status, searchTarget, searchTarget]);
    } catch(e) {}

    res.json({ message: 'Ticket status updated' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// -------------------------------------------------------------
// ADMIN PANEL ENDPOINTS & FULL DATA MODULE CRUD API
// -------------------------------------------------------------
// KITCHEN IP WHITELIST MANAGEMENT API
app.get('/api/v1/admin/kitchen-ips', requireAdmin, (req, res) => {
  const clientIp = getClientIp(req);
  res.json({
    current_ip: clientIp,
    allowed_ips: Array.from(allowedKitchenIps)
  });
});

app.post('/api/v1/admin/kitchen-ips', requireAdmin, (req, res) => {
  const { ip_address } = req.body;
  if (!ip_address || !ip_address.trim()) {
    return res.status(400).json({ message: 'IP Address is required' });
  }
  const cleanIp = ip_address.trim();
  allowedKitchenIps.add(cleanIp);
  res.json({ message: 'IP Address added to Kitchen Whitelist', allowed_ips: Array.from(allowedKitchenIps) });
});

app.delete('/api/v1/admin/kitchen-ips/:ip', requireAdmin, (req, res) => {
  const { ip } = req.params;
  allowedKitchenIps.delete(decodeURIComponent(ip));
  res.json({ message: 'IP Address removed from Whitelist', allowed_ips: Array.from(allowedKitchenIps) });
});

// ORDER / INVOICE NUMBERING CONFIGURATION API ENDPOINTS
app.get('/api/v1/admin/order-number-settings', requireAdmin, (req, res) => {
  res.json({
    data: orderNumberSettings,
    next_preview: getNextPreviewOrderNumber()
  });
});

app.post('/api/v1/admin/order-number-settings', requireAdmin, (req, res) => {
  const { prefix, suffix, digit_count, current_counter, auto_hide_minutes } = req.body;
  if (prefix !== undefined) orderNumberSettings.prefix = String(prefix).trim();
  if (suffix !== undefined) orderNumberSettings.suffix = String(suffix).trim();
  if (digit_count !== undefined) orderNumberSettings.digit_count = Math.max(1, parseInt(digit_count || 6));
  if (current_counter !== undefined) orderNumberSettings.current_counter = Math.max(1, parseInt(current_counter || 1));
  if (auto_hide_minutes !== undefined && auto_hide_minutes !== null) orderNumberSettings.auto_hide_minutes = Math.max(0, parseInt(auto_hide_minutes));

  res.json({
    message: 'Order Numbering & Kitchen Display Settings updated successfully!',
    data: orderNumberSettings,
    next_preview: getNextPreviewOrderNumber()
  });
});

app.post('/api/v1/admin/settings/preorder-toggle', requireAdmin, async (req, res) => {
  const { allow } = req.body;
  if (allow !== undefined) {
    orderNumberSettings.allow_remote_preorder = Boolean(allow);
  } else {
    orderNumberSettings.allow_remote_preorder = !orderNumberSettings.allow_remote_preorder;
  }

  // Persist to PostgreSQL system_settings table so setting remains permanent across server restarts
  try {
    await pool.query(
      "INSERT INTO system_settings (key, value, updated_at) VALUES ('allow_remote_preorder', ?, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
      [String(orderNumberSettings.allow_remote_preorder)]
    );
  } catch(e) {}

  res.json({
    message: orderNumberSettings.allow_remote_preorder 
      ? 'Classroom Pre-Ordering enabled successfully!' 
      : 'Classroom Pre-Ordering disabled. Students MUST scan a Canteen Table QR code to order.',
    allow_remote_preorder: orderNumberSettings.allow_remote_preorder
  });
});


// -------------------------------------------------------------
// TOGGLE MANDATORY GOOGLE AUTHENTICATION SETTING
// -------------------------------------------------------------
app.post('/api/v1/admin/settings/google-auth-toggle', requireAdmin, async (req, res) => {
  orderNumberSettings.require_google_auth = !orderNumberSettings.require_google_auth;
  try {
    if (global.__pgPool) {
      await global.__pgPool.query(
        "INSERT INTO system_settings (key, value, updated_at) VALUES ('require_google_auth', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
        [String(orderNumberSettings.require_google_auth)]
      );
    }
  } catch(e) { console.error('Failed to persist require_google_auth to DB:', e); }

  res.json({
    success: true,
    message: orderNumberSettings.require_google_auth 
      ? '🔑 Google Sign-In is now MANDATORY (Campus Mode)' 
      : '🔓 Google Sign-In is now OPTIONAL (External Shop Mode)',
    require_google_auth: orderNumberSettings.require_google_auth
  });
});

// -------------------------------------------------------------
// TOGGLE CANTEEN TV DISPLAY PIN REQUIREMENT SETTING
// -------------------------------------------------------------
app.post('/api/v1/admin/settings/canteen-pin-toggle', requireAdmin, async (req, res) => {
  orderNumberSettings.require_canteen_pin = !orderNumberSettings.require_canteen_pin;
  try {
    if (global.__pgPool) {
      await global.__pgPool.query(
        "INSERT INTO system_settings (key, value, updated_at) VALUES ('require_canteen_pin', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
        [String(orderNumberSettings.require_canteen_pin)]
      );
    }
  } catch(e) { console.error('Failed to persist require_canteen_pin to DB:', e); }

  res.json({
    success: true,
    message: orderNumberSettings.require_canteen_pin 
      ? '📺 Canteen TV PIN Check is now REQUIRED' 
      : '⚡ Canteen TV PIN Check is now BYPASSED (External Shop Mode)',
    require_canteen_pin: orderNumberSettings.require_canteen_pin
  });
});

app.post('/api/v1/admin/settings/domain-toggle', requireAdmin, async (req, res) => {
  const { domain } = req.body;
  if (domain !== undefined) {
    orderNumberSettings.restrict_email_domain = String(domain).trim();
  } else {
    orderNumberSettings.restrict_email_domain = orderNumberSettings.restrict_email_domain === 'campus.edu' ? '' : 'campus.edu';
  }

  try {
    await pool.query(
      "INSERT INTO system_settings (key, value, updated_at) VALUES ('restrict_email_domain', ?, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
      [String(orderNumberSettings.restrict_email_domain)]
    );
  } catch(e) {}

  res.json({
    message: orderNumberSettings.restrict_email_domain === 'campus.edu' 
      ? 'Google Sign-In restricted to @campus.edu emails ONLY!' 
      : 'Google Sign-In open to ALL Email IDs (Gmail, Yahoo, Outlook, etc.)!',
    restrict_email_domain: orderNumberSettings.restrict_email_domain
  });
});

// -------------------------------------------------------------
// UPDATE ADMIN LOGIN CREDENTIALS (USERNAME/ID & PASSWORD)
// -------------------------------------------------------------
app.post('/api/v1/admin/settings/credentials', requireAdmin, async (req, res) => {
  try {
    const { current_password, new_username, new_password, confirm_password } = req.body || {};

    if (!current_password || !checkAdminCredentials(adminCredentials.username, current_password)) {
      return res.status(401).json({ message: 'Current password is incorrect!' });
    }

    const trimmedUser = String(new_username || '').trim();
    if (!trimmedUser || trimmedUser.length < 3) {
      return res.status(400).json({ message: 'Admin Username / ID must be at least 3 characters.' });
    }

    let updatedPasswordHash = adminCredentials.passwordHash;
    if (new_password && String(new_password).trim().length > 0) {
      const cleanNewPass = String(new_password).trim();
      if (cleanNewPass.length < 4) {
        return res.status(400).json({ message: 'New password must be at least 4 characters.' });
      }
      if (cleanNewPass !== String(confirm_password || '').trim()) {
        return res.status(400).json({ message: 'New password and confirm password do not match!' });
      }
      updatedPasswordHash = hashAdminPassword(cleanNewPass);
      adminCredentials.passwordHash = updatedPasswordHash;
      adminCredentials.passwordPlainFallback = null;
    }

    adminCredentials.username = trimmedUser;

    try {
      if (global.__pgPool) {
        await global.__pgPool.query(
          "INSERT INTO system_settings (key, value, updated_at) VALUES ('admin_username', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
          [adminCredentials.username]
        );
        if (updatedPasswordHash) {
          await global.__pgPool.query(
            "INSERT INTO system_settings (key, value, updated_at) VALUES ('admin_password_hash', $1, NOW()) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
            [updatedPasswordHash]
          );
        }
      }
    } catch (dbErr) {
      console.error('Failed to persist admin credentials to DB:', dbErr.message);
    }

    return res.json({
      success: true,
      message: '✅ Admin ID & Password updated successfully!',
      username: adminCredentials.username
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

// DELETE SINGLE ACTIVE CART SESSION FROM MEMORY
app.delete('/api/v1/admin/active-carts/:cartUuid', requireAdmin, (req, res) => {
  const { cartUuid } = req.params;
  if (memoryCarts.has(cartUuid)) {
    memoryCarts.delete(cartUuid);
  }
  res.json({ message: 'Active cart session deleted successfully' });
});

// CLEAR ALL ACTIVE UNPLACED CART SESSIONS
app.post('/api/v1/admin/active-carts/clear-all', requireAdmin, (req, res) => {
  memoryCarts.clear();
  res.json({ message: 'All active cart sessions cleared successfully' });
});

// DELETE SINGLE ORDER
app.delete('/api/v1/admin/orders/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const target = String(id).trim().toLowerCase();

    try {
      await pool.query("DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE LOWER(uuid) = ? OR LOWER(order_number) = ? OR CAST(id AS TEXT) = ?)", [target, target, target]);
      await pool.query("DELETE FROM kitchen_order_tickets WHERE LOWER(uuid) = ? OR LOWER(ticket_number) = ? OR CAST(order_id AS TEXT) = ?", [target, target, target]);
      await pool.query("DELETE FROM orders WHERE LOWER(uuid) = ? OR LOWER(order_number) = ? OR CAST(id AS TEXT) = ?", [target, target, target]);
    } catch(e) {}

    for (let i = memoryTickets.length - 1; i >= 0; i--) {
      const t = memoryTickets[i];
      if (String(t.id) === target || String(t.uuid).toLowerCase() === target || String(t.order_number).toLowerCase() === target) {
        memoryTickets.splice(i, 1);
      }
    }

    res.json({ message: 'Order deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PURGE / CLEAR ALL OLD COMPLETED AND DELIVERED ORDERS
app.post('/api/v1/admin/orders/clear-completed', requireAdmin, async (req, res) => {
  try {
    try {
      // 1. Delete order items for old orders
      await pool.query("DELETE FROM order_items WHERE order_id IN (SELECT id FROM orders WHERE status IN ('delivered', 'completed', 'cancelled') OR status IS NULL)");
      // 2. Delete kitchen tickets for old orders
      await pool.query("DELETE FROM kitchen_order_tickets WHERE status IN ('delivered', 'completed', 'cancelled') OR order_id IN (SELECT id FROM orders WHERE status IN ('delivered', 'completed', 'cancelled'))");
      // 3. Delete orders
      await pool.query("DELETE FROM orders WHERE status IN ('delivered', 'completed', 'cancelled') OR status IS NULL");
    } catch(e) {
      console.error('Clear Completed DB Error:', e.message);
    }

    for (let i = memoryTickets.length - 1; i >= 0; i--) {
      const st = String(memoryTickets[i].status || '').toLowerCase();
      if (st === 'delivered' || st === 'completed' || st === 'cancelled' || !st) {
        memoryTickets.splice(i, 1);
      }
    }

    res.json({ message: 'All old completed and delivered orders cleared successfully!' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PURGE ALL ORDERS & RESET COUNTER TO 1 (FULL SYSTEM FRESH RESET)
app.post('/api/v1/admin/orders/purge-all', requireAdmin, async (req, res) => {
  try {
    try {
      await pool.query("DELETE FROM order_items");
      await pool.query("DELETE FROM kitchen_order_tickets");
      await pool.query("DELETE FROM orders");
    } catch(e) {}

    memoryTickets.length = 0;
    memoryOrderItems.clear();
    memoryCarts.clear();

    orderNumberSettings.current_counter = 1;

    res.json({ message: 'All test orders purged and system reset to #1 successfully!' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ADMIN CRUD ENDPOINTS FOR FOOD DISHES, CATEGORIES, TABLES, USERS, COUPONS
app.post('/api/v1/admin/items', requireAdmin, async (req, res) => {
  try {
    const { name, category_id, base_price, description } = req.body;
    const newId = defaultFoodItems.length + 1;
    const catName = defaultFoodCategories.find(c => String(c.id) === String(category_id))?.name || 'Main Dish';
    const newItem = {
      id: newId,
      food_category_id: parseInt(category_id || 1),
      category_name: catName,
      code: 'FD-' + Math.floor(Math.random() * 9000 + 1000),
      name: name || 'New Dish',
      description: description || 'Delicious handcrafted canteen specialty',
      base_price: parseFloat(base_price || 100),
      is_available: 1,
      status: 'active'
    };
    defaultFoodItems.unshift(newItem);
    res.json({ message: 'Food item created', data: newItem });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/v1/admin/items/:id', requireAdmin, async (req, res) => {
  const idx = defaultFoodItems.findIndex(i => String(i.id) === String(req.params.id));
  if (idx >= 0) defaultFoodItems.splice(idx, 1);
  res.json({ message: 'Food item deleted' });
});

app.patch('/api/v1/admin/items/:id/toggle', requireAdmin, async (req, res) => {
  const item = defaultFoodItems.find(i => String(i.id) === String(req.params.id));
  if (item) item.is_available = item.is_available ? 0 : 1;
  res.json({ message: 'Item availability toggled' });
});

app.post('/api/v1/admin/categories', requireAdmin, async (req, res) => {
  const { name } = req.body;
  const newCat = { id: defaultFoodCategories.length + 1, name: name || 'Special Category', code: 'CAT0' + (defaultFoodCategories.length + 1), status: 'active' };
  defaultFoodCategories.push(newCat);
  res.json({ message: 'Category added' });
});

app.delete('/api/v1/admin/categories/:id', requireAdmin, async (req, res) => {
  const idx = defaultFoodCategories.findIndex(c => String(c.id) === String(req.params.id));
  if (idx >= 0) defaultFoodCategories.splice(idx, 1);
  res.json({ message: 'Category deleted' });
});

app.post('/api/v1/admin/tables', requireAdmin, async (req, res) => {
  try {
    const { name, seat_capacity } = req.body;
    const cleanName = (name && name.trim()) ? name.trim() : ('Table ' + (defaultTables.length + 1));
    const digits = cleanName.replace(/[^0-9]/g, '');
    const tblNum = digits ? parseInt(digits) : (defaultTables.length + 1);
    const tblUuid = 't' + (tblNum < 10 ? '0' + tblNum : tblNum);
    const tblCode = 'T' + (tblNum < 10 ? '0' + tblNum : tblNum);
    const seatCap = parseInt(seat_capacity || 4);

    const newTab = { id: tblNum, uuid: tblUuid, name: cleanName, code: tblCode, seat_capacity: seatCap };
    
    // 1. Update in-memory array
    const existingMemIdx = defaultTables.findIndex(t => t.id === tblNum || t.name.toLowerCase() === cleanName.toLowerCase());
    if (existingMemIdx >= 0) {
      defaultTables[existingMemIdx] = newTab;
    } else {
      defaultTables.push(newTab);
    }

    // 2. INSERT/UPSERT into PostgreSQL database table
    try {
      await pool.query(
        "INSERT INTO dining_tables (id, uuid, branch_id, name, code, seat_capacity, created_at, updated_at) VALUES (?, ?, 1, ?, ?, ?, NOW(), NOW()) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, seat_capacity = EXCLUDED.seat_capacity",
        [tblNum, tblUuid, cleanName, tblCode, seatCap]
      );
    } catch(dbErr) {
      console.error('Table DB Insert Error:', dbErr.message);
    }

    res.json({ message: 'Dining Table added successfully', data: newTab });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete('/api/v1/admin/tables/:id', requireAdmin, async (req, res) => {
  try {
    const targetId = String(req.params.id);
    const idx = defaultTables.findIndex(t => String(t.id) === targetId || t.uuid.toLowerCase() === targetId.toLowerCase());
    if (idx >= 0) defaultTables.splice(idx, 1);

    try {
      await pool.query("DELETE FROM dining_tables WHERE CAST(id AS TEXT) = ? OR LOWER(uuid) = ?", [targetId, targetId.toLowerCase()]);
    } catch(dbErr) {}

    res.json({ message: 'Dining Table deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post('/api/v1/admin/users', requireAdmin, async (req, res) => {
  const { name, email, user_type } = req.body;
  const newUser = { id: defaultUsers.length + 1, name: name || 'Staff Member', email: email || 'staff@mastercanteen.com', user_type: user_type || 'staff' };
  defaultUsers.push(newUser);
  res.json({ message: 'Staff User created' });
});

app.delete('/api/v1/admin/users/:id', requireAdmin, async (req, res) => {
  const idx = defaultUsers.findIndex(u => String(u.id) === String(req.params.id));
  if (idx >= 0) defaultUsers.splice(idx, 1);
  res.json({ message: 'User deleted' });
});

app.post('/api/v1/admin/coupons', requireAdmin, async (req, res) => {
  const { code, discount, max_limit } = req.body;
  const newCoup = { id: defaultCoupons.length + 1, code: (code || 'SAVE50').toUpperCase(), discount: discount || '50% OFF', max_limit: max_limit || '₹100', status: 'Active' };
  defaultCoupons.push(newCoup);
  res.json({ message: 'Coupon created' });
});

app.delete('/api/v1/admin/coupons/:id', requireAdmin, async (req, res) => {
  const idx = defaultCoupons.findIndex(c => String(c.id) === String(req.params.id));
  if (idx >= 0) defaultCoupons.splice(idx, 1);
  res.json({ message: 'Coupon deleted' });
});

app.post('/api/v1/admin/stocks', requireAdmin, async (req, res) => {
  const { name, quantity } = req.body;
  const newStk = { id: defaultStocks.length + 1, name: name || 'Raw Ingredient', quantity: quantity || '50 KG', status: 'In Stock' };
  defaultStocks.push(newStk);
  res.json({ message: 'Stock item added' });
});

app.delete('/api/v1/admin/stocks/:id', requireAdmin, async (req, res) => {
  const idx = defaultStocks.findIndex(s => String(s.id) === String(req.params.id));
  if (idx >= 0) defaultStocks.splice(idx, 1);
  res.json({ message: 'Stock item deleted' });
});

// MAIN ADMIN DASHBOARD RENDER WITH FULL LIVE DATASETS
app.get('/admin', requireAdmin, async (req, res) => {
  try {
    const clientIp = getClientIp(req);
    const [revRes] = await pool.query("SELECT SUM(total_amount) as rev FROM orders WHERE status != 'cancelled'");
    const [dbItems] = await pool.query("SELECT * FROM food_items WHERE status = 'active'");
    const [dbCategories] = await pool.query("SELECT * FROM food_categories");
    const [dbTables] = await pool.query("SELECT * FROM dining_tables");

    const activeFoodItems = (dbItems && dbItems.length) ? dbItems : defaultFoodItems;
    const activeCategories = (dbCategories && dbCategories.length) ? dbCategories : defaultFoodCategories;
    const activeTables = (dbTables && dbTables.length) ? dbTables : defaultTables;

    // Query DB orders directly using LEFT JOIN so zero orders are missed in Admin Dashboard
    let dbOrdersList = [];
    try {
      const [dbOrders] = await pool.query(`
        SELECT o.*, 
               COALESCE(dt.name, 'Table 1') as resolved_table_name,
               kt.ticket_number as resolved_ticket_number,
               COALESCE(kt.status, o.status, 'pending') as resolved_status,
               kt.uuid as resolved_ticket_uuid
        FROM orders o
        LEFT JOIN dining_tables dt ON o.dining_table_id = dt.id
        LEFT JOIN kitchen_order_tickets kt ON kt.order_id = o.id
        ORDER BY o.id DESC
      `);
      if (dbOrders && dbOrders.length) {
        dbOrdersList = dbOrders.map(o => ({
          id: o.id,
          uuid: o.resolved_ticket_uuid || o.uuid,
          order_id: o.id,
          ticket_number: o.resolved_ticket_number || `KOT-${String(o.id).padStart(6, '0')}`,
          order_number: o.order_number || `ORD-${String(o.id).padStart(6, '0')}`,
          customer_name: o.customer_name || 'Guest',
          customer_phone: o.customer_phone || '',
          table_number: o.resolved_table_name || o.table_number || 'Table 1',
          total_amount: parseFloat(o.total_amount || 0),
          status: o.resolved_status || o.status || 'pending',
          created_at: o.ordered_at || o.created_at
        }));
      }
    } catch(e) {}

    for (let memTicket of memoryTickets) {
      const exists = dbOrdersList.some(t => 
        (t.order_number && memTicket.order_number && t.order_number === memTicket.order_number) ||
        (t.order_id && memTicket.order_id && String(t.order_id) === String(memTicket.order_id))
      );
      if (!exists) {
        dbOrdersList.push(memTicket);
      }
    }

    dbOrdersList.sort((a, b) => (b.id || b.order_id || 0) - (a.id || a.order_id || 0));
    const displayOrdersList = dbOrdersList;

    const totalOrdersCount = displayOrdersList.length;
    const totalRevAmount = (revRes && revRes[0] && revRes[0].rev) ? revRes[0].rev : (displayOrdersList.reduce((acc, t) => acc + (parseFloat(t.total_amount) || 150), 0));

    // DYNAMIC STATS - Sidebar badge for Kitchen Tickets matches EXACT total tickets count!
    const stats = {
      totalRevenue: totalRevAmount,
      totalOrders: totalOrdersCount,
      activeTickets: displayOrdersList.length,
      totalTables: activeTables.length,
      totalCategories: activeCategories.length,
      totalUsers: defaultUsers.length,
      activeCarts: 0,
    };

    // Dynamically query memory Carts for ALL tables (Table 1, Table 2 ... Table 10)
    const activeCartsList = [];
    memoryCarts.forEach((cart, key) => {
      if (cart.items && cart.items.length > 0) {
        activeCartsList.push({
          uuid: key,
          table_name: cart.table_name || 'Table 1',
          status: 'ACTIVE SESSION',
          items_count: cart.items.length,
          total_amount: cart.total_amount || 0,
          created_at: new Date().toISOString()
        });
      }
    });

    stats.activeCarts = activeCartsList.length;

    const currentBaseUrl = `${req.protocol}://${req.get('host')}`;

    res.render('admin-dashboard', {
      clientIp,
      baseUrl: currentBaseUrl,
      adminUsername: adminCredentials.username,
      allowedKitchenIps: Array.from(allowedKitchenIps),
      orderNumberSettings,
      nextOrderPreview: getNextPreviewOrderNumber(),
      stats,
      orders: displayOrdersList,
      tickets: displayOrdersList,
      carts: activeCartsList,
      foodItems: activeFoodItems,
      foodCategories: activeCategories,
      foodVariants: [
        { id: 1, item_name: 'Ghee Masala Dosa', name: 'Extra Cheese Butter Special', price: 160.00 },
        { id: 2, item_name: 'Filter Coffee', name: 'Double Strong Extra Decoction', price: 45.00 }
      ],
      tables: activeTables,
      areas: [
        { id: 1, name: 'Main AC Dining Hall', code: 'DA01' },
        { id: 2, name: 'Garden Rooftop Family Section', code: 'DA02' }
      ],
      branches: [
        { id: 1, name: 'Main Branch - Central HQ', code: 'BR001' }
      ],
      kitchens: [
        { id: 1, name: 'Main Express Kitchen', code: 'K01' }
      ],
      users: defaultUsers,
      coupons: defaultCoupons,
      stocks: defaultStocks,
    });
  } catch (err) {
    res.status(500).send('Admin Dashboard Error: ' + err.message);
  }
});

// CRITICAL: Wait for DB init to complete before accepting any requests
async function startServer() {
  if (global.__pgPool) {
    console.log('⏳ Waiting for PostgreSQL initialization to complete...');
    await initPgDatabase(global.__pgPool);
    console.log('✅ DB init complete, counter is:', orderNumberSettings.current_counter);
  }
  app.listen(PORT, () => {
    console.log(`Pure Node.js Canteen App running at http://localhost:${PORT}`);
  });
}
startServer();
