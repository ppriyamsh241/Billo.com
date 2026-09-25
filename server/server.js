require("dotenv").config();

const bcrypt = require("bcryptjs");
const cors = require("cors");
const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT || 3000);
const databaseUrl =
  process.env.DATABASE_URL || "postgresql://postgres@localhost:5432/billo";
const jwtSecret = process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");
const voucherDirectory = path.join(__dirname, "data", "vouchers");
const configuredOrigins = (process.env.ALLOWED_ORIGINS ||
  "http://localhost:3000,http://127.0.0.1:3000,https://ppriyamsh241.github.io")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

if (!process.env.JWT_SECRET) {
  console.warn(
    "JWT_SECRET is not set. A temporary secret was generated; all sessions will end when this server restarts.",
  );
}

fs.mkdirSync(voucherDirectory, { recursive: true });

const pool = new Pool({ connectionString: databaseUrl });

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || configuredOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("This browser origin is not allowed to use Billo API."));
    },
  }),
);
app.use(express.json({ limit: "2mb" }));

function fail(res, status, message) {
  return res.status(status).json({ error: message });
}

function numberId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function safeUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    merchant_id: row.merchant_id,
    created_at: row.created_at,
  };
}

function signUser(user) {
  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      merchantId: user.merchant_id || null,
    },
    jwtSecret,
    { expiresIn: "12h" },
  );
}

function authenticate(req, res, next) {
  const header = req.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return fail(res, 401, "Sign in is required.");

  try {
    const claims = jwt.verify(token, jwtSecret);
    req.auth = {
      userId: numberId(claims.sub),
      role: claims.role,
      merchantId: numberId(claims.merchantId),
    };
    if (!req.auth.userId || !["admin", "merchant"].includes(req.auth.role)) {
      return fail(res, 401, "Invalid session.");
    }
    return next();
  } catch {
    return fail(res, 401, "Your session has expired. Please sign in again.");
  }
}

function requireAdmin(req, res, next) {
  if (req.auth.role !== "admin") return fail(res, 403, "Administrator access is required.");
  return next();
}

function allowedMerchantId(req, requestedMerchantId) {
  if (req.auth.role === "admin") return requestedMerchantId;
  return req.auth.merchantId === requestedMerchantId ? requestedMerchantId : null;
}

async function audit(client, req, action, merchantId, details = "") {
  await client.query(
    `INSERT INTO audit_logs (user_id, merchant_id, action, details, created_at)
     VALUES ($1, $2, $3, $4, NOW())`,
    [req.auth.userId, merchantId || null, action, details],
  );
}

async function requireMerchant(req, res, next) {
  const merchantId = numberId(req.params.merchantId || req.query.merchant_id || req.body?.merchant_id);
  if (!merchantId) return fail(res, 400, "A valid merchant ID is required.");
  if (!allowedMerchantId(req, merchantId)) {
    return fail(res, 403, "You do not have access to this merchant.");
  }
  req.merchantId = merchantId;
  return next();
}

function ownerFilter(req, fieldName = "merchant_id") {
  if (req.auth.role === "admin" && numberId(req.query.merchant_id)) {
    return { sql: ` WHERE ${fieldName} = $1`, values: [numberId(req.query.merchant_id)] };
  }
  if (req.auth.role === "merchant") {
    return { sql: ` WHERE ${fieldName} = $1`, values: [req.auth.merchantId] };
  }
  return { sql: "", values: [] };
}

function multerStorage() {
  return multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, voucherDirectory),
    filename: (_req, file, callback) => {
      const extension = path.extname(file.originalname || "").toLowerCase().slice(0, 12);
      callback(null, `${crypto.randomUUID()}${extension}`);
    },
  });
}

const upload = multer({
  storage: multerStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, callback) => {
    const allowed = ["image/jpeg", "image/png", "image/webp", "application/pdf"];
    callback(allowed.includes(file.mimetype) ? null : new Error("Only JPG, PNG, WEBP, and PDF vouchers are allowed."), allowed.includes(file.mimetype));
  },
});

app.get("/", (_req, res) => {
  res.json({ success: true, message: "Billo Server is running", health: "/health" });
});

app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    return res.json({ success: true, database: "connected" });
  } catch (error) {
    return res.status(503).json({ success: false, database: "unavailable", error: error.message });
  }
});

app.post("/api/setup/admin", async (req, res, next) => {
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  if (!name || !email || password.length < 10) {
    return fail(res, 400, "Name, email, and a password of at least 10 characters are required.");
  }

  try {
    const exists = await pool.query("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1");
    if (exists.rowCount) return fail(res, 409, "An administrator has already been created.");

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role, merchant_id, created_at)
       VALUES ($1, $2, $3, 'admin', NULL, NOW())
       RETURNING id, name, email, role, merchant_id, created_at`,
      [name, email, passwordHash],
    );
    const user = result.rows[0];
    return res.status(201).json({ user: safeUser(user), token: signUser(user) });
  } catch (error) {
    if (error.code === "23505") return fail(res, 409, "That email is already registered.");
    return next(error);
  }
});

app.post("/api/auth/register", async (req, res, next) => {
  const businessName = String(req.body?.business_name || "").trim();
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").trim().toLowerCase();
  const phone = String(req.body?.phone || "").trim();
  const password = String(req.body?.password || "");
  if (!businessName || !name || !email || password.length < 10) {
    return fail(res, 400, "Business name, name, email, and a password of at least 10 characters are required.");
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const merchant = await client.query(
      `INSERT INTO merchants (business_name, owner_name, phone, email, address, status, created_at)
       VALUES ($1, $2, $3, $4, $5, 'active', NOW())
       RETURNING id, business_name, owner_name, phone, email, address, status, created_at`,
      [businessName, name, phone || null, email, String(req.body?.address || "").trim() || null],
    );
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await client.query(
      `INSERT INTO users (name, email, password_hash, role, merchant_id, created_at)
       VALUES ($1, $2, $3, 'merchant', $4, NOW())
       RETURNING id, name, email, role, merchant_id, created_at`,
      [name, email, passwordHash, merchant.rows[0].id],
    );
    await client.query(
      `INSERT INTO settings (merchant_id, settings_json, updated_at)
       VALUES ($1, '{}'::jsonb, NOW()) ON CONFLICT (merchant_id) DO NOTHING`,
      [merchant.rows[0].id],
    );
    await client.query("COMMIT");
    return res.status(201).json({
      user: safeUser(user.rows[0]),
      merchant: merchant.rows[0],
      token: signUser(user.rows[0]),
    });
  } catch (error) {
    await client.query("ROLLBACK");
    if (error.code === "23505") return fail(res, 409, "That email is already registered.");
    return next(error);
  } finally {
    client.release();
  }
});

app.post("/api/auth/login", async (req, res, next) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  try {
    const result = await pool.query(
      `SELECT id, name, email, password_hash, role, merchant_id, created_at
       FROM users WHERE email = $1 LIMIT 1`,
      [email],
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return fail(res, 401, "Email or password is incorrect.");
    }
    return res.json({ user: safeUser(user), token: signUser(user) });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/me", authenticate, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role, merchant_id, created_at FROM users WHERE id = $1`,
      [req.auth.userId],
    );
    if (!result.rowCount) return fail(res, 401, "Your account no longer exists.");
    return res.json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/merchants", authenticate, async (req, res, next) => {
  try {
    if (req.auth.role === "merchant") {
      const result = await pool.query("SELECT * FROM merchants WHERE id = $1", [req.auth.merchantId]);
      return res.json({ merchants: result.rows });
    }
    const result = await pool.query("SELECT * FROM merchants ORDER BY id DESC");
    return res.json({ merchants: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.patch("/api/merchants/:merchantId", authenticate, requireMerchant, async (req, res, next) => {
  const fields = ["business_name", "owner_name", "phone", "email", "address", "status"];
  const updates = fields.filter((field) => Object.prototype.hasOwnProperty.call(req.body || {}, field));
  if (!updates.length) return fail(res, 400, "No editable merchant fields were provided.");
  if (updates.includes("status") && req.auth.role !== "admin") {
    return fail(res, 403, "Only an administrator can change merchant status.");
  }
  const values = updates.map((field) => req.body[field]);
  const setSql = updates.map((field, index) => `${field} = $${index + 1}`).join(", ");
  try {
    const result = await pool.query(
      `UPDATE merchants SET ${setSql} WHERE id = $${values.length + 1} RETURNING *`,
      [...values, req.merchantId],
    );
    if (!result.rowCount) return fail(res, 404, "Merchant not found.");
    const client = await pool.connect();
    try {
      await audit(client, req, "merchant.updated", req.merchantId);
    } finally {
      client.release();
    }
    return res.json({ merchant: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/products", authenticate, async (req, res, next) => {
  try {
    const filter = ownerFilter(req);
    const result = await pool.query(`SELECT * FROM products${filter.sql} ORDER BY id DESC`, filter.values);
    return res.json({ products: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/products", authenticate, async (req, res, next) => {
  const requestedMerchant = numberId(req.body?.merchant_id) || req.auth.merchantId;
  if (!requestedMerchant || !allowedMerchantId(req, requestedMerchant)) {
    return fail(res, 403, "You do not have access to this merchant.");
  }
  const name = String(req.body?.name || "").trim();
  const price = Number(req.body?.price);
  if (!name || !Number.isFinite(price) || price < 0) return fail(res, 400, "A product name and non-negative price are required.");
  try {
    const result = await pool.query(
      `INSERT INTO products (merchant_id, name, description, price, stock, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING *`,
      [requestedMerchant, name, String(req.body?.description || "").trim() || null, price, Number(req.body?.stock || 0)],
    );
    const client = await pool.connect();
    try {
      await audit(client, req, "product.created", requestedMerchant, result.rows[0].id.toString());
    } finally {
      client.release();
    }
    return res.status(201).json({ product: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.patch("/api/products/:id", authenticate, async (req, res, next) => {
  const id = numberId(req.params.id);
  if (!id) return fail(res, 400, "Invalid product ID.");
  const fields = ["name", "description", "price", "stock"];
  const updates = fields.filter((field) => Object.prototype.hasOwnProperty.call(req.body || {}, field));
  if (!updates.length) return fail(res, 400, "No editable product fields were provided.");
  try {
    const existing = await pool.query("SELECT merchant_id FROM products WHERE id = $1", [id]);
    if (!existing.rowCount) return fail(res, 404, "Product not found.");
    if (!allowedMerchantId(req, existing.rows[0].merchant_id)) return fail(res, 403, "You do not have access to this product.");
    const values = updates.map((field) => req.body[field]);
    const result = await pool.query(
      `UPDATE products SET ${updates.map((field, index) => `${field} = $${index + 1}`).join(", ")}
       WHERE id = $${values.length + 1} RETURNING *`,
      [...values, id],
    );
    return res.json({ product: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.delete("/api/products/:id", authenticate, async (req, res, next) => {
  const id = numberId(req.params.id);
  if (!id) return fail(res, 400, "Invalid product ID.");
  try {
    const existing = await pool.query("SELECT merchant_id FROM products WHERE id = $1", [id]);
    if (!existing.rowCount) return fail(res, 404, "Product not found.");
    if (!allowedMerchantId(req, existing.rows[0].merchant_id)) return fail(res, 403, "You do not have access to this product.");
    await pool.query("DELETE FROM products WHERE id = $1", [id]);
    return res.status(204).end();
  } catch (error) {
    return next(error);
  }
});

app.get("/api/customers", authenticate, async (req, res, next) => {
  try {
    const filter = ownerFilter(req);
    const result = await pool.query(`SELECT * FROM customers${filter.sql} ORDER BY id DESC`, filter.values);
    return res.json({ customers: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/customers", authenticate, async (req, res, next) => {
  const merchantId = numberId(req.body?.merchant_id) || req.auth.merchantId;
  if (!merchantId || !allowedMerchantId(req, merchantId)) return fail(res, 403, "You do not have access to this merchant.");
  const name = String(req.body?.name || "").trim();
  if (!name) return fail(res, 400, "Customer name is required.");
  try {
    const result = await pool.query(
      `INSERT INTO customers (merchant_id, name, phone, email, address, account_id, qr_code, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
      [merchantId, name, req.body?.phone || null, req.body?.email || null, req.body?.address || null, req.body?.account_id || null, req.body?.qr_code || null],
    );
    return res.status(201).json({ customer: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.patch("/api/customers/:id", authenticate, async (req, res, next) => {
  const id = numberId(req.params.id);
  const fields = ["name", "phone", "email", "address", "account_id", "qr_code"];
  const updates = fields.filter((field) => Object.prototype.hasOwnProperty.call(req.body || {}, field));
  if (!id || !updates.length) return fail(res, 400, "A valid customer ID and at least one field are required.");
  try {
    const existing = await pool.query("SELECT merchant_id FROM customers WHERE id = $1", [id]);
    if (!existing.rowCount) return fail(res, 404, "Customer not found.");
    if (!allowedMerchantId(req, existing.rows[0].merchant_id)) return fail(res, 403, "You do not have access to this customer.");
    const values = updates.map((field) => req.body[field]);
    const result = await pool.query(
      `UPDATE customers SET ${updates.map((field, index) => `${field} = $${index + 1}`).join(", ")}
       WHERE id = $${values.length + 1} RETURNING *`,
      [...values, id],
    );
    return res.json({ customer: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/invoices", authenticate, async (req, res, next) => {
  try {
    const filter = ownerFilter(req);
    const result = await pool.query(`SELECT * FROM invoices${filter.sql} ORDER BY id DESC`, filter.values);
    return res.json({ invoices: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/invoices", authenticate, async (req, res, next) => {
  const merchantId = numberId(req.body?.merchant_id) || req.auth.merchantId;
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  if (!merchantId || !allowedMerchantId(req, merchantId)) return fail(res, 403, "You do not have access to this merchant.");
  if (!items.length) return fail(res, 400, "An invoice needs at least one item.");
  const subtotal = items.reduce((sum, item) => sum + Number(item.quantity || 0) * Number(item.price || 0), 0);
  const discount = Number(req.body?.discount || 0);
  const tax = Number(req.body?.tax || 0);
  const total = subtotal - discount + tax;
  if (![subtotal, discount, tax, total].every(Number.isFinite) || total < 0) return fail(res, 400, "Invoice amounts are invalid.");

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const sequence = await client.query("SELECT nextval(pg_get_serial_sequence('invoices', 'id')) AS id");
    const invoiceId = sequence.rows[0].id;
    const invoiceNumber = String(req.body?.invoice_number || `INV-${String(invoiceId).padStart(6, "0")}`);
    const invoice = await client.query(
      `INSERT INTO invoices (id, merchant_id, customer_id, invoice_number, subtotal, discount, tax, total, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING *`,
      [invoiceId, merchantId, numberId(req.body?.customer_id), invoiceNumber, subtotal, discount, tax, total, String(req.body?.status || "paid")],
    );
    for (const item of items) {
      const quantity = Number(item.quantity);
      const price = Number(item.price);
      if (!Number.isFinite(quantity) || quantity <= 0 || !Number.isFinite(price) || price < 0) {
        throw new Error("Invoice items must have a positive quantity and a non-negative price.");
      }
      await client.query(
        `INSERT INTO invoice_items (invoice_id, product_id, product_name, quantity, price, total)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [invoiceId, numberId(item.product_id), String(item.product_name || "").trim() || null, quantity, price, quantity * price],
      );
    }
    await audit(client, req, "invoice.created", merchantId, invoiceId.toString());
    await client.query("COMMIT");
    return res.status(201).json({ invoice: invoice.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK");
    return next(error);
  } finally {
    client.release();
  }
});

app.get("/api/transactions", authenticate, async (req, res, next) => {
  try {
    const filter = ownerFilter(req);
    const result = await pool.query(`SELECT * FROM transactions${filter.sql} ORDER BY id DESC`, filter.values);
    return res.json({ transactions: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/transactions", authenticate, async (req, res, next) => {
  const merchantId = numberId(req.body?.merchant_id) || req.auth.merchantId;
  const amount = Number(req.body?.amount);
  const type = String(req.body?.transaction_type || "").trim();
  if (!merchantId || !allowedMerchantId(req, merchantId)) return fail(res, 403, "You do not have access to this merchant.");
  if (!type || !Number.isFinite(amount) || amount < 0) return fail(res, 400, "Transaction type and amount are required.");
  try {
    const result = await pool.query(
      `INSERT INTO transactions (merchant_id, customer_id, invoice_id, transaction_type, amount, payment_method, status, reference_number, description, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) RETURNING *`,
      [merchantId, numberId(req.body?.customer_id), numberId(req.body?.invoice_id), type, amount, req.body?.payment_method || null, req.body?.status || "completed", req.body?.reference_number || null, req.body?.description || null],
    );
    return res.status(201).json({ transaction: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/subscriptions/plans", authenticate, async (_req, res, next) => {
  try {
    const result = await pool.query("SELECT * FROM subscription_plans ORDER BY price ASC, id ASC");
    return res.json({ plans: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/subscriptions/payments", authenticate, async (req, res, next) => {
  try {
    const filter = ownerFilter(req);
    const result = await pool.query(`SELECT * FROM subscription_payments${filter.sql} ORDER BY id DESC`, filter.values);
    return res.json({ payments: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/subscriptions/payments", authenticate, async (req, res, next) => {
  const merchantId = numberId(req.body?.merchant_id) || req.auth.merchantId;
  const planId = numberId(req.body?.plan_id);
  const amount = Number(req.body?.amount);
  if (!merchantId || !allowedMerchantId(req, merchantId)) return fail(res, 403, "You do not have access to this merchant.");
  if (!planId || !Number.isFinite(amount) || amount < 0) return fail(res, 400, "Plan and amount are required.");
  try {
    const result = await pool.query(
      `INSERT INTO subscription_payments (merchant_id, plan_id, amount, status, payment_method, reference_number, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`,
      [merchantId, planId, amount, req.body?.status || "pending", req.body?.payment_method || null, req.body?.reference_number || null],
    );
    return res.status(201).json({ payment: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.patch("/api/subscriptions/payments/:id", authenticate, requireAdmin, async (req, res, next) => {
  const id = numberId(req.params.id);
  const status = String(req.body?.status || "").trim();
  if (!id || !status) return fail(res, 400, "Payment ID and status are required.");
  try {
    const result = await pool.query("UPDATE subscription_payments SET status = $1 WHERE id = $2 RETURNING *", [status, id]);
    if (!result.rowCount) return fail(res, 404, "Subscription payment not found.");
    return res.json({ payment: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/settings", authenticate, async (req, res, next) => {
  const merchantId = numberId(req.query.merchant_id) || req.auth.merchantId;
  if (!merchantId || !allowedMerchantId(req, merchantId)) return fail(res, 403, "You do not have access to this merchant.");
  try {
    const result = await pool.query("SELECT merchant_id, settings_json, updated_at FROM settings WHERE merchant_id = $1", [merchantId]);
    return res.json({ settings: result.rows[0] || { merchant_id: merchantId, settings_json: {} } });
  } catch (error) {
    return next(error);
  }
});

app.put("/api/settings", authenticate, async (req, res, next) => {
  const merchantId = numberId(req.body?.merchant_id) || req.auth.merchantId;
  if (!merchantId || !allowedMerchantId(req, merchantId)) return fail(res, 403, "You do not have access to this merchant.");
  if (!req.body?.settings || typeof req.body.settings !== "object" || Array.isArray(req.body.settings)) {
    return fail(res, 400, "Settings must be an object.");
  }
  try {
    const result = await pool.query(
      `INSERT INTO settings (merchant_id, settings_json, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (merchant_id) DO UPDATE SET settings_json = EXCLUDED.settings_json, updated_at = NOW()
       RETURNING merchant_id, settings_json, updated_at`,
      [merchantId, JSON.stringify(req.body.settings)],
    );
    return res.json({ settings: result.rows[0] });
  } catch (error) {
    return next(error);
  }
});

app.post("/api/vouchers", authenticate, upload.single("voucher"), async (req, res, next) => {
  const merchantId = numberId(req.body?.merchant_id) || req.auth.merchantId;
  const transactionId = numberId(req.body?.transaction_id);
  if (!merchantId || !allowedMerchantId(req, merchantId)) return fail(res, 403, "You do not have access to this merchant.");
  if (!transactionId || !req.file) return fail(res, 400, "A transaction ID and voucher file are required.");
  try {
    const transaction = await pool.query("SELECT merchant_id FROM transactions WHERE id = $1", [transactionId]);
    if (!transaction.rowCount || transaction.rows[0].merchant_id !== merchantId) {
      fs.rmSync(req.file.path, { force: true });
      return fail(res, 404, "Transaction not found.");
    }
    const result = await pool.query(
      `INSERT INTO voucher_files (transaction_id, merchant_id, original_filename, stored_filename, file_path, mime_type, file_size, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING id, transaction_id, merchant_id, original_filename, mime_type, file_size, created_at`,
      [transactionId, merchantId, req.file.originalname, req.file.filename, req.file.path, req.file.mimetype, req.file.size],
    );
    return res.status(201).json({ voucher: result.rows[0] });
  } catch (error) {
    if (req.file) fs.rmSync(req.file.path, { force: true });
    return next(error);
  }
});

app.get("/api/vouchers", authenticate, async (req, res, next) => {
  try {
    const filter = ownerFilter(req);
    const result = await pool.query(
      `SELECT id, transaction_id, merchant_id, original_filename, mime_type, file_size, created_at
       FROM voucher_files${filter.sql} ORDER BY id DESC`,
      filter.values,
    );
    return res.json({ vouchers: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.get("/api/vouchers/:id/download", authenticate, async (req, res, next) => {
  const id = numberId(req.params.id);
  if (!id) return fail(res, 400, "Invalid voucher ID.");
  try {
    const result = await pool.query("SELECT * FROM voucher_files WHERE id = $1", [id]);
    if (!result.rowCount) return fail(res, 404, "Voucher not found.");
    const voucher = result.rows[0];
    if (!allowedMerchantId(req, voucher.merchant_id)) return fail(res, 403, "You do not have access to this voucher.");
    if (!fs.existsSync(voucher.file_path)) return fail(res, 404, "Voucher file is unavailable.");
    return res.download(voucher.file_path, voucher.original_filename);
  } catch (error) {
    return next(error);
  }
});

app.get("/api/audit-logs", authenticate, requireAdmin, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT audit_logs.*, users.email AS user_email, merchants.business_name
       FROM audit_logs
       LEFT JOIN users ON users.id = audit_logs.user_id
       LEFT JOIN merchants ON merchants.id = audit_logs.merchant_id
       ORDER BY audit_logs.id DESC LIMIT 500`,
    );
    return res.json({ audit_logs: result.rows });
  } catch (error) {
    return next(error);
  }
});

app.use((error, _req, res, _next) => {
  if (error instanceof multer.MulterError) return fail(res, 400, error.message);
  if (error.message === "Only JPG, PNG, WEBP, and PDF vouchers are allowed.") return fail(res, 400, error.message);
  if (error.message === "This browser origin is not allowed to use Billo API.") return fail(res, 403, error.message);
  console.error(error);
  return res.status(500).json({ error: "An unexpected server error occurred." });
});

async function initializeDatabase() {
  const schemaPath = path.join(__dirname, "..", "database", "schema.sql");
  const schema = fs.readFileSync(schemaPath, "utf8");
  await pool.query(schema);
  console.log("Billo PostgreSQL schema is ready.");
}

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(port, "0.0.0.0", () => {
      console.log(`Billo API is listening on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Billo server could not initialize the database.", error);
    process.exit(1);
  }
}

startServer();

