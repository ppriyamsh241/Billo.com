-- Billo PostgreSQL schema
-- Safe to run repeatedly.

CREATE TABLE IF NOT EXISTS merchants (
  id BIGSERIAL PRIMARY KEY,
  business_name TEXT NOT NULL,
  owner_name TEXT NOT NULL,
  phone TEXT,
  email TEXT NOT NULL,
  address TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','pending')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS merchants_email_lower_idx ON merchants (LOWER(email));

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','merchant')),
  merchant_id BIGINT REFERENCES merchants(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT users_role_merchant_check CHECK (
    (role = 'admin' AND merchant_id IS NULL) OR
    (role = 'merchant' AND merchant_id IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email));
CREATE INDEX IF NOT EXISTS users_merchant_id_idx ON users (merchant_id);

CREATE TABLE IF NOT EXISTS settings (
  merchant_id BIGINT PRIMARY KEY REFERENCES merchants(id) ON DELETE CASCADE,
  settings_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS products (
  id BIGSERIAL PRIMARY KEY,
  merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  price NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (price >= 0),
  stock NUMERIC(14,3) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS products_merchant_id_idx ON products (merchant_id);

CREATE TABLE IF NOT EXISTS customers (
  id BIGSERIAL PRIMARY KEY,
  merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  address TEXT,
  account_id TEXT,
  qr_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS customers_merchant_id_idx ON customers (merchant_id);

CREATE TABLE IF NOT EXISTS invoices (
  id BIGSERIAL PRIMARY KEY,
  merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  customer_id BIGINT REFERENCES customers(id) ON DELETE SET NULL,
  invoice_number TEXT NOT NULL,
  subtotal NUMERIC(14,2) NOT NULL DEFAULT 0,
  discount NUMERIC(14,2) NOT NULL DEFAULT 0,
  tax NUMERIC(14,2) NOT NULL DEFAULT 0,
  total NUMERIC(14,2) NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'paid',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS invoices_merchant_id_idx ON invoices (merchant_id);
CREATE UNIQUE INDEX IF NOT EXISTS invoices_merchant_number_idx ON invoices (merchant_id, invoice_number);

CREATE TABLE IF NOT EXISTS invoice_items (
  id BIGSERIAL PRIMARY KEY,
  invoice_id BIGINT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  product_id BIGINT REFERENCES products(id) ON DELETE SET NULL,
  product_name TEXT,
  quantity NUMERIC(14,3) NOT NULL CHECK (quantity > 0),
  price NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (price >= 0),
  total NUMERIC(14,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS invoice_items_invoice_id_idx ON invoice_items (invoice_id);

CREATE TABLE IF NOT EXISTS transactions (
  id BIGSERIAL PRIMARY KEY,
  merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  customer_id BIGINT REFERENCES customers(id) ON DELETE SET NULL,
  invoice_id BIGINT REFERENCES invoices(id) ON DELETE SET NULL,
  transaction_type TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (amount >= 0),
  payment_method TEXT,
  status TEXT NOT NULL DEFAULT 'completed',
  reference_number TEXT,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS transactions_merchant_id_idx ON transactions (merchant_id);
CREATE INDEX IF NOT EXISTS transactions_created_at_idx ON transactions (created_at);

CREATE TABLE IF NOT EXISTS subscription_plans (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  duration_days INTEGER NOT NULL CHECK (duration_days > 0),
  price NUMERIC(14,2) NOT NULL CHECK (price >= 0),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subscription_payments (
  id BIGSERIAL PRIMARY KEY,
  merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  plan_id BIGINT NOT NULL REFERENCES subscription_plans(id),
  amount NUMERIC(14,2) NOT NULL CHECK (amount >= 0),
  status TEXT NOT NULL DEFAULT 'pending',
  payment_method TEXT,
  reference_number TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS subscription_payments_merchant_id_idx ON subscription_payments (merchant_id);

CREATE TABLE IF NOT EXISTS voucher_files (
  id BIGSERIAL PRIMARY KEY,
  transaction_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
  merchant_id BIGINT NOT NULL REFERENCES merchants(id) ON DELETE CASCADE,
  original_filename TEXT NOT NULL,
  stored_filename TEXT NOT NULL,
  file_path TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  file_size BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS voucher_files_merchant_id_idx ON voucher_files (merchant_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
  merchant_id BIGINT REFERENCES merchants(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  details TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs (created_at);

INSERT INTO subscription_plans (name, duration_days, price, active)
SELECT '1 Month', 30, 200, TRUE
WHERE NOT EXISTS (SELECT 1 FROM subscription_plans WHERE duration_days = 30 AND price = 200);

INSERT INTO subscription_plans (name, duration_days, price, active)
SELECT '3 Months', 90, 500, TRUE
WHERE NOT EXISTS (SELECT 1 FROM subscription_plans WHERE duration_days = 90 AND price = 500);

INSERT INTO subscription_plans (name, duration_days, price, active)
SELECT '12 Months', 365, 2000, TRUE
WHERE NOT EXISTS (SELECT 1 FROM subscription_plans WHERE duration_days = 365 AND price = 2000);
