PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS customers (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  locale TEXT NOT NULL DEFAULT 'fa',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plans (
  code TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  interval TEXT NOT NULL CHECK (interval IN ('month','year','once')),
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1))
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id),
  plan_code TEXT NOT NULL REFERENCES plans(code),
  provider TEXT NOT NULL CHECK (provider IN ('zarinpal','stripe')),
  currency TEXT NOT NULL,
  amount INTEGER NOT NULL CHECK (amount > 0),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid','failed','expired','refunded')),
  authority TEXT,
  provider_session_id TEXT,
  checkout_url TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  paid_at TEXT,
  expires_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_authority ON orders(provider, authority) WHERE authority IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_session ON orders(provider, provider_session_id) WHERE provider_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_orders_customer_created ON orders(customer_id, created_at DESC);

CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id),
  plan_code TEXT NOT NULL REFERENCES plans(code),
  order_id TEXT NOT NULL REFERENCES orders(id),
  status TEXT NOT NULL CHECK (status IN ('active','expired','cancelled')),
  starts_at TEXT NOT NULL,
  ends_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(customer_id, status);

INSERT OR IGNORE INTO plans(code,name,interval,active) VALUES
 ('PLUS_MONTHLY','PLUS Monthly','month',1),
 ('PLUS_ANNUAL','PLUS Annual','year',1),
 ('PRO_FAMILY','PRO Family','year',1),
 ('LIFETIME_OFFLINE','Lifetime Offline','once',1);
