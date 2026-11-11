const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const PLAN_CODES = new Set(["PLUS_MONTHLY", "PLUS_ANNUAL", "PRO_FAMILY", "LIFETIME_OFFLINE"]);

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...headers } });
}
function cors(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(v => v.trim()).filter(Boolean);
  const headers = { "Vary": "Origin" };
  if (allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, Stripe-Signature";
    headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
  }
  return headers;
}
function validEmail(value) {
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function nowIso() { return new Date().toISOString(); }
function addInterval(interval) {
  const d = new Date();
  if (interval === "month") d.setUTCMonth(d.getUTCMonth() + 1);
  else if (interval === "year") d.setUTCFullYear(d.getUTCFullYear() + 1);
  else return null;
  return d.toISOString();
}
async function readJson(request) {
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 12000) throw new Error("Request too large");
  return await request.json();
}
async function getPlan(env, code) {
  if (!PLAN_CODES.has(code)) return null;
  const row = await env.DB.prepare("SELECT code,name,interval FROM plans WHERE code=? AND active=1").bind(code).first();
  if (!row) return null;
  const map = {
    PLUS_MONTHLY: { IRR: env.PRICE_PLUS_MONTHLY_IRR, USD: env.PRICE_PLUS_MONTHLY_USD },
    PLUS_ANNUAL: { IRR: env.PRICE_PLUS_ANNUAL_IRR, USD: env.PRICE_PLUS_ANNUAL_USD },
    PRO_FAMILY: { IRR: env.PRICE_PRO_FAMILY_IRR, USD: env.PRICE_PRO_FAMILY_USD },
    LIFETIME_OFFLINE: { IRR: env.PRICE_LIFETIME_IRR, USD: env.PRICE_LIFETIME_USD }
  };
  return { ...row, prices: map[code] };
}
async function createOrder(request, env) {
  const body = await readJson(request);
  const email = String(body.email || "").trim().toLowerCase();
  const locale = body.locale === "en" ? "en" : "fa";
  const plan = await getPlan(body.plan, env);
  const provider = body.provider === "stripe" ? "stripe" : body.provider === "zarinpal" ? "zarinpal" : "";
  const currency = provider === "stripe" ? "USD" : "IRR";
  const amount = Number(plan?.prices?.[currency]);
  if (!validEmail(email)) return json({ error: "A valid email address is required." }, 400);
  if (!plan || !provider || !Number.isSafeInteger(amount) || amount < 1) {
    return json({ error: "This plan or payment route is not configured yet." }, 409);
  }
  if (provider === "stripe" && !env.STRIPE_SECRET_KEY) return json({ error: "International payments are not configured yet." }, 503);
  if (provider === "zarinpal" && !env.ZARINPAL_MERCHANT_ID) return json({ error: "Domestic payments are not configured yet." }, 503);

  const customerId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO customers(id,email,locale) VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET locale=excluded.locale")
    .bind(customerId, email, locale).run();
  const customer = await env.DB.prepare("SELECT id FROM customers WHERE email=?").bind(email).first();
  const orderId = crypto.randomUUID();
  const expires = new Date(Date.now() + 30 * 60 * 1000).toISOString();
  await env.DB.prepare("INSERT INTO orders(id,customer_id,plan_code,provider,currency,amount,status,expires_at) VALUES(?,?,?,?,?,?,'pending',?)")
    .bind(orderId, customer.id, plan.code, provider, currency, amount, expires).run();

  const origin = new URL(request.url).origin;
  const callback = origin + "/api/payments/" + provider + "/callback?order=" + encodeURIComponent(orderId);
  let checkoutUrl = "";
  try {
    if (provider === "zarinpal") {
      const response = await fetch("https://payment.zarinpal.com/pg/v4/payment/request.json", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({
          merchant_id: env.ZARINPAL_MERCHANT_ID, amount, currency: "IRR",
          description: "ANTIVIRUS AL AI " + plan.name,
          callback_url: callback, metadata: { email, order_id: orderId }
        })
      });
      const result = await response.json();
      const data = result.data || {};
      if (!response.ok || !data.authority || !(data.code === 100 || data.code === 101)) throw new Error("Zarinpal request rejected");
      checkoutUrl = "https://payment.zarinpal.com/pg/StartPay/" + encodeURIComponent(data.authority);
      await env.DB.prepare("UPDATE orders SET authority=?,checkout_url=? WHERE id=?").bind(data.authority, checkoutUrl, orderId).run();
    } else {
      const params = new URLSearchParams();
      params.set("mode", "payment");
      params.set("success_url", callback + "&session_id={CHECKOUT_SESSION_ID}");
      params.set("cancel_url", (env.PORTAL_URL || origin) + "?payment=cancelled&order=" + orderId);
      params.set("customer_email", email);
      params.set("client_reference_id", orderId);
      params.set("metadata[order_id]", orderId);
      params.set("line_items[0][quantity]", "1");
      params.set("line_items[0][price_data][currency]", "usd");
      params.set("line_items[0][price_data][unit_amount]", String(amount));
      params.set("line_items[0][price_data][product_data][name]", "ANTIVIRUS AL AI " + plan.name);
      const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
        method: "POST", headers: { authorization: "Bearer " + env.STRIPE_SECRET_KEY, "content-type": "application/x-www-form-urlencoded" }, body: params
      });
      const session = await response.json();
      if (!response.ok || !session.url || !session.id) throw new Error("Stripe checkout could not be created");
      checkoutUrl = session.url;
      await env.DB.prepare("UPDATE orders SET provider_session_id=?,checkout_url=? WHERE id=?").bind(session.id, checkoutUrl, orderId).run();
    }
    return json({ orderId, checkoutUrl, provider, currency, amount });
  } catch (error) {
    await env.DB.prepare("UPDATE orders SET status='failed' WHERE id=?").bind(orderId).run();
    return json({ error: "Could not start checkout. Please try again later." }, 502);
  }
}
async function activateOrder(env, orderId, providerReference) {
  const order = await env.DB.prepare("SELECT * FROM orders WHERE id=?").bind(orderId).first();
  if (!order || order.status !== "pending" || order.expires_at < nowIso()) return false;
  const paidAt = nowIso();
  const subscriptionId = crypto.randomUUID();
  const endsAt = order.plan_code === "LIFETIME_OFFLINE" ? null : addInterval(order.plan_code === "PLUS_MONTHLY" ? "month" : "year");
  // D1 batch is transactional. The insert is conditional on this exact transition,
  // so concurrent/duplicate provider callbacks cannot create duplicate subscriptions.
  await env.DB.batch([
    env.DB.prepare("UPDATE orders SET status='paid',paid_at=? WHERE id=? AND status='pending' AND expires_at>=?")
      .bind(paidAt, orderId, paidAt),
    env.DB.prepare("INSERT INTO subscriptions(id,customer_id,plan_code,order_id,status,starts_at,ends_at) SELECT ?,?,?,?,'active',?,? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND status='paid' AND paid_at=?)")
      .bind(subscriptionId, order.customer_id, order.plan_code, order.id, paidAt, endsAt, orderId, paidAt)
  ]);
  return true;
}
async function zarinpalCallback(request, env, url) {
  const orderId = url.searchParams.get("order") || "";
  const status = url.searchParams.get("Status");
  const authority = url.searchParams.get("Authority");
  const order = await env.DB.prepare("SELECT * FROM orders WHERE id=? AND provider='zarinpal'").bind(orderId).first();
  if (!order || !authority || authority !== order.authority || status !== "OK") return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=failed", 303);
  const response = await fetch("https://payment.zarinpal.com/pg/v4/payment/verify.json", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ merchant_id: env.ZARINPAL_MERCHANT_ID, amount: order.amount, authority })
  });
  const result = await response.json();
  if (!response.ok || ![100, 101].includes(result.data?.code)) return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=failed", 303);
  await activateOrder(env, orderId, result.data.ref_id);
  return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=success&order=" + encodeURIComponent(orderId), 303);
}
async function verifyStripeSignature(raw, header, secret) {
  const parts = Object.fromEntries(header.split(",").map(p => p.split("=").map(v => v.trim())));
  if (!parts.t || !parts.v1 || Math.abs(Date.now() / 1000 - Number(parts.t)) > 300) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signed = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(parts.t + "." + raw));
  const hex = [...new Uint8Array(signed)].map(b => b.toString(16).padStart(2, "0")).join("");
  return hex.length === parts.v1.length && [...hex].every((c, i) => c === parts.v1[i]);
}
async function stripeWebhook(request, env) {
  const raw = await request.text();
  if (!env.STRIPE_WEBHOOK_SECRET || !await verifyStripeSignature(raw, request.headers.get("Stripe-Signature") || "", env.STRIPE_WEBHOOK_SECRET)) {
    return json({ error: "Invalid signature" }, 400);
  }
  const event = JSON.parse(raw);
  if (event.type === "checkout.session.completed" && event.data?.object?.payment_status === "paid") {
    const session = event.data.object;
    const orderId = session.metadata?.order_id || session.client_reference_id;
    const order = await env.DB.prepare("SELECT id,provider_session_id,amount,currency FROM orders WHERE id=? AND provider='stripe'").bind(orderId).first();
    if (order && order.provider_session_id === session.id && order.amount === session.amount_total && order.currency.toLowerCase() === session.currency) {
      await activateOrder(env, orderId, session.payment_intent || session.id);
    }
  }
  return json({ received: true });
}
async function orderStatus(url, env) {
  const orderId = url.searchParams.get("order") || "";
  const email = (url.searchParams.get("email") || "").trim().toLowerCase();
  if (!orderId || !validEmail(email)) return json({ error: "Order and email are required." }, 400);
  const row = await env.DB.prepare("SELECT o.id,o.plan_code,o.status,o.currency,o.amount,o.created_at,o.paid_at,c.email FROM orders o JOIN customers c ON c.id=o.customer_id WHERE o.id=? AND c.email=?")
    .bind(orderId, email).first();
  if (!row) return json({ error: "Order not found." }, 404);
  return json({ order: { id: row.id, plan: row.plan_code, status: row.status, currency: row.currency, amount: row.amount, createdAt: row.created_at, paidAt: row.paid_at } });
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const headers = cors(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (url.pathname === "/api/health" && request.method === "GET") return json({ service: "antivirus-billing", status: "ok" }, 200, headers);
    if (url.pathname === "/api/plans" && request.method === "GET") {
      return json({ plans: [
        { code: "PLUS_MONTHLY", interval: "month" }, { code: "PLUS_ANNUAL", interval: "year" },
        { code: "PRO_FAMILY", interval: "year" }, { code: "LIFETIME_OFFLINE", interval: "once" }
      ] }, 200, headers);
    }
    if (url.pathname === "/api/checkout" && request.method === "POST") {
      if (headers["Access-Control-Allow-Origin"] === undefined && request.headers.get("Origin")) return json({ error: "Origin not allowed." }, 403);
      const response = await createOrder(request, env);
      const payload = await response.json();
      return json(payload, response.status, headers);
    }
    if (url.pathname === "/api/order-status" && request.method === "GET") return orderStatus(url, env).then(r => new Response(r.body, { status: r.status, headers: { ...Object.fromEntries(r.headers), ...headers } }));
    if (url.pathname === "/api/payments/zarinpal/callback" && request.method === "GET") return zarinpalCallback(request, env, url);
    if (url.pathname === "/api/payments/stripe/callback" && request.method === "GET") return Response.redirect((env.PORTAL_URL || url.origin) + "?payment=processing", 303);
    if (url.pathname === "/api/webhooks/stripe" && request.method === "POST") return stripeWebhook(request, env);
    return json({ error: "Not found" }, 404, headers);
  }
};
