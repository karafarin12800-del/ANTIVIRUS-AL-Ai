# ANTIVIRUS AL AI — Independent billing service

This service is intentionally separate from Planet Commerce. It provides a bilingual checkout portal and a Cloudflare Worker API backed by its own D1 database.

## Included
- Domestic Zarinpal checkout in IRR and international Stripe Checkout in USD.
- Server-side verification only: Zarinpal verify API and signed Stripe webhook.
- D1 tables for customers, orders, subscriptions and plan catalogue.
- No card data is collected or stored by this project.
- The Android scanner's file content is never uploaded by the billing service.
- Prices and all gateway credentials are configured outside Git.

## Important release gates
**Real payments remain disabled until the service is deployed, gateway merchant accounts are approved, all secrets and prices are configured, the Stripe webhook is registered, and a production domain is connected.** Never put gateway secrets in this repository, the APK, a browser bundle, or a support message.

The current Android app is still offline-first. Its Store screen is a catalogue and is not yet connected to this portal. Connect it only after a stable HTTPS portal URL is assigned and verified.

## Cloudflare resources
Create a new D1 database named `antivirus-billing` (EU jurisdiction is recommended for an EU-facing service), then apply `schema.sql`. Create a separate Worker named `antivirus-billing-api` and bind that database as `DB`. Do not reuse `planet-commerce` or `planet-commerce-api`.

Required Worker variables:
- `ALLOWED_ORIGINS`: comma-separated exact HTTPS origins of the portal and Android WebView/client only if used.
- `PORTAL_URL`: public HTTPS URL of the portal.
- `PRICE_PLUS_MONTHLY_IRR`, `PRICE_PLUS_ANNUAL_IRR`, `PRICE_PRO_FAMILY_IRR`, `PRICE_LIFETIME_IRR`: positive integer amounts in rial.
- `PRICE_PLUS_MONTHLY_USD`, `PRICE_PLUS_ANNUAL_USD`, `PRICE_PRO_FAMILY_USD`, `PRICE_LIFETIME_USD`: positive integer amounts in US cents.
- Secrets: `ZARINPAL_MERCHANT_ID`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`.

Set Stripe webhook endpoint to `https://YOUR_API_HOST/api/webhooks/stripe`, subscribe to `checkout.session.completed`, and store its signing secret as `STRIPE_WEBHOOK_SECRET`.

## API
- `GET /api/health`
- `GET /api/plans`
- `POST /api/checkout` JSON: `{ "email":"buyer@example.com", "plan":"PLUS_MONTHLY", "provider":"zarinpal|stripe", "locale":"fa|en" }`
- `GET /api/order-status?order=UUID&email=buyer@example.com`

The browser only receives the provider's hosted checkout URL. Activation is never based on a browser redirect alone. The Stripe webhook validates its signature, order/session association, amount and currency. Zarinpal callbacks call the provider's verify endpoint before activation.

## Deployment checklist
1. Provision the dedicated D1 and Worker; keep them isolated from Planet.
2. Apply the schema and configure the D1 binding.
3. Configure non-secret variables and secrets in Cloudflare.
4. Deploy the Worker and static portal on HTTPS.
5. Register Stripe webhook and verify both providers in sandbox/test mode first.
6. Set real plan prices and verify refunds, duplicate callbacks, expiry, and order reconciliation.
7. Only then connect the Android Store screen to the portal.
8. Complete privacy policy, terms, refund policy, tax and consumer-law review for each target market.

## Known next hardening work
- Add an authenticated customer account/session layer before exposing subscription management.
- Add admin reconciliation and refund endpoints with role-based access.
- Add idempotent transaction ledger and subscription extension logic for renewals.
- Send receipts only after verified payment, through a configured transactional email provider.
- Add automated Worker tests and CI validation before production release.
