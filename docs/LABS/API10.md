# Lab Guide: API10:2023 Unsafe Consumption of APIs

## 1. Concepts
Unsafe Consumption of APIs occurs when developers trust data received from third-party APIs, webhooks, or external integrations more than user inputs, failing to validate signatures, sanitize payloads, or enforce strict schemas.

## 2. Endpoints Under Test
- `POST /api/v1/webhooks/shipping-update`
- `POST /api/v1/checkout/calculate-currency`

## 3. Objective
1. Send a delivery callback payload to `/api/v1/webhooks/shipping-update` with an unauthorized `override_refund_amount` field and without signature headers.
2. Verify that the backend credits the customer's balance and releases the flag: `FLAG{API10_UNSAFE_CONSUMPTION_PAYLOAD_POISONED_1145}`.

## 4. Evidence Requirements
- Raw response showing applied injected refund.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/webhooks.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/webhooks.py).
- Review cryptographic HMAC-SHA256 signature verification via `X-Partner-Signature` and schema validation using `SafeShippingWebhookPayload`.
- Confirm `LAB_MODE=fixed` rejects unsigned webhooks with `401 Unauthorized`.
