# Lab Guide: API6:2023 Unrestricted Access to Sensitive Business Flows

## 1. Concepts
APIs exposing sensitive business workflows (purchases, coupon redemption, referrals, refunds) must defend against workflow abuse, replay attacks, negative pricing, and race conditions.

## 2. Endpoints Under Test
- `POST /api/v1/checkout/apply-coupon`
- `POST /api/v1/checkout/process-order`

## 3. Objective
1. Replay the single-use promo code `DEVTEST100` repeatedly or achieve 100% discount.
2. Submit an order checkout containing negative quantities (`quantity: -2`) to credit store balance.
3. Capture flag: `FLAG{API6_BUSINESS_FLOW_COUPON_REPLAYED_8819}`.

## 4. Evidence Requirements
- Successful HTTP 200 response demonstrating coupon replay or negative order total.
- Captured flag.

## 5. Remediation Exercise
- Inspect [app/routers/checkout.py](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/app/routers/checkout.py).
- Review single-use tracking per user account and validation requiring quantity $\ge 1$.
- Confirm `LAB_MODE=fixed` rejects coupon replay with `400 Bad Request`.
