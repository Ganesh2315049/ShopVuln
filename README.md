# ShopVuln — OWASP API Security Top 10 (2023) Training Lab

> [!CAUTION]
> **SAFETY WARNING: INTENTIONALLY VULNERABLE TRAINING LAB — DO NOT DEPLOY**  
> This application contains deliberate security vulnerabilities modeled after the **OWASP API Security Top 10 (2023)**. It is created strictly for educational purposes, local security research, and authorized defensive training.
> - **Never** deploy this code to any public or production server.
> - **Never** expose the port beyond `127.0.0.1` (localhost).
> - All credentials, tokens, users, and business data are synthetic.

---

## 1. Overview & Architecture

ShopVuln is a realistic e-commerce REST API built with **FastAPI**, **SQLAlchemy 2.x**, and **SQLite**. It simulates modern e-commerce operations—users, seller product management, inventory, cart workflows, orders, returns, and administrative telemetry—while embedding reproducible vulnerabilities mapped to the OWASP API Security Top 10 (2023).

```
                      ┌────────────────────────────────────────┐
                      │    Security Tester / Burp / Postman    │
                      └───────────────────┬────────────────────┘
                                          │ 127.0.0.1:8000
                                          ▼
                      ┌────────────────────────────────────────┐
                      │      ShopVuln FastAPI Main Service     │
                      │  - E-Commerce Endpoints (/api/v1/...)   │
                      │  - Lab Controls (/lab/hints, reset)    │
                      │  - Swagger / OpenAPI Docs (/docs)      │
                      └──────────────┬──────────────────┬──────┘
                                     │                  │
                Internal Bridge /    │                  │  Local DB
                Docker Network       │                  │  (SQLite)
                                     ▼                  ▼
                    ┌──────────────────────┐    ┌───────────────┐
                    │ Mock Shipping &      │    │  shopvuln.db  │
                    │ Partner Gateway      │    └───────────────┘
                    │ (Port 9000, SSRF Lab)│
                    └──────────────────────┘
```

---

## 2. OWASP API Security Top 10 (2023) Coverage

| OWASP Category | Vulnerability Description | Lab Mode Support |
|---|---|---|
| **API1:2023** | Broken Object Level Authorization (BOLA) | `vulnerable` & `fixed` |
| **API2:2023** | Broken Authentication | `vulnerable` & `fixed` |
| **API3:2023** | Broken Object Property Level Authorization (BOPLA) | `vulnerable` & `fixed` |
| **API4:2023** | Unrestricted Resource Consumption | `vulnerable` & `fixed` |
| **API5:2023** | Broken Function Level Authorization (BFLA) | `vulnerable` & `fixed` |
| **API6:2023** | Unrestricted Access to Sensitive Business Flows | `vulnerable` & `fixed` |
| **API7:2023** | Server-Side Request Forgery (SSRF) | `vulnerable` & `fixed` |
| **API8:2023** | Security Misconfiguration | `vulnerable` & `fixed` |
| **API9:2023** | Improper Inventory Management | `vulnerable` & `fixed` |
| **API10:2023**| Unsafe Consumption of APIs | `vulnerable` & `fixed` |

---

## 3. Quick Start (Local Python)

### Prerequisites
- Python 3.11+
- pip

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Main API Service
```bash
# In PowerShell / Bash:
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 3. Run the Mock Shipping Partner Service (Optional for SSRF lab)
```bash
python -m uvicorn app.mock_services.shipping_mock:app --host 127.0.0.1 --port 9000
```

### 4. Interactive OpenAPI Docs
Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) in your browser.

---

## 4. Quick Start (Docker & Docker Compose)

```bash
docker compose up --build
```
The main API will be available at `http://127.0.0.1:8000` and the mock service at `http://127.0.0.1:9000`.

---

## 5. Lab Configuration (`LAB_MODE` and `LAB_HINTS`)

Configure the lab via environment variables or a `.env` file:

- **`LAB_MODE=vulnerable`** (Default): Flaws are live and exploitable for training.
- **`LAB_MODE=fixed`**: Defense mechanisms and secure coding patterns are enforced.
- **`LAB_HINTS=off`** (Default) / **`LAB_HINTS=on`**: Enables walkthrough guidance via `GET /lab/hints/{category}`.

### Dynamic Runtime Mode Switching (Swagger UI)
You can dynamically toggle between `vulnerable` and `fixed` modes at runtime without restarting containers:
1. Open Swagger UI at `http://127.0.0.1:8000/docs`.
2. Click **Authorize** and log in with admin credentials (`admin` / `AdminSecret2026!`).
3. Scroll to the **Lab Mode Control** section.
4. Use `GET /lab/mode` to check the current mode, or `PUT /lab/mode` with `{"mode": "fixed"}` or `{"mode": "vulnerable"}` to switch modes immediately.

---

## 6. Seed Credentials (Local Demo Only)

*All credentials are synthetic and restricted to local lab testing.*

| Role | Username | Email | Password |
|---|---|---|---|
| Customer 1 | `alice` | `alice@shopvuln.local` | `Password123!` |
| Customer 2 | `bob` | `bob@shopvuln.local` | `Password123!` |
| Customer 3 | `charlie` | `charlie@shopvuln.local` | `Password123!` |
| Seller | `seller_sam` | `sam@shopvuln.local` | `SellerPass123!` |
| Administrator | `admin` | `admin@shopvuln.local` | `AdminSecret2026!` |

---

## 7. Lab Endpoints & CTF Controls

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Operational status and current mode |
| `/lab/mode` | GET | Return active lab operational mode |
| `/lab/mode` | PUT | Switch mode between `vulnerable` and `fixed` (Admin only) |
| `/lab/reset` | POST | Restore database to default seed state |
| `/lab/scoreboard` | GET | View CTF progress and points |
| `/lab/flags/submit` | POST | Submit captured flag code |
| `/lab/hints/{category}` | GET | Educational hint (enabled when `LAB_HINTS=on`) |
| `/api/v1/auth/login` | POST | Authenticate and obtain JWT token |
| `/docs` | GET | Interactive Swagger / OpenAPI documentation |

---

## 8. Postman Collection & Automation Scripts

### Postman
- **Collection**: [postman/ShopVuln.postman_collection.json](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/postman/ShopVuln.postman_collection.json)
- **Environment**: [postman/ShopVuln.postman_environment.json](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/postman/ShopVuln.postman_environment.json)

Import both files into Postman to execute all API1–API10 vulnerability exercises and tests.

### Automation Scripts
- **Reset Database**:
  - Bash: `bash scripts/reset.sh`
  - PowerShell: `powershell -File scripts/reset.ps1`
- **Smoke Tests**:
  - Bash: `bash scripts/smoke_test.sh`
  - PowerShell: `powershell -File scripts/smoke_test.ps1`
- **Verify Fixed Mitigations**:
  - Bash: `bash scripts/verify_fixed.sh`
  - PowerShell: `powershell -File scripts/verify_fixed.ps1`

---

## 9. Documentation Index

- [docs/METHODOLOGY.md](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/docs/METHODOLOGY.md): Comprehensive API VAPT methodology.
- [docs/PLAN.md](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/docs/PLAN.md): Practical 30-day learning curriculum.
- **Lab Guides**: [API1](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/docs/LABS/API1.md) through [API10](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/docs/LABS/API10.md).
- **Solution Guides**: [API1 Solution](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/docs/SOLUTIONS/API1.md) through [API10 Solution](file:///c:/Users/GANESH/OneDrive/ドキュメント/Desktop/ShopVuln/docs/SOLUTIONS/API10.md).

---

## 10. Running Automated Tests

Run the complete 53-test regression suite:
```powershell
python -m pytest
```

