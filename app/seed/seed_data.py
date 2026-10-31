"""Deterministic synthetic seed data loader for ShopVuln training lab."""

import logging
from sqlalchemy.orm import Session
from app.core.security import hash_password
from app.models import (
    Cart,
    CartItem,
    DiscountCode,
    LabFlag,
    Order,
    OrderItem,
    Product,
    ReturnRequest,
    Review,
    User,
)

logger = logging.getLogger("shopvuln.seed")


def seed_database(db: Session, force_reset: bool = False) -> None:
    """Populate database with deterministic synthetic data if not already seeded."""
    # Check if database is already seeded
    existing_users = db.query(User).count()
    if existing_users > 0 and not force_reset:
        logger.info("Database already contains seed data (%d users found). Skipping.", existing_users)
        return

    if force_reset:
        logger.warning("Forcing reset of seed data. Purging existing records...")
        db.query(CartItem).delete()
        db.query(Cart).delete()
        db.query(ReturnRequest).delete()
        db.query(OrderItem).delete()
        db.query(Order).delete()
        db.query(Review).delete()
        db.query(Product).delete()
        db.query(DiscountCode).delete()
        db.query(LabFlag).delete()
        db.query(User).delete()
        db.commit()

    logger.info("Inserting deterministic synthetic seed data...")

    # Precomputed bcrypt hashes for deterministic speed
    PW_HASH_CUSTOMER = "$2b$10$OUKlHdCa3geRGUru.eHpG.oyh0IDCBx3gdPml65oFKCyOerIFfQGS"  # Password123!
    PW_HASH_SELLER = "$2b$10$YgXtHLsKd1D7PJoSLBSO1OCiGHl7FjisRN7R9lskjdgO71R/n8Z3a"    # SellerPass123!
    PW_HASH_ADMIN = "$2b$10$mKN7KX4dBUJm0QPGHhHV8.rHbIUIG7IaOfM8Edip2igEeXCJPl/Bq"     # AdminSecret2026!

    # 1. Synthetic Users
    users_data = [
        {
            "id": 1,
            "username": "alice",
            "email": "alice@shopvuln.local",
            "hashed_password": PW_HASH_CUSTOMER,
            "role": "customer",
            "balance": 1500.0,
        },
        {
            "id": 2,
            "username": "bob",
            "email": "bob@shopvuln.local",
            "hashed_password": PW_HASH_CUSTOMER,
            "role": "customer",
            "balance": 1200.0,
        },
        {
            "id": 3,
            "username": "charlie",
            "email": "charlie@shopvuln.local",
            "hashed_password": PW_HASH_CUSTOMER,
            "role": "customer",
            "balance": 800.0,
        },
        {
            "id": 4,
            "username": "seller_sam",
            "email": "sam@shopvuln.local",
            "hashed_password": PW_HASH_SELLER,
            "role": "seller",
            "balance": 5000.0,
        },
        {
            "id": 5,
            "username": "admin",
            "email": "admin@shopvuln.local",
            "hashed_password": PW_HASH_ADMIN,
            "role": "admin",
            "balance": 99999.0,
        },
    ]

    for u in users_data:
        user_obj = User(
            id=u["id"],
            username=u["username"],
            email=u["email"],
            hashed_password=u["hashed_password"],
            role=u["role"],
            balance=u["balance"],
            is_active=True,
        )
        db.add(user_obj)
    db.commit()

    # 2. Synthetic Products (At least 15 products)
    seller_id = 4  # seller_sam
    products_data = [
        (1, "CyberSentry Hardware Security Key", "FIDO2 / U2F cryptographic USB-C security key.", 49.99, 50, "Security Tools", False),
        (2, "Vulcanized Mechanical Keyboard", "RGB hot-swappable mechanical keyboard with custom switches.", 129.99, 30, "Hardware", False),
        (3, "UltraWide Gaming Monitor 34-inch", "144Hz curved IPS display with HDR400 support.", 499.99, 15, "Hardware", False),
        (4, "Noise-Canceling Wireless Headphones", "Over-ear active noise cancellation with 40h battery.", 199.99, 40, "Gadgets", False),
        (5, "Ergonomic Mesh Office Chair", "Adjustable lumbar support and 3D armrests.", 249.99, 20, "Home", False),
        (6, "Smart Home IoT Thermostat Hub", "Zigbee and Matter compatible smart temperature controller.", 89.99, 25, "Smart Home", False),
        (7, "Developer Hoodie - Black Edition", "100% heavyweight cotton hoodie with terminal prompt print.", 59.99, 100, "Apparel", False),
        (8, "Rust for Systems Engineering Book", "Deep dive into memory safety and concurrent programming.", 44.99, 60, "Books", False),
        (9, "The Web Application Hacker's Handbook", "Definitive classic guide to discovering web and API flaws.", 54.99, 35, "Books", False),
        (10, "Microcontroller Prototyping Kit", "ARM Cortex-M4 development board with breadboard and sensors.", 39.99, 75, "Hardware", False),
        (11, "USB-C Multiport Docking Station", "Dual 4K HDMI, Gigabit Ethernet, 100W PD charging.", 79.99, 45, "Hardware", False),
        (12, "Privacy Screen Filter for Laptop", "Polarized 15.6 inch anti-glare screen filter.", 29.99, 80, "Gadgets", False),
        (13, "Faraday Signal Blocking Bag", "RF shield bag protecting RFID, NFC, GPS, and cellular signals.", 19.99, 120, "Security Tools", False),
        (14, "Precision Screwdriver Tool Set", "64 magnetic driver bits for electronics disassembly.", 24.99, 90, "Hardware", False),
        (15, "High-Speed NVMe M.2 SSD 1TB", "PCIe Gen4 solid state drive with 7000MB/s read speeds.", 109.99, 50, "Hardware", False),
        (16, "ShopVuln Internal Prototype Gizmo", "Unreleased internal hardware prototype. RESTRICTED.", 999.99, 2, "Confidential", True),
    ]

    for p_id, title, desc, price, stock, cat, hidden in products_data:
        db.add(
            Product(
                id=p_id,
                title=title,
                description=desc,
                price=price,
                stock=stock,
                category=cat,
                is_hidden=hidden,
                seller_id=seller_id,
            )
        )
    db.commit()

    # 3. Discount Codes
    discount_codes = [
        ("WELCOME10", 10.0, 500, 15, True),
        ("VIP50", 50.0, 10, 2, True),
        ("DEVTEST100", 100.0, 1, 0, True),
    ]
    for code, pct, max_u, used, active in discount_codes:
        db.add(
            DiscountCode(
                code=code,
                discount_percent=pct,
                max_uses=max_u,
                times_used=used,
                is_active=active,
            )
        )
    db.commit()

    # 4. Orders and Order Items
    orders_data = [
        (1, 1, 179.98, 0.0, "delivered", "101 Cyber Way, San Jose, CA", "TRACK-ALICE-1001", [(1, 1, 49.99), (2, 1, 129.99)]),
        (2, 1, 59.99, 0.0, "shipped", "101 Cyber Way, San Jose, CA", "TRACK-ALICE-1002", [(7, 1, 59.99)]),
        (3, 2, 199.99, 0.0, "delivered", "404 Hacker Lane, Austin, TX", "TRACK-BOB-2001", [(4, 1, 199.99)]),
        (4, 2, 44.99, 0.0, "pending", "404 Hacker Lane, Austin, TX", "TRACK-BOB-2002", [(8, 1, 44.99)]),
        (5, 3, 249.99, 0.0, "delivered", "777 Silicon Blvd, Seattle, WA", "TRACK-CHARLIE-3001", [(5, 1, 249.99)]),
    ]

    for o_id, u_id, total, disc, status, addr, track, items in orders_data:
        order_obj = Order(
            id=o_id,
            user_id=u_id,
            total_amount=total,
            discount_amount=disc,
            status=status,
            shipping_address=addr,
            tracking_number=track,
        )
        db.add(order_obj)
        db.flush()
        for p_id, qty, unit_p in items:
            db.add(
                OrderItem(
                    order_id=order_obj.id,
                    product_id=p_id,
                    quantity=qty,
                    unit_price=unit_p,
                )
            )
    db.commit()

    # 5. Reviews
    reviews_data = [
        (1, 1, 1, 5, "Top notch security token! Works seamlessly with my auth setup.", False),
        (2, 2, 2, 4, "Solid tactile feel on switches, but keycaps could be thicker.", False),
        (3, 4, 3, 5, "Best noise cancellation I have tested during daily commute.", False),
    ]
    for r_id, p_id, u_id, rating, comment, flagged in reviews_data:
        db.add(
            Review(
                id=r_id,
                product_id=p_id,
                user_id=u_id,
                rating=rating,
                comment=comment,
                is_flagged=flagged,
            )
        )
    db.commit()

    # 6. Return Requests
    db.add(
        ReturnRequest(
            id=1,
            order_id=1,
            user_id=1,
            reason="Wrong switch layout ordered. Requesting exchange or store credit.",
            status="requested",
            refund_amount=129.99,
        )
    )

    # 7. Carts with initial items
    for u_id in [1, 2, 3]:
        cart = Cart(user_id=u_id)
        db.add(cart)
        db.flush()
        # Alice cart has product 13
        if u_id == 1:
            db.add(CartItem(cart_id=cart.id, product_id=13, quantity=2))
        # Bob cart has product 15
        elif u_id == 2:
            db.add(CartItem(cart_id=cart.id, product_id=15, quantity=1))
    db.commit()

    # 8. Deterministic Lab Flags for OWASP Top 10
    flags_data = [
        ("API1", "FLAG{API1_BOLA_ORDER_DATA_EXPOSED_9182}", "Broken Object Level Authorization - Order data intercepted", 100),
        ("API2", "FLAG{API2_BROKEN_AUTH_TOKEN_FORGED_3391}", "Broken Authentication - Token manipulation or bypass", 100),
        ("API3", "FLAG{API3_BOPLA_ADMIN_FIELD_OVERWRITTEN_7721}", "Broken Object Property Level Authorization - Mass assignment", 100),
        ("API4", "FLAG{API4_RESOURCE_CONSUMPTION_DOS_AVOIDED_6623}", "Unrestricted Resource Consumption - Large batch / page exhaustion", 100),
        ("API5", "FLAG{API5_BFLA_ADMIN_EXPORT_EXTRACTED_4412}", "Broken Function Level Authorization - Admin export accessed as user", 100),
        ("API6", "FLAG{API6_BUSINESS_FLOW_COUPON_REPLAYED_8819}", "Unrestricted Access to Sensitive Business Flows - Coupon re-use / negative price", 100),
        ("API7", "FLAG{API7_SSRF_INTERNAL_SERVICE_ACCESSED_9000}", "Server-Side Request Forgery - Mock partner gateway reached", 100),
        ("API8", "FLAG{API8_SECURITY_MISCONFIG_DEBUG_LEAK_5510}", "Security Misconfiguration - Verbose stacktrace / debug endpoint exposed", 100),
        ("API9", "FLAG{API9_IMPROPER_INVENTORY_HIDDEN_PRODUCT_FOUND_2287}", "Improper Inventory Management - Undocumented / hidden product queried", 100),
        ("API10", "FLAG{API10_UNSAFE_CONSUMPTION_PAYLOAD_POISONED_1145}", "Unsafe Consumption of APIs - Untrusted partner payload processed", 100),
    ]

    for cat, flag_c, desc, pts in flags_data:
        db.add(
            LabFlag(
                category=cat,
                flag_code=flag_c,
                description=desc,
                points=pts,
                is_solved=False,
            )
        )
    db.commit()
    logger.info("Successfully seeded database with synthetic models, products, users, and flags.")
