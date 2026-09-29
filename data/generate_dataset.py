"""
Fraud Investigation Copilot — Synthetic Dataset Generator v2
=============================================================
Tables: accounts, transactions, trades, device_fingerprints,
        complaints, login_events, payment_methods, agent_investigation_log

Usage:
    python data/generate_dataset.py

Outputs:
    data/fraud_cases.db   — SQLite (primary, all 8 tables)
    data/accounts.csv
    data/transactions.csv
    data/trades.csv
    data/device_fingerprints.csv
    data/complaints.csv
    data/login_events.csv
    data/payment_methods.csv
    (agent_investigation_log starts empty — populated at runtime)

Ground truth stored in separate table, never exposed to agents.
Seed is fixed (42) — regenerating produces identical data.
"""

import csv, hashlib, os, random, sqlite3, uuid
from datetime import datetime, timedelta, timezone

random.seed(42)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "fraud_cases.db")

NOW = datetime(2026, 9, 29, 7, 0, 0, tzinfo=timezone.utc)

# ── Name / geo pools ──────────────────────────────────────────────────────
FIRST = ["Amara","Chidi","Fatima","Kofi","Ngozi","Seun","Taiwo","Abiodun",
         "Blessing","Emeka","Yetunde","Kunle","Adaeze","Babatunde","Chioma",
         "Olumide","Nkechi","Femi","Aisha","Tunde","Ifeoma","Chiamaka",
         "Damilola","Ebuka","Funke","Gbenga","Halima","Ibrahim","Juliet",
         "Kola","Lara","Musa","Nneka","Patience","Rashida","Sade","Toyin",
         "Uche","Victoria","Wale","Yinka","Zainab","Ahmed","Priya","Dmitri",
         "Leila","Carlos","Jana","Mikael","Hassan","Omar","Tariq","Vera","Yusuf"]

LAST  = ["Okonkwo","Adeleke","Ibrahim","Musa","Osei","Adeyemi","Nwosu","Bello",
         "Eze","Fashola","Hassan","Ikenna","Kamara","Lawal","Mohammed","Nkrumah",
         "Okafor","Patel","Quadri","Raji","Salami","Taiwo","Usman","Vidal",
         "Abubakar","Bakare","Chukwu","Dada","Folarin","Garba","Hausa","Inyama",
         "Jibril","Kayode","Leke","Makinde","Nduka","Ekwueme","Obinna","Adeola"]

COUNTRIES = [
    ("NG","Nigeria",0.35),("GH","Ghana",0.10),("KE","Kenya",0.08),
    ("ZA","South Africa",0.07),("TZ","Tanzania",0.05),("UG","Uganda",0.04),
    ("PK","Pakistan",0.05),("IN","India",0.06),("ID","Indonesia",0.04),
    ("PH","Philippines",0.04),("MY","Malaysia",0.03),("TH","Thailand",0.02),
    ("BD","Bangladesh",0.02),("EG","Egypt",0.03),("MA","Morocco",0.02),
]

ATTACKER_COUNTRIES = ["RU","CN","UA","RO","BR"]

IP_PREFIXES = {
    "NG":["197.210","197.211","41.58","105.112"],
    "GH":["154.160","196.0","41.189"],
    "KE":["196.207","197.136"],
    "ZA":["196.2","102.65"],
    "RU":["91.108","185.220","5.188"],
    "CN":["103.21","45.195","103.224"],
    "UA":["91.234","185.191"],
    "RO":["178.175","5.2"],
    "BR":["177.67","189.112"],
}

BROWSERS  = ["Chrome/124","Firefox/125","Safari/17","Edge/124","Chrome/123"]
OS_LIST   = ["Windows 11","Windows 10","macOS 14","Ubuntu 22.04","Android 14","iOS 17"]
SCREENS   = ["1920x1080","1440x900","2560x1440","375x812","390x844","1280x800"]
TIMEZONES = ["Africa/Lagos","Africa/Accra","Africa/Nairobi","Asia/Karachi",
             "Asia/Kolkata","Europe/Moscow","Asia/Shanghai","America/Sao_Paulo"]
ASSETS    = ["R_100","R_50","EURUSD","BTCUSD","GBPUSD","Boom_1000","Crash_500","USDJPY"]
CONTRACTS = ["CALL","PUT","HIGHER","LOWER","TOUCH","NO_TOUCH"]
PAY_TYPES = ["visa","mastercard","bank_transfer","e-wallet","crypto"]
CARD_BINS = {   # BIN prefix → issuing country
    "407370":"NG","532415":"NG","455904":"GH","404455":"KE",
    "520151":"ZA","490103":"IN","491089":"PK","421694":"PH",
    "447956":"RU","601100":"NG","627488":"NG",
}

def wt_country():
    r = random.random(); cum = 0
    for code,name,w in COUNTRIES:
        cum += w
        if r < cum: return code, name
    return "NG","Nigeria"

def fake_ip(cc):
    pref = IP_PREFIXES.get(cc, ["10.0","172.16"])
    return f"{random.choice(pref)}.{random.randint(1,254)}.{random.randint(1,254)}"

def fake_device():
    return "DEV-" + hashlib.md5(str(random.random()).encode()).hexdigest()[:8].upper()

def aid(i): return f"CR-{i:05d}"

def ts(days_ago, hour=None, minute=None):
    h = hour if hour is not None else random.randint(0,23)
    m = minute if minute is not None else random.randint(0,59)
    return (NOW - timedelta(days=days_ago, hours=24-h, minutes=60-m)).isoformat()

def uid(prefix): return prefix + "-" + uuid.uuid4().hex[:10].upper()


# ════════════════════════════════════════════════════════════════════════════
# ACCOUNT ARCHETYPES
# ════════════════════════════════════════════════════════════════════════════

def base_account(idx, cc, cn, device, ip, created_days_ago):
    return {
        "account_id":          aid(idx),
        "full_name":           f"{random.choice(FIRST)} {random.choice(LAST)}",
        "email":               f"user{idx}@{random.choice(['gmail.com','yahoo.com','outlook.com'])}",
        "phone":               f"+{random.randint(1,999)}{random.randint(700,909)}{random.randint(1000000,9999999)}",
        "country_code":        cc,
        "country_name":        cn,
        "date_of_birth":       (NOW - timedelta(days=random.randint(20*365,55*365))).date().isoformat(),
        "account_created_at":  ts(created_days_ago),
        "device_id":           device,
        "ip_address":          ip,
        "currency":            random.choice(["USD","EUR","GBP"]),
        "pep_flag":            False,
        "sanctions_flag":      False,
        "sar_previously_filed":False,
        "failed_kyc_attempts": 0,
        "linked_account_count":0,
    }

def gen_clean(idx):
    cc,cn = wt_country()
    device = fake_device(); ip = fake_ip(cc)
    created = random.randint(90,730)
    dep = round(random.uniform(200,8000),2)
    trades = random.randint(20,400)
    vol = round(dep * random.uniform(1.5,8.0),2)
    wins = int(trades * random.uniform(0.40,0.60))
    wdw = round(dep * random.uniform(0.05,0.45),2)
    dep_cnt = random.randint(3,20)
    a = base_account(idx,cc,cn,device,ip,created)
    a.update({
        "total_deposited":           dep,
        "total_withdrawn":           wdw,
        "net_balance":               round(dep-wdw,2),
        "total_trades":              trades,
        "trading_volume_usd":        vol,
        "win_rate":                  round(wins/trades,3),
        "avg_trade_duration_seconds":random.randint(30,3600),
        "deposit_count":             dep_cnt,
        "withdrawal_count":          random.randint(0,5),
        "largest_single_deposit":    round(dep/dep_cnt*random.uniform(1.2,2.0),2),
        "largest_single_withdrawal": round(wdw*random.uniform(0.5,1.0),2),
        "login_count_7d":            random.randint(5,30),
        "last_login_at":             ts(random.randint(0,3)),
        "chargeback_count":          0,
    })
    return a, "CLEAN", device, ip, cc, created

def gen_mule(idx, ring_device, ring_ip, ring_size):
    cc,cn = wt_country()
    created = random.randint(7,45)
    dep = round(random.uniform(3000,12000),2)
    wdw_r = round(random.uniform(0.88,0.99),3)
    wdw = round(dep*wdw_r,2)
    dep_cnt = random.randint(2,6)
    trades = random.randint(0,3)
    a = base_account(idx,cc,cn,ring_device,ring_ip,created)
    a.update({
        "total_deposited":           dep,
        "total_withdrawn":           wdw,
        "net_balance":               round(dep-wdw,2),
        "total_trades":              trades,
        "trading_volume_usd":        round(trades*random.uniform(5,20),2),
        "win_rate":                  round(random.uniform(0,0.5),3) if trades else 0.0,
        "avg_trade_duration_seconds":random.randint(5,120) if trades else 0,
        "deposit_count":             dep_cnt,
        "withdrawal_count":          dep_cnt,
        "largest_single_deposit":    round(dep/dep_cnt*1.3,2),
        "largest_single_withdrawal": round(wdw*0.9,2),
        "login_count_7d":            random.randint(8,25),
        "last_login_at":             ts(random.randint(0,2)),
        "chargeback_count":          random.randint(0,1),
        "failed_kyc_attempts":       random.randint(0,2),
        "linked_account_count":      ring_size-1,
        "sar_previously_filed":      random.random()<0.2,
    })
    return a, "MULE", ring_device, ring_ip, cc, created

def gen_wash(idx):
    cc,cn = wt_country()
    device = fake_device(); ip = fake_ip(cc)
    created = random.randint(30,180)
    dep = round(random.uniform(5000,25000),2)
    wdw = round(dep*random.uniform(0.80,0.97),2)
    dep_cnt = random.randint(3,10)
    trades = random.randint(5,30)
    vol = round(dep*random.uniform(0.02,0.08),2)
    a = base_account(idx,cc,cn,device,ip,created)
    a.update({
        "total_deposited":           dep,
        "total_withdrawn":           wdw,
        "net_balance":               round(dep-wdw,2),
        "total_trades":              trades,
        "trading_volume_usd":        vol,
        "win_rate":                  round(random.uniform(0.85,1.0),3),
        "avg_trade_duration_seconds":random.randint(2,15),
        "deposit_count":             dep_cnt,
        "withdrawal_count":          dep_cnt-1,
        "largest_single_deposit":    round(dep*random.uniform(0.3,0.6),2),
        "largest_single_withdrawal": round(wdw*random.uniform(0.5,0.9),2),
        "login_count_7d":            random.randint(3,15),
        "last_login_at":             ts(random.randint(0,5)),
        "chargeback_count":          0,
    })
    return a, "WASH", device, ip, cc, created

def gen_ato(idx):
    cc,cn = wt_country()
    legit_device = fake_device()
    atk_device   = fake_device()
    legit_ip = fake_ip(cc)
    atk_cc   = random.choice(ATTACKER_COUNTRIES)
    atk_ip   = fake_ip(atk_cc)
    created  = random.randint(365,1095)
    dep = round(random.uniform(1000,15000),2)
    wdw = round(dep*random.uniform(0.70,0.95),2)
    trades = random.randint(50,300)
    dep_cnt = random.randint(5,20)
    a = base_account(idx,cc,cn,atk_device,atk_ip,created)
    a.update({
        "total_deposited":           dep,
        "total_withdrawn":           wdw,
        "net_balance":               round(dep-wdw,2),
        "total_trades":              trades,
        "trading_volume_usd":        round(dep*random.uniform(2.0,6.0),2),
        "win_rate":                  round(random.uniform(0.38,0.55),3),
        "avg_trade_duration_seconds":random.randint(60,1800),
        "deposit_count":             dep_cnt,
        "withdrawal_count":          2,
        "largest_single_deposit":    round(dep/dep_cnt*1.5,2),
        "largest_single_withdrawal": round(wdw*0.9,2),
        "login_count_7d":            random.randint(40,120),
        "last_login_at":             ts(0, hour=random.randint(2,5)),
        "chargeback_count":          random.randint(1,3),
        "failed_kyc_attempts":       random.randint(3,10),
    })
    # stash for login event generation
    a["_legit_device"] = legit_device
    a["_legit_ip"]     = legit_ip
    a["_atk_cc"]       = atk_cc
    a["_atk_ip"]       = atk_ip
    a["_atk_device"]   = atk_device
    return a, "ATO", atk_device, atk_ip, cc, created

def gen_velocity(idx):
    cc,cn = wt_country()
    device = fake_device(); ip = fake_ip(cc)
    created = random.randint(14,90)
    dep_cnt = random.randint(40,80)
    dep_each = round(random.uniform(100,499),2)
    dep = round(dep_cnt*dep_each,2)
    wdw = round(dep*random.uniform(0.60,0.85),2)
    trades = random.randint(0,10)
    a = base_account(idx,cc,cn,device,ip,created)
    a.update({
        "total_deposited":           dep,
        "total_withdrawn":           wdw,
        "net_balance":               round(dep-wdw,2),
        "total_trades":              trades,
        "trading_volume_usd":        round(trades*random.uniform(10,50),2),
        "win_rate":                  round(random.uniform(0,0.6),3) if trades else 0.0,
        "avg_trade_duration_seconds":random.randint(10,300) if trades else 0,
        "deposit_count":             dep_cnt,
        "withdrawal_count":          random.randint(3,10),
        "largest_single_deposit":    round(dep_each*1.1,2),
        "largest_single_withdrawal": round(wdw*0.6,2),
        "login_count_7d":            random.randint(20,60),
        "last_login_at":             ts(0),
        "chargeback_count":          random.randint(0,2),
        "failed_kyc_attempts":       random.randint(0,2),
    })
    return a, "VELOCITY", device, ip, cc, created

def gen_suspicious(idx):
    cc,cn = wt_country()
    device = fake_device(); ip = fake_ip(cc)
    created = random.randint(30,400)
    dep = round(random.uniform(1000,10000),2)
    wdw = round(dep*random.uniform(0.50,0.75),2)
    dep_cnt = random.randint(2,8)
    trades = random.randint(5,50)
    a = base_account(idx,cc,cn,device,ip,created)
    a.update({
        "total_deposited":           dep,
        "total_withdrawn":           wdw,
        "net_balance":               round(dep-wdw,2),
        "total_trades":              trades,
        "trading_volume_usd":        round(dep*random.uniform(0.1,0.8),2),
        "win_rate":                  round(random.uniform(0.35,0.65),3),
        "avg_trade_duration_seconds":random.randint(30,1800),
        "deposit_count":             dep_cnt,
        "withdrawal_count":          random.randint(1,4),
        "largest_single_deposit":    round(dep/dep_cnt*1.3,2),
        "largest_single_withdrawal": round(wdw*0.7,2),
        "login_count_7d":            random.randint(5,25),
        "last_login_at":             ts(random.randint(0,7)),
        "chargeback_count":          random.randint(0,1),
        "failed_kyc_attempts":       random.randint(0,1),
        "pep_flag":                  random.random()<0.1,
        "linked_account_count":      random.randint(0,1),
    })
    return a, "SUSPICIOUS", device, ip, cc, created


# ════════════════════════════════════════════════════════════════════════════
# SUPPORTING TABLE GENERATORS
# ════════════════════════════════════════════════════════════════════════════

def gen_transactions(acct, pattern):
    dep   = float(acct["total_deposited"])
    wdw   = float(acct["total_withdrawn"])
    dc    = int(acct["deposit_count"])
    wc    = int(acct["withdrawal_count"])
    aid_  = acct["account_id"]
    curr  = acct["currency"]
    dev   = acct["device_id"]
    ip    = acct["ip_address"]
    rows  = []
    created_days = max(1,(NOW - datetime.fromisoformat(acct["account_created_at"])).days)

    def add(typ, amt, days, hr=None, method=None):
        rows.append({
            "transaction_id":  uid("TX"),
            "account_id":      aid_,
            "timestamp":       ts(days, hr),
            "transaction_type":typ,
            "amount":          round(abs(amt),2),
            "currency":        curr,
            "payment_method":  method or random.choice(["card","bank_transfer","e-wallet"]),
            "device_id":       dev,
            "ip_address":      ip,
            "status":          "completed",
            "notes":           pattern,
        })

    if pattern == "mule":
        base = random.randint(3,20)
        for i in range(dc):
            add("deposit", dep/dc*random.uniform(0.8,1.2), base,
                random.randint(8,18), "bank_transfer")
        for i in range(wc):
            add("withdrawal", wdw/wc, base-1, random.randint(9,20))
    elif pattern == "ato":
        for i in range(dc):
            add("deposit", dep/dc, random.randint(30,created_days), random.randint(9,17))
        add("withdrawal", wdw*0.9, 1, random.randint(2,5))
        add("withdrawal", wdw*0.1, 1, random.randint(2,5))
    elif pattern == "wash":
        for i in range(dc):
            day = random.randint(5,60); h = random.randint(9,17)
            add("deposit", dep/dc, day, h)
            add("withdrawal", wdw/dc, day, h+1)
    elif pattern == "velocity":
        base = random.randint(2,5)
        for i in range(dc):
            day = max(1, base - random.randint(0,2))
            add("deposit", dep/dc*random.uniform(0.9,1.1), day,
                random.randint(0,23), "card")
        for i in range(max(1,wc)):
            add("withdrawal", wdw/max(1,wc), 1, random.randint(8,22))
    else:
        for i in range(dc):
            add("deposit", dep/dc, random.randint(10,created_days))
        for i in range(max(0,wc)):
            add("withdrawal", wdw/max(1,wc), random.randint(3,30))
    return rows


def gen_trades(acct):
    count = int(acct["total_trades"])
    vol   = float(acct["trading_volume_usd"])
    wins  = int(count * float(acct["win_rate"]))
    aid_  = acct["account_id"]
    dev   = acct["device_id"]
    rows  = []
    if count == 0 or vol == 0:
        return rows
    stake_avg = vol/count
    for i in range(count):
        stake = max(1.0, round(stake_avg*random.uniform(0.5,1.5),2))
        is_win = i < wins
        dur = max(1, int(float(acct["avg_trade_duration_seconds"])*random.uniform(0.5,1.5)))
        rows.append({
            "trade_id":        uid("TR"),
            "account_id":      aid_,
            "timestamp":       ts(random.randint(1,120), random.randint(0,23)),
            "asset":           random.choice(ASSETS),
            "contract_type":   random.choice(CONTRACTS),
            "stake_usd":       stake,
            "payout_usd":      round(stake*random.uniform(1.7,1.95),2) if is_win else 0.0,
            "duration_seconds":dur,
            "result":          "win" if is_win else "loss",
            "device_id":       dev,
        })
    return rows


def gen_device_fingerprints(acct, label, atk_meta=None):
    """One or two fingerprint records per account.
    ATO accounts get two: one for the legit user, one for attacker."""
    rows = []
    aid_ = acct["account_id"]
    created_days = max(1,(NOW - datetime.fromisoformat(acct["account_created_at"])).days)

    def fp(device_id, ip, cc, first_seen_days, last_seen_days, is_attacker=False):
        return {
            "fingerprint_id":  uid("FP"),
            "account_id":      aid_,
            "device_id":       device_id,
            "ip_address":      ip,
            "ip_country":      cc,
            "first_seen_at":   ts(first_seen_days),
            "last_seen_at":    ts(last_seen_days),
            "os":              random.choice(OS_LIST),
            "browser":         random.choice(BROWSERS),
            "screen_resolution":random.choice(SCREENS),
            "timezone":        "Europe/Moscow" if is_attacker and cc in ATTACKER_COUNTRIES
                               else random.choice(TIMEZONES),
            "language":        "ru" if is_attacker and cc=="RU" else "en",
            "vpn_detected":    is_attacker and random.random()<0.6,
            "tor_detected":    is_attacker and random.random()<0.2,
        }

    cc = acct["country_code"]
    rows.append(fp(acct["device_id"], acct["ip_address"], cc,
                   created_days, random.randint(0,3)))

    if label == "ATO" and atk_meta:
        # Attacker's device appeared recently
        rows.append(fp(atk_meta["atk_device"], atk_meta["atk_ip"], atk_meta["atk_cc"],
                       random.randint(1,7), 0, is_attacker=True))
    return rows


def gen_complaints(acct, label):
    rows = []
    aid_ = acct["account_id"]

    if label == "ATO" and random.random() < 0.85:
        rows.append({
            "complaint_id":   uid("CMP"),
            "account_id":     aid_,
            "timestamp":      ts(random.randint(0,2), random.randint(6,12)),
            "complaint_type": "account_hacked",
            "reported_by":    "customer",
            "status":         random.choice(["open","open","open","under_review"]),
            "priority":       "high",
            "notes":          "Customer reports unauthorised login and withdrawal. Did not initiate recent transactions.",
        })
    if label == "MULE" and random.random() < 0.3:
        rows.append({
            "complaint_id":   uid("CMP"),
            "account_id":     aid_,
            "timestamp":      ts(random.randint(3,15)),
            "complaint_type": "unauthorized_transaction",
            "reported_by":    "third_party",
            "status":         "open",
            "priority":       "medium",
            "notes":          "Third-party bank flagged incoming transfer as potentially fraudulent.",
        })
    if label == "VELOCITY" and random.random() < 0.2:
        rows.append({
            "complaint_id":   uid("CMP"),
            "account_id":     aid_,
            "timestamp":      ts(random.randint(0,3)),
            "complaint_type": "suspicious_activity",
            "reported_by":    "internal",
            "status":         "open",
            "priority":       "medium",
            "notes":          "Automated monitoring flagged unusual deposit volume.",
        })
    return rows


def gen_login_events(acct, label, atk_meta=None):
    """Generate realistic login event stream.
    ATO: normal history then attack pattern.
    Mule: frequent logins from shared device.
    Clean: sparse, regular logins from known device.
    """
    rows = []
    aid_ = acct["account_id"]
    cc   = acct["country_code"]
    dev  = acct["device_id"]
    ip   = acct["ip_address"]
    created_days = max(1,(NOW - datetime.fromisoformat(acct["account_created_at"])).days)

    def login(outcome, days, hr, device_id, ip_, ip_cc, reason=None):
        rows.append({
            "event_id":      uid("LG"),
            "account_id":    aid_,
            "timestamp":     ts(days, hr),
            "outcome":       outcome,
            "device_id":     device_id,
            "ip_address":    ip_,
            "ip_country":    ip_cc,
            "failure_reason":reason or ("" if outcome=="success" else "wrong_password"),
            "vpn_detected":  False,
        })

    if label == "ATO":
        # Phase 1: normal legitimate logins (old)
        for _ in range(random.randint(10,25)):
            login("success", random.randint(30,created_days),
                  random.randint(8,20), atk_meta["legit_device"],
                  atk_meta["legit_ip"], cc)
        # Phase 2: attacker credential stuffing (recent, many failures)
        atk_day = random.randint(1,7)
        for _ in range(random.randint(8,20)):
            login("fail", atk_day, random.randint(1,5),
                  atk_meta["atk_device"], atk_meta["atk_ip"],
                  atk_meta["atk_cc"], "wrong_password")
        # Phase 3: attacker succeeds
        login("success", atk_day, random.randint(2,6),
              atk_meta["atk_device"], atk_meta["atk_ip"], atk_meta["atk_cc"])
        # Phase 4: legit user tries to log back in, blocked
        login("fail", atk_day-1, random.randint(7,10),
              atk_meta["legit_device"], atk_meta["legit_ip"], cc, "account_locked")

    elif label == "MULE":
        for _ in range(random.randint(6,20)):
            fail = random.random() < 0.15
            login("fail" if fail else "success",
                  random.randint(0,30), random.randint(8,22),
                  dev, ip, cc, "wrong_password" if fail else None)

    elif label == "CLEAN":
        for _ in range(random.randint(5,20)):
            login("success", random.randint(0,90), random.randint(7,22), dev, ip, cc)

    else:
        for _ in range(random.randint(3,15)):
            fail = random.random() < 0.1
            login("fail" if fail else "success",
                  random.randint(0,60), random.randint(6,23),
                  dev, ip, cc, "wrong_password" if fail else None)
    return rows


def gen_payment_methods(acct, label):
    rows = []
    aid_ = acct["account_id"]
    bins = list(CARD_BINS.items())

    def add_method(ptype, bin_=None, bin_cc=None, shared=False, days_added=None):
        b = bin_ or random.choice(bins)
        bk, bcc = (b if isinstance(b,tuple) else (b, bin_cc or acct["country_code"]))
        rows.append({
            "method_id":     uid("PM"),
            "account_id":    aid_,
            "added_at":      ts(days_added or random.randint(10,200)),
            "payment_type":  ptype,
            "card_bin":      bk,
            "bin_country":   bcc,
            "is_active":     True,
            "times_used":    random.randint(1,20),
            "is_shared":     shared,
        })

    created_days = max(1,(NOW - datetime.fromisoformat(acct["account_created_at"])).days)

    if label == "ATO":
        # Legit card, then attacker adds a foreign card
        add_method("visa", bin_cc=acct["country_code"], days_added=created_days-5)
        atk_bin = random.choice([("447956","RU"),("420034","CN")])
        add_method("visa", bin_=atk_bin[0], bin_cc=atk_bin[1], days_added=random.randint(1,7))
    elif label == "MULE":
        # Often use same card across ring (is_shared=True)
        shared_bin = random.choice(bins)
        for _ in range(random.randint(1,2)):
            add_method(random.choice(["visa","mastercard"]),
                       bin_=shared_bin[0], bin_cc=shared_bin[1],
                       shared=True, days_added=random.randint(5,30))
    else:
        for _ in range(random.randint(1,3)):
            add_method(random.choice(PAY_TYPES), bin_cc=acct["country_code"],
                       days_added=random.randint(10,created_days))
    return rows


# ════════════════════════════════════════════════════════════════════════════
# BUILD FULL DATASET
# Distribution: 30 clean, 25 suspicious, 15 mule (4 rings), 15 wash, 10 ato, 5 velocity
# ════════════════════════════════════════════════════════════════════════════

def build():
    accounts, transactions, trades_list = [], [], []
    devices, complaints, logins, payments = [], [], [], []
    ground_truth = []
    idx = 1

    def process(gen_result, pattern):
        nonlocal idx
        a, label, device, ip, cc, created = gen_result
        # strip ATO meta fields before storing
        atk_meta = None
        if label == "ATO":
            atk_meta = {
                "legit_device": a.pop("_legit_device"),
                "legit_ip":     a.pop("_legit_ip"),
                "atk_cc":       a.pop("_atk_cc"),
                "atk_ip":       a.pop("_atk_ip"),
                "atk_device":   a.pop("_atk_device"),
            }

        accounts.append(a)
        transactions.extend(gen_transactions(a, pattern))
        trades_list.extend(gen_trades(a))
        devices.extend(gen_device_fingerprints(a, label, atk_meta))
        complaints.extend(gen_complaints(a, label))
        logins.extend(gen_login_events(a, label, atk_meta))
        payments.extend(gen_payment_methods(a, label))
        ground_truth.append({"account_id": a["account_id"], "true_label": label})

    # Clean
    for _ in range(30):
        process(gen_clean(idx), "normal"); idx += 1

    # Suspicious
    for _ in range(25):
        process(gen_suspicious(idx), "normal"); idx += 1

    # Mule rings: 4+3+4+4 = 15
    for ring_size in [4, 3, 4, 4]:
        ring_device = fake_device()
        ring_ip     = fake_ip("NG")
        ring_ids    = list(range(idx, idx+ring_size))
        for _ in ring_ids:
            process(gen_mule(idx, ring_device, ring_ip, ring_size), "mule"); idx += 1

    # Wash
    for _ in range(15):
        process(gen_wash(idx), "wash"); idx += 1

    # ATO
    for _ in range(10):
        process(gen_ato(idx), "ato"); idx += 1

    # Velocity
    for _ in range(5):
        process(gen_velocity(idx), "velocity"); idx += 1

    print(f"Accounts:     {len(accounts)}")
    print(f"Transactions: {len(transactions)}")
    print(f"Trades:       {len(trades_list)}")
    print(f"Devices:      {len(devices)}")
    print(f"Complaints:   {len(complaints)}")
    print(f"Login events: {len(logins)}")
    print(f"Pay methods:  {len(payments)}")
    return accounts, transactions, trades_list, devices, complaints, logins, payments, ground_truth


# ════════════════════════════════════════════════════════════════════════════
# WRITE SQLITE
# ════════════════════════════════════════════════════════════════════════════

DDL = """
CREATE TABLE accounts (
    account_id              TEXT PRIMARY KEY,
    full_name               TEXT NOT NULL,
    email                   TEXT,
    phone                   TEXT,
    country_code            TEXT,
    country_name            TEXT,
    date_of_birth           TEXT,
    account_created_at      TEXT,
    device_id               TEXT,
    ip_address              TEXT,
    currency                TEXT,
    pep_flag                INTEGER DEFAULT 0,
    sanctions_flag          INTEGER DEFAULT 0,
    sar_previously_filed    INTEGER DEFAULT 0,
    failed_kyc_attempts     INTEGER DEFAULT 0,
    linked_account_count    INTEGER DEFAULT 0,
    total_deposited         REAL DEFAULT 0,
    total_withdrawn         REAL DEFAULT 0,
    net_balance             REAL DEFAULT 0,
    total_trades            INTEGER DEFAULT 0,
    trading_volume_usd      REAL DEFAULT 0,
    win_rate                REAL DEFAULT 0,
    avg_trade_duration_seconds INTEGER DEFAULT 0,
    deposit_count           INTEGER DEFAULT 0,
    withdrawal_count        INTEGER DEFAULT 0,
    largest_single_deposit  REAL DEFAULT 0,
    largest_single_withdrawal REAL DEFAULT 0,
    login_count_7d          INTEGER DEFAULT 0,
    last_login_at           TEXT,
    chargeback_count        INTEGER DEFAULT 0
);

CREATE TABLE transactions (
    transaction_id   TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    timestamp        TEXT NOT NULL,
    transaction_type TEXT NOT NULL,   -- deposit | withdrawal
    amount           REAL NOT NULL,
    currency         TEXT,
    payment_method   TEXT,            -- card | bank_transfer | e-wallet
    device_id        TEXT,
    ip_address       TEXT,
    status           TEXT DEFAULT 'completed',
    notes            TEXT
);

CREATE TABLE trades (
    trade_id         TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    timestamp        TEXT NOT NULL,
    asset            TEXT,            -- R_100, EURUSD, BTCUSD …
    contract_type    TEXT,            -- CALL | PUT | HIGHER | LOWER …
    stake_usd        REAL,
    payout_usd       REAL,
    duration_seconds INTEGER,
    result           TEXT,            -- win | loss
    device_id        TEXT
);

CREATE TABLE device_fingerprints (
    fingerprint_id   TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    device_id        TEXT NOT NULL,
    ip_address       TEXT,
    ip_country       TEXT,
    first_seen_at    TEXT,
    last_seen_at     TEXT,
    os               TEXT,            -- Windows 11, macOS 14, Android 14 …
    browser          TEXT,            -- Chrome/124, Firefox/125 …
    screen_resolution TEXT,
    timezone         TEXT,
    language         TEXT,
    vpn_detected     INTEGER DEFAULT 0,
    tor_detected     INTEGER DEFAULT 0
);

CREATE TABLE complaints (
    complaint_id     TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    timestamp        TEXT NOT NULL,
    complaint_type   TEXT,  -- account_hacked | unauthorized_transaction | identity_theft | suspicious_activity
    reported_by      TEXT,  -- customer | third_party | internal
    status           TEXT,  -- open | under_review | resolved | false_alarm
    priority         TEXT,  -- high | medium | low
    notes            TEXT
);

CREATE TABLE login_events (
    event_id         TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    timestamp        TEXT NOT NULL,
    outcome          TEXT NOT NULL,   -- success | fail | blocked
    device_id        TEXT,
    ip_address       TEXT,
    ip_country       TEXT,
    failure_reason   TEXT,            -- wrong_password | account_locked | mfa_fail | ''
    vpn_detected     INTEGER DEFAULT 0
);

CREATE TABLE payment_methods (
    method_id        TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    added_at         TEXT,
    payment_type     TEXT,            -- visa | mastercard | bank_transfer | e-wallet | crypto
    card_bin         TEXT,            -- first 6 digits of card number (never full PAN)
    bin_country      TEXT,            -- issuing country derived from BIN
    is_active        INTEGER DEFAULT 1,
    times_used       INTEGER DEFAULT 0,
    is_shared        INTEGER DEFAULT 0   -- same card found on multiple accounts
);

CREATE TABLE agent_investigation_log (
    log_id              TEXT PRIMARY KEY,
    account_id          TEXT REFERENCES accounts(account_id),
    investigated_at     TEXT,
    data_source         TEXT,          -- sqlite | csv_fallback
    signal_output       TEXT,          -- JSON
    pattern_output      TEXT,          -- JSON
    policy_output       TEXT,          -- JSON
    reasoning_output    TEXT,          -- JSON
    ai_recommendation   TEXT,
    risk_classification TEXT,
    human_decision      TEXT,          -- confirmed | downgraded | dismissed | evidence_requested | null
    human_decided_at    TEXT,
    investigation_ms    INTEGER
);

-- Ground truth: NOT accessible via DataConnector
CREATE TABLE ground_truth (
    account_id  TEXT PRIMARY KEY,
    true_label  TEXT  -- CLEAN | SUSPICIOUS | MULE | WASH | ATO | VELOCITY
);

-- Convenience view: accounts sharing a device (mule ring detection)
CREATE VIEW linked_by_device AS
SELECT a.account_id, b.account_id AS linked_id, a.device_id
FROM accounts a
JOIN accounts b ON a.device_id = b.device_id AND a.account_id != b.account_id;

-- Convenience view: accounts sharing an IP
CREATE VIEW linked_by_ip AS
SELECT a.account_id, b.account_id AS linked_id, a.ip_address
FROM accounts a
JOIN accounts b ON a.ip_address = b.ip_address AND a.account_id != b.account_id;
"""

ACCT_COLS = ["account_id","full_name","email","phone","country_code","country_name",
             "date_of_birth","account_created_at","device_id","ip_address","currency",
             "pep_flag","sanctions_flag","sar_previously_filed","failed_kyc_attempts",
             "linked_account_count","total_deposited","total_withdrawn","net_balance",
             "total_trades","trading_volume_usd","win_rate","avg_trade_duration_seconds",
             "deposit_count","withdrawal_count","largest_single_deposit",
             "largest_single_withdrawal","login_count_7d","last_login_at","chargeback_count"]

TXN_COLS  = ["transaction_id","account_id","timestamp","transaction_type","amount",
             "currency","payment_method","device_id","ip_address","status","notes"]

TRD_COLS  = ["trade_id","account_id","timestamp","asset","contract_type","stake_usd",
             "payout_usd","duration_seconds","result","device_id"]

DEV_COLS  = ["fingerprint_id","account_id","device_id","ip_address","ip_country",
             "first_seen_at","last_seen_at","os","browser","screen_resolution",
             "timezone","language","vpn_detected","tor_detected"]

CMP_COLS  = ["complaint_id","account_id","timestamp","complaint_type","reported_by",
             "status","priority","notes"]

LOG_COLS  = ["event_id","account_id","timestamp","outcome","device_id","ip_address",
             "ip_country","failure_reason","vpn_detected"]

PAY_COLS  = ["method_id","account_id","added_at","payment_type","card_bin",
             "bin_country","is_active","times_used","is_shared"]


def write_sqlite(accounts, txns, trades, devices, complaints, logins, payments, gt):
    if os.path.exists(DB_PATH): os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(DDL)

    def ins(table, cols, rows):
        if not rows: return
        ph = ",".join("?"*len(cols))
        conn.executemany(f"INSERT OR IGNORE INTO {table} VALUES ({ph})",
                         [[r.get(c) for c in cols] for r in rows])

    ins("accounts",           ACCT_COLS, accounts)
    ins("transactions",       TXN_COLS,  txns)
    ins("trades",             TRD_COLS,  trades)
    ins("device_fingerprints",DEV_COLS,  devices)
    ins("complaints",         CMP_COLS,  complaints)
    ins("login_events",       LOG_COLS,  logins)
    ins("payment_methods",    PAY_COLS,  payments)

    conn.executemany("INSERT OR IGNORE INTO ground_truth VALUES (?,?)",
                     [(g["account_id"], g["true_label"]) for g in gt])
    conn.commit(); conn.close()
    print(f"SQLite → {DB_PATH}")


def write_csvs(accounts, txns, trades, devices, complaints, logins, payments):
    def w(name, cols, rows):
        path = os.path.join(BASE_DIR, f"{name}.csv")
        with open(path,"w",newline="",encoding="utf-8") as f:
            wr = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            wr.writeheader(); wr.writerows(rows)
        print(f"CSV → {path} ({len(rows)} rows)")

    w("accounts",           ACCT_COLS, accounts)
    w("transactions",       TXN_COLS,  txns)
    w("trades",             TRD_COLS,  trades)
    w("device_fingerprints",DEV_COLS,  devices)
    w("complaints",         CMP_COLS,  complaints)
    w("login_events",       LOG_COLS,  logins)
    w("payment_methods",    PAY_COLS,  payments)


if __name__ == "__main__":
    os.makedirs(BASE_DIR, exist_ok=True)
    data = build()
    accounts, txns, trades, devices, complaints, logins, payments, gt = data
    write_sqlite(*data)
    write_csvs(accounts, txns, trades, devices, complaints, logins, payments)

    # Sanity checks
    conn = sqlite3.connect(DB_PATH)
    print("\n── Label distribution ──")
    for r in conn.execute("SELECT true_label,COUNT(*) FROM ground_truth GROUP BY 1 ORDER BY 2 DESC"):
        print(f"  {r[0]:<12} {r[1]}")
    print("\n── Mule rings (shared device) ──")
    for r in conn.execute("""
        SELECT device_id, COUNT(*) as n, GROUP_CONCAT(account_id) as ring
        FROM accounts GROUP BY device_id HAVING n>1 LIMIT 6"""):
        print(f"  {r[0]}: {r[2]}")
    print("\n── ATO complaints (open) ──")
    for r in conn.execute("""
        SELECT c.account_id, c.complaint_type, c.status
        FROM complaints c LIMIT 5"""):
        print(f"  {r[0]} | {r[1]} | {r[2]}")
    print("\n── Login attack pattern (ATO sample) ──")
    ato = conn.execute("SELECT account_id FROM ground_truth WHERE true_label='ATO' LIMIT 1").fetchone()
    if ato:
        for r in conn.execute("""
            SELECT timestamp, outcome, ip_country, failure_reason
            FROM login_events WHERE account_id=? ORDER BY timestamp""", (ato[0],)):
            print(f"  {r[0][:16]}  {r[1]:<8}  {r[2]}  {r[3]}")
    conn.close()
