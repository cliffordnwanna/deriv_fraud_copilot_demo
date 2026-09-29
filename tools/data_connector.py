"""
tools/data_connector.py  —  v2 (8-table)
==========================================
DataConnector — single access layer for the Fraud Investigation Copilot.

Tables served:
  accounts · transactions · trades · device_fingerprints
  complaints · login_events · payment_methods · agent_investigation_log

Priority:
  1. SQLite  (data/fraud_cases.db)
  2. CSV     (data/<table>.csv)
  3. Fail explicitly — no hardcoded fallback

Every response includes  "data_source": "sqlite" | "csv_fallback" | "unavailable"

Security:
  Ground truth table is intentionally inaccessible through this connector.
  Agents receive only raw behavioural data.
"""

import csv
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

# ── Paths ──────────────────────────────────────────────────────────────────
_HERE     = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_HERE, "..", "data")
_DB       = os.path.join(_DATA_DIR, "fraud_cases.db")

def _csv(name):
    return os.path.join(_DATA_DIR, f"{name}.csv")

def _db_ok():  return os.path.exists(_DB)
def _csv_ok(name): return os.path.exists(_csv(name))


# ════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ════════════════════════════════════════════════════════════════════════════

def _db_query(sql: str, params: tuple = ()) -> list[dict]:
    conn = sqlite3.connect(_DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def _csv_load(name: str) -> list[dict]:
    path = _csv(name)
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

# Fields that should be cast to numeric from CSV string
_NUM = {
    "total_deposited","total_withdrawn","net_balance","trading_volume_usd",
    "win_rate","largest_single_deposit","largest_single_withdrawal",
    "total_trades","deposit_count","withdrawal_count","avg_trade_duration_seconds",
    "login_count_7d","failed_kyc_attempts","chargeback_count","linked_account_count",
    "amount","stake_usd","payout_usd","duration_seconds","times_used",
    "investigation_ms",
}
_BOOL = {"pep_flag","sanctions_flag","sar_previously_filed","vpn_detected","tor_detected","is_shared","is_active"}

def _cast(row: dict) -> dict:
    out = {}
    for k, v in row.items():
        if k in _BOOL:
            out[k] = str(v).lower() in ("1","true","yes")
        elif k in _NUM:
            try:
                out[k] = float(v) if "." in str(v) else int(v)
            except (ValueError, TypeError):
                out[k] = v
        else:
            out[k] = v
    return out

def _now():
    return datetime.now(timezone.utc)

def _age_seconds(ts_str: str) -> float:
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z","+00:00"))
        return (_now() - ts).total_seconds()
    except Exception:
        return 9e9


# ════════════════════════════════════════════════════════════════════════════
# 1. ACCOUNT
# ════════════════════════════════════════════════════════════════════════════

def get_account(account_id: str) -> dict:
    """
    Fetch the full account profile.
    Raises ValueError if account not found.
    """
    if _db_ok():
        rows = _db_query("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
        source = "sqlite"
    elif _csv_ok("accounts"):
        rows = [r for r in _csv_load("accounts") if r.get("account_id") == account_id]
        source = "csv_fallback"
    else:
        raise RuntimeError("No data source available")

    if not rows:
        raise ValueError(f"Account {account_id} not found")

    record = _cast(rows[0])
    record["data_source"] = source
    return record


# ════════════════════════════════════════════════════════════════════════════
# 2. TRANSACTIONS
# ════════════════════════════════════════════════════════════════════════════

def get_transactions(account_id: str, days: int = 90) -> dict:
    """
    Transaction history + behavioural summary (velocity, ratios, patterns).
    """
    if _db_ok():
        rows = _db_query("""
            SELECT * FROM transactions WHERE account_id = ?
            ORDER BY timestamp DESC LIMIT 500
        """, (account_id,))
        source = "sqlite"
    elif _csv_ok("transactions"):
        rows = [r for r in _csv_load("transactions") if r.get("account_id") == account_id]
        source = "csv_fallback"
    else:
        return {"transactions": [], "summary": {}, "data_source": "unavailable"}

    rows = [_cast(r) for r in rows]
    deposits    = [r for r in rows if r.get("transaction_type") == "deposit"]
    withdrawals = [r for r in rows if r.get("transaction_type") == "withdrawal"]
    dep_amt = sum(float(r.get("amount",0)) for r in deposits)
    wdw_amt = sum(float(r.get("amount",0)) for r in withdrawals)

    def recent(rr, hours):
        return sum(1 for r in rr if _age_seconds(r.get("timestamp","")) <= hours*3600)

    # Deposit velocity pattern (structuring detection)
    # Count deposits < $500 — structuring threshold
    below_500 = sum(1 for r in deposits if float(r.get("amount",0)) < 500)
    dep_amounts = sorted([float(r.get("amount",0)) for r in deposits])

    summary = {
        "total_transactions":            len(rows),
        "deposit_count":                 len(deposits),
        "withdrawal_count":              len(withdrawals),
        "total_deposited_observed":      round(dep_amt, 2),
        "total_withdrawn_observed":      round(wdw_amt, 2),
        "withdrawal_ratio":              round(wdw_amt / dep_amt, 4) if dep_amt else 0,
        "transactions_last_24h":         recent(rows, 24),
        "transactions_last_7d":          recent(rows, 168),
        "deposits_last_24h":             recent(deposits, 24),
        "withdrawals_last_24h":          recent(withdrawals, 24),
        "largest_single_deposit":        max((float(r.get("amount",0)) for r in deposits), default=0),
        "largest_single_withdrawal":     max((float(r.get("amount",0)) for r in withdrawals), default=0),
        "avg_deposit_amount":            round(dep_amt/len(deposits),2) if deposits else 0,
        "avg_withdrawal_amount":         round(wdw_amt/len(withdrawals),2) if withdrawals else 0,
        "deposits_below_500":            below_500,
        "pct_deposits_below_500":        round(below_500/len(deposits),3) if deposits else 0,
        "avg_time_deposit_to_withdrawal":None,   # see below
    }

    # Time between first deposit and first withdrawal (quick-flip signal)
    if deposits and withdrawals:
        d_ts = sorted(r.get("timestamp","") for r in deposits)
        w_ts = sorted(r.get("timestamp","") for r in withdrawals)
        try:
            gap = _age_seconds(d_ts[0]) - _age_seconds(w_ts[0])
            summary["avg_time_deposit_to_withdrawal"] = abs(round(gap/3600, 2))  # hours
        except Exception:
            pass

    return {
        "transactions":  rows[:50],
        "summary":       summary,
        "data_source":   source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 3. TRADES
# ════════════════════════════════════════════════════════════════════════════

def get_trades(account_id: str) -> dict:
    """
    Trading activity + summary (volume, win_rate, average duration).
    """
    if _db_ok():
        rows = _db_query("""
            SELECT * FROM trades WHERE account_id = ?
            ORDER BY timestamp DESC LIMIT 200
        """, (account_id,))
        source = "sqlite"
    elif _csv_ok("trades"):
        rows = [r for r in _csv_load("trades") if r.get("account_id") == account_id]
        source = "csv_fallback"
    else:
        return {"trades": [], "summary": {}, "data_source": "unavailable"}

    rows = [_cast(r) for r in rows]
    wins        = [r for r in rows if r.get("result") == "win"]
    total_stake  = sum(float(r.get("stake_usd",0)) for r in rows)
    total_payout = sum(float(r.get("payout_usd",0)) for r in rows)
    durations    = [float(r.get("duration_seconds",0)) for r in rows if r.get("duration_seconds")]
    avg_dur      = sum(durations)/len(durations) if durations else 0

    # Very short trades = wash trading signal
    ultra_short  = sum(1 for d in durations if d <= 15)

    summary = {
        "total_trades":            len(rows),
        "win_count":               len(wins),
        "loss_count":              len(rows)-len(wins),
        "win_rate":                round(len(wins)/len(rows),4) if rows else 0,
        "total_stake_usd":         round(total_stake, 2),
        "total_payout_usd":        round(total_payout, 2),
        "net_pnl_usd":             round(total_payout-total_stake, 2),
        "avg_trade_duration_secs": round(avg_dur, 1),
        "trades_under_15s":        ultra_short,
        "pct_trades_under_15s":    round(ultra_short/len(rows),3) if rows else 0,
        "assets_traded":           list({r.get("asset") for r in rows}),
    }

    return {
        "trades":      rows[:30],
        "summary":     summary,
        "data_source": source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 4. DEVICE FINGERPRINTS
# ════════════════════════════════════════════════════════════════════════════

def get_device_fingerprints(account_id: str) -> dict:
    """
    Device fingerprint history for an account.
    Multiple devices = possible account takeover or device sharing.
    VPN/TOR flags are key ATO signals.
    """
    if _db_ok():
        rows = _db_query("""
            SELECT * FROM device_fingerprints WHERE account_id = ?
            ORDER BY first_seen_at ASC
        """, (account_id,))
        source = "sqlite"
    elif _csv_ok("device_fingerprints"):
        rows = [r for r in _csv_load("device_fingerprints") if r.get("account_id") == account_id]
        source = "csv_fallback"
    else:
        return {"fingerprints": [], "summary": {}, "data_source": "unavailable"}

    rows = [_cast(r) for r in rows]

    unique_devices   = list({r["device_id"] for r in rows if r.get("device_id")})
    unique_countries = list({r["ip_country"] for r in rows if r.get("ip_country")})
    vpn_sessions     = sum(1 for r in rows if r.get("vpn_detected"))
    tor_sessions     = sum(1 for r in rows if r.get("tor_detected"))

    summary = {
        "unique_devices":       len(unique_devices),
        "unique_countries":     len(unique_countries),
        "countries_seen":       unique_countries,
        "vpn_sessions":         vpn_sessions,
        "tor_sessions":         tor_sessions,
        "new_device_last_7d":   any(
            r for r in rows
            if _age_seconds(r.get("first_seen_at","")) <= 7*86400
        ),
    }

    return {
        "fingerprints": rows,
        "summary":      summary,
        "data_source":  source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 5. COMPLAINTS
# ════════════════════════════════════════════════════════════════════════════

def get_complaints(account_id: str) -> dict:
    """
    Customer and internal complaints for an account.
    Open 'account_hacked' complaints are immediate RED signals — account
    should stay under investigation until resolved.
    """
    if _db_ok():
        rows = _db_query("""
            SELECT * FROM complaints WHERE account_id = ?
            ORDER BY timestamp DESC
        """, (account_id,))
        source = "sqlite"
    elif _csv_ok("complaints"):
        rows = [r for r in _csv_load("complaints") if r.get("account_id") == account_id]
        source = "csv_fallback"
    else:
        return {"complaints": [], "summary": {}, "data_source": "unavailable"}

    rows = [_cast(r) for r in rows]

    open_complaints    = [r for r in rows if r.get("status") in ("open","under_review")]
    hacked_open        = [r for r in open_complaints if r.get("complaint_type") == "account_hacked"]
    high_priority_open = [r for r in open_complaints if r.get("priority") == "high"]

    summary = {
        "total_complaints":       len(rows),
        "open_complaints":        len(open_complaints),
        "has_open_hack_report":   len(hacked_open) > 0,
        "high_priority_open":     len(high_priority_open),
        "complaint_types":        list({r.get("complaint_type") for r in rows}),
        "oldest_open_days":       None,
    }
    if open_complaints:
        oldest_ts = min(r.get("timestamp","") for r in open_complaints)
        summary["oldest_open_days"] = round(_age_seconds(oldest_ts)/86400, 1)

    return {
        "complaints":  rows,
        "summary":     summary,
        "data_source": source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 6. LOGIN EVENTS
# ════════════════════════════════════════════════════════════════════════════

def get_login_events(account_id: str, days: int = 30) -> dict:
    """
    Login event stream for an account.
    Key signals: login failures, new countries, suspicious hours, rapid succession.
    """
    if _db_ok():
        rows = _db_query("""
            SELECT * FROM login_events WHERE account_id = ?
            ORDER BY timestamp DESC LIMIT 200
        """, (account_id,))
        source = "sqlite"
    elif _csv_ok("login_events"):
        rows = [r for r in _csv_load("login_events") if r.get("account_id") == account_id]
        source = "csv_fallback"
    else:
        return {"login_events": [], "summary": {}, "data_source": "unavailable"}

    rows = [_cast(r) for r in rows]

    successes  = [r for r in rows if r.get("outcome") == "success"]
    failures   = [r for r in rows if r.get("outcome") == "fail"]
    blocked    = [r for r in rows if r.get("outcome") == "blocked"]

    countries  = list({r.get("ip_country") for r in rows if r.get("ip_country")})
    new_7d     = [r for r in rows if _age_seconds(r.get("timestamp","")) <= 7*86400]

    # Night-time logins (00:00–05:00 local approximation from UTC)
    def is_night(ts_str):
        try:
            h = datetime.fromisoformat(ts_str.replace("Z","+00:00")).hour
            return h < 5
        except Exception:
            return False

    night_logins = sum(1 for r in rows if is_night(r.get("timestamp","")))

    # Rapid fail-then-succeed pattern: ≥3 failures followed by success within 1h
    brute_force_detected = False
    if failures and successes:
        for s in successes:
            s_age = _age_seconds(s.get("timestamp",""))
            recent_fails = sum(1 for f in failures
                               if abs(_age_seconds(f.get("timestamp","")) - s_age) < 3600)
            if recent_fails >= 3:
                brute_force_detected = True
                break

    summary = {
        "total_events":           len(rows),
        "success_count":          len(successes),
        "failure_count":          len(failures),
        "blocked_count":          len(blocked),
        "failure_rate":           round(len(failures)/len(rows),3) if rows else 0,
        "events_last_7d":         len(new_7d),
        "unique_countries":       len(countries),
        "countries_seen":         countries,
        "night_time_logins":      night_logins,
        "brute_force_pattern":    brute_force_detected,
        "vpn_sessions":           sum(1 for r in rows if r.get("vpn_detected")),
    }

    return {
        "login_events": rows[:50],
        "summary":      summary,
        "data_source":  source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 7. PAYMENT METHODS
# ════════════════════════════════════════════════════════════════════════════

def get_payment_methods(account_id: str) -> dict:
    """
    Payment methods registered on the account.
    Key signals: cards from foreign countries, shared cards (same card on multiple accounts),
    recently added cards (ATO attacker adds card to exfiltrate funds).
    """
    if _db_ok():
        rows = _db_query("""
            SELECT * FROM payment_methods WHERE account_id = ?
            ORDER BY added_at ASC
        """, (account_id,))
        source = "sqlite"
    elif _csv_ok("payment_methods"):
        rows = [r for r in _csv_load("payment_methods") if r.get("account_id") == account_id]
        source = "csv_fallback"
    else:
        return {"payment_methods": [], "summary": {}, "data_source": "unavailable"}

    rows = [_cast(r) for r in rows]

    # Try to get account's home country for foreign card detection
    try:
        acct = get_account(account_id)
        home_cc = acct.get("country_code","")
    except Exception:
        home_cc = ""

    shared_cards   = [r for r in rows if r.get("is_shared")]
    foreign_cards  = [r for r in rows if r.get("bin_country") and r.get("bin_country") != home_cc]
    new_7d         = [r for r in rows if _age_seconds(r.get("added_at","")) <= 7*86400]

    summary = {
        "total_methods":       len(rows),
        "shared_card_count":   len(shared_cards),
        "foreign_card_count":  len(foreign_cards),
        "foreign_card_countries": list({r.get("bin_country") for r in foreign_cards}),
        "methods_added_last_7d":  len(new_7d),
        "has_new_foreign_card":   any(
            r for r in new_7d if r.get("bin_country") and r.get("bin_country") != home_cc
        ),
    }

    return {
        "payment_methods": rows,
        "summary":         summary,
        "data_source":     source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 8. LINKED ACCOUNTS  (mule-ring detection)
# ════════════════════════════════════════════════════════════════════════════

def get_linked_accounts(account_id: str) -> dict:
    """
    Other accounts sharing the same device_id or IP address.
    Device linkage is stronger (definitive shared device).
    IP linkage may indicate same operator/network.
    """
    if _db_ok():
        device_links = _db_query("""
            SELECT b.account_id, b.full_name, b.country_code,
                   b.total_deposited, b.total_withdrawn, b.total_trades,
                   'device' AS link_type
            FROM accounts a
            JOIN accounts b ON a.device_id = b.device_id
                            AND a.account_id != b.account_id
            WHERE a.account_id = ?
        """, (account_id,))
        ip_links = _db_query("""
            SELECT b.account_id, b.full_name, b.country_code,
                   b.total_deposited, b.total_withdrawn, b.total_trades,
                   'ip_address' AS link_type
            FROM accounts a
            JOIN accounts b ON a.ip_address = b.ip_address
                            AND a.account_id != b.account_id
            WHERE a.account_id = ?
        """, (account_id,))
        linked_map = {r["account_id"]: r for r in device_links + ip_links}
        source = "sqlite"

    elif _csv_ok("accounts"):
        all_accts = [_cast(r) for r in _csv_load("accounts")]
        target = next((a for a in all_accts if a["account_id"] == account_id), None)
        if not target:
            return {"linked_accounts": [], "count": 0, "data_source": "csv_fallback"}
        linked_map = {}
        for a in all_accts:
            if a["account_id"] == account_id:
                continue
            if a.get("device_id") == target.get("device_id"):
                linked_map[a["account_id"]] = {**a, "link_type": "device"}
            elif a.get("ip_address") == target.get("ip_address"):
                linked_map[a["account_id"]] = {**a, "link_type": "ip_address"}
        source = "csv_fallback"
    else:
        return {"linked_accounts": [], "count": 0, "data_source": "unavailable"}

    linked = list(linked_map.values())
    return {
        "linked_accounts":  linked,
        "count":            len(linked),
        "device_links":     sum(1 for r in linked if r.get("link_type") == "device"),
        "ip_links":         sum(1 for r in linked if r.get("link_type") == "ip_address"),
        "data_source":      source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 9. POPULATION STATISTICS  (Pattern Agent baseline)
# ════════════════════════════════════════════════════════════════════════════

def get_population_statistics() -> dict:
    """
    Compute population baseline for Z-score normalisation.
    Returns median, mean, std, p90, p99 for key behavioural metrics.
    Ground truth never included.
    """
    if _db_ok():
        rows = _db_query("SELECT * FROM accounts")
        source = "sqlite"
    elif _csv_ok("accounts"):
        rows = [_cast(r) for r in _csv_load("accounts")]
        source = "csv_fallback"
    else:
        return {"data_source": "unavailable"}

    rows = [_cast(r) for r in rows]

    def stats(values):
        vals = sorted([v for v in values if v is not None])
        if not vals:
            return {"median":0,"mean":0,"std":0,"p90":0,"p99":0}
        n    = len(vals)
        mean = sum(vals)/n
        std  = (sum((v-mean)**2 for v in vals)/n)**0.5
        return {
            "median": vals[n//2],
            "mean":   round(mean,3),
            "std":    round(std,3),
            "p90":    vals[int(n*0.90)],
            "p99":    vals[min(int(n*0.99),n-1)],
        }

    def col(field): return [float(r.get(field,0) or 0) for r in rows]

    wdw_ratios = []
    for r in rows:
        dep = float(r.get("total_deposited",0) or 0)
        wdw = float(r.get("total_withdrawn",0) or 0)
        wdw_ratios.append(wdw/dep if dep else 0)

    return {
        "population_size":         len(rows),
        "withdrawal_ratio":        stats(wdw_ratios),
        "total_trades":            stats(col("total_trades")),
        "trading_volume_usd":      stats(col("trading_volume_usd")),
        "win_rate":                stats(col("win_rate")),
        "avg_trade_duration_secs": stats(col("avg_trade_duration_seconds")),
        "login_count_7d":          stats(col("login_count_7d")),
        "deposit_count":           stats(col("deposit_count")),
        "total_deposited":         stats(col("total_deposited")),
        "failed_kyc_attempts":     stats(col("failed_kyc_attempts")),
        "data_source":             source,
    }


# ════════════════════════════════════════════════════════════════════════════
# 10. LIST ACCOUNTS  (UI queue)
# ════════════════════════════════════════════════════════════════════════════

def list_accounts(limit: int = 100) -> dict:
    """
    All accounts with key risk signals — used to populate the investigation queue UI.
    Sorted by risk signal count descending.
    Ground-truth label intentionally excluded.
    """
    if _db_ok():
        rows = _db_query(f"""
            SELECT  a.account_id, a.full_name, a.country_code, a.currency,
                    a.total_deposited, a.total_withdrawn, a.total_trades,
                    a.pep_flag, a.sanctions_flag, a.sar_previously_filed,
                    a.failed_kyc_attempts, a.linked_account_count,
                    a.account_created_at, a.last_login_at, a.chargeback_count,
                    COALESCE(c.open_complaints, 0) AS open_complaints
            FROM    accounts a
            LEFT JOIN (
                SELECT account_id, COUNT(*) AS open_complaints
                FROM   complaints WHERE status IN ('open','under_review')
                GROUP BY account_id
            ) c ON a.account_id = c.account_id
            ORDER BY a.account_id
            LIMIT {limit}
        """)
        source = "sqlite"
    elif _csv_ok("accounts"):
        key_cols = ["account_id","full_name","country_code","currency",
                    "total_deposited","total_withdrawn","total_trades",
                    "pep_flag","sanctions_flag","sar_previously_filed",
                    "failed_kyc_attempts","linked_account_count",
                    "account_created_at","last_login_at","chargeback_count"]
        rows = [{k: r.get(k) for k in key_cols}
                for r in _csv_load("accounts")[:limit]]
        for r in rows:
            r["open_complaints"] = 0  # CSV doesn't join; good enough for queue
        source = "csv_fallback"
    else:
        return {"accounts": [], "count": 0, "data_source": "unavailable"}

    rows = [_cast(r) for r in rows]

    for r in rows:
        dep    = float(r.get("total_deposited",0) or 0)
        wdw    = float(r.get("total_withdrawn",0) or 0)
        ratio  = wdw/dep if dep else 0
        trades = int(r.get("total_trades",0) or 0)
        linked = int(r.get("linked_account_count",0) or 0)
        r["risk_signals"] = sum([
            bool(r.get("pep_flag")),
            bool(r.get("sanctions_flag")),
            bool(r.get("sar_previously_filed")),
            ratio > 0.85,
            trades == 0 and dep > 1000,
            linked > 0,
            int(r.get("failed_kyc_attempts",0) or 0) > 1,
            int(r.get("chargeback_count",0) or 0) > 0,
            int(r.get("open_complaints",0) or 0) > 0,   # NEW: complaint signal
        ])
        r["withdrawal_ratio"] = round(ratio, 3)

    rows.sort(key=lambda r: r["risk_signals"], reverse=True)
    return {"accounts": rows, "count": len(rows), "data_source": source}


# ════════════════════════════════════════════════════════════════════════════
# 11. AGENT INVESTIGATION LOG
# ════════════════════════════════════════════════════════════════════════════

def log_investigation(
    account_id: str,
    data_source: str,
    signal_output: str,
    pattern_output: str,
    policy_output: str,
    reasoning_output: str,
    ai_recommendation: str,
    risk_classification: str,
    investigation_ms: int,
) -> dict:
    """
    Persist an agent investigation run to the log table.
    Called by api.py after a completed /investigate run.
    Does NOT write human_decision — that's set via a separate endpoint.
    """
    import json, uuid
    log_id = "LOG-" + uuid.uuid4().hex[:10].upper()
    now_str = _now().isoformat()

    if _db_ok():
        _db_query("""
            INSERT INTO agent_investigation_log
            (log_id, account_id, investigated_at, data_source,
             signal_output, pattern_output, policy_output, reasoning_output,
             ai_recommendation, risk_classification, investigation_ms)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (log_id, account_id, now_str, data_source,
              signal_output, pattern_output, policy_output, reasoning_output,
              ai_recommendation, risk_classification, investigation_ms))
    # CSV fallback: skip — log only lives in DB
    return {"log_id": log_id, "logged_at": now_str}


def get_investigation_history(account_id: str, limit: int = 10) -> dict:
    """
    Retrieve past investigation runs for an account.
    Useful for re-investigation and audit trail UI.
    """
    if not _db_ok():
        return {"history": [], "data_source": "unavailable"}

    rows = _db_query("""
        SELECT log_id, account_id, investigated_at, data_source,
               ai_recommendation, risk_classification,
               human_decision, human_decided_at, investigation_ms
        FROM agent_investigation_log
        WHERE account_id = ?
        ORDER BY investigated_at DESC
        LIMIT ?
    """, (account_id, limit))
    return {"history": rows, "count": len(rows), "data_source": "sqlite"}


# ════════════════════════════════════════════════════════════════════════════
# CLI smoke test
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    # Quick smoke test against the first mule account
    test_id = "CR-00056"
    print(f"\n{'='*60}")
    print(f"DataConnector smoke test — {test_id}")
    print("="*60)

    acct = get_account(test_id)
    print(f"\n[get_account]  source={acct['data_source']}  name={acct['full_name']}")

    txn = get_transactions(test_id)
    print(f"[transactions] {txn['summary']['total_transactions']} txns  "
          f"ratio={txn['summary']['withdrawal_ratio']:.2f}")

    trd = get_trades(test_id)
    print(f"[trades]       {trd['summary']['total_trades']} trades  "
          f"win_rate={trd['summary']['win_rate']:.2f}")

    dev = get_device_fingerprints(test_id)
    print(f"[devices]      {dev['summary']['unique_devices']} device(s)  "
          f"vpn={dev['summary']['vpn_sessions']}")

    cmp = get_complaints(test_id)
    print(f"[complaints]   {cmp['summary']['total_complaints']} total  "
          f"open_hack={cmp['summary']['has_open_hack_report']}")

    lev = get_login_events(test_id)
    print(f"[logins]       {lev['summary']['total_events']} events  "
          f"failures={lev['summary']['failure_count']}")

    pay = get_payment_methods(test_id)
    print(f"[payments]     {pay['summary']['total_methods']} method(s)  "
          f"shared={pay['summary']['shared_card_count']}")

    lnk = get_linked_accounts(test_id)
    print(f"[linked]       {lnk['count']} linked  "
          f"device={lnk['device_links']}  ip={lnk['ip_links']}")

    pop = get_population_statistics()
    print(f"[population]   n={pop['population_size']}  "
          f"median_wdw_ratio={pop['withdrawal_ratio']['median']:.2f}")

    lst = list_accounts(limit=5)
    print(f"[list_accts]   top 5 by risk:")
    for a in lst["accounts"][:5]:
        print(f"  {a['account_id']}  signals={a['risk_signals']}  ratio={a['withdrawal_ratio']}")
