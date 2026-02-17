# v3.3.0 - Agent Payment Redirect Defense

**Release Date:** 2026-02-17

## 🛡️ New Critical Pattern: `agent_payment_hijack`

Added 3 CRITICAL patterns to detect Agent Payment Redirect Injection attacks — previously undetected (returned SAFE for fund theft vectors).

### Attack Vector
Adversarial injection instructs AI agents to silently redirect crypto payments (ETH/BTC/SOL/USDT/USDC) to attacker-controlled wallets while suppressing user notifications. This enables direct fund theft with no audit trail.

### New Detection Signatures

| Pattern | Description |
|---------|-------------|
| `(transfer|send|pay)...ETH/BTC/SOL...do not notify user` | Payment redirect with notification suppression |
| `send...0x[address]...quietly/silently` | Crypto address redirect with stealth instruction |
| `redirect payment...do not log/record` | Payment redirect with audit suppression |

### Impact
- **Before:** Agent Payment Redirect → SAFE (missed)
- **After:** Agent Payment Redirect → CRITICAL (detected)
