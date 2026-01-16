# SimplCyber EAL (Expected Annual Loss) Methodology

**Version**: 2.3 (January 2026)
**Baseline**: $300,000 anchor
**Family Cap Formula**: `anchor × prevalence × (1 + ln(finding_count))` — logarithmic scaling
**Freshness Factor**: Undated infostealer malware = 1.5 years recency (conservative estimate)

---

## Executive Summary

**What We Do**: We add up the financial impact of the security problems we found and show you the amount of money you're putting at risk if they aren't fixed. It gives you a realistic sense of the damage these issues can cause, so you can decide what needs attention and what can wait.

SimplCyber calculates **Expected Annual Loss (EAL)** using a FAIR-inspired risk model anchored to **$300,000** — the typical cost of a serious cybersecurity incident for a small-to-medium business based on 2023-2025 breach cost data.

Each vulnerability we find represents a **potential pathway to that loss**. We calculate the financial risk by considering:
1. **What type of attack** the vulnerability enables
2. **How likely** that attack is to succeed (prevalence)
3. **How severe** the vulnerability is (CRITICAL, HIGH, MEDIUM, LOW)
4. **How fresh** the exposure is (for credential breaches)
5. **The expected financial impact** based on real-world incident costs

**Result**: A dollar figure representing the annual cybersecurity risk exposure for each company.

**Current Results (5,876 full-scan companies)**:
- Mean EAL: **$279,674**
- Median EAL: **$247,347**
- P25: **$214,914**
- P75: **$369,730**

**Key Update (Jan 2026)**: Undated infostealer malware exposures are now treated as **1.5 years old** (was 0.5 years). This is a more conservative assumption since LeakCheck does not timestamp individual stealer records. The previous 0.5-year assumption overstated risk. Expected impact: ~40% reduction in EAL for undated stealer findings.

**Why Higher Than Expected**: Most companies (50%) have **2+ attack families** (credentials + email auth + ADA), each contributing to total EAL. The mean reflects companies with legitimate multiple vulnerabilities across different families, not uncapped single-family exposure.

### Why Companies Can Exceed $300k (It's Not a Cap)

**34.6% of companies exceed the $300k anchor** - and that's correct because:

The $300k represents the **cost of ONE serious breach**, not a ceiling on total risk. Companies exceed it when they have **multiple independent attack vectors** across different families.

**Real Example - DecisionNext ($623k total EAL)**:
- **WordPress Compromise**: $254k (vulnerable WordPress → site hack → ransomware)
- **ADA Compliance**: $152k (accessibility violations → lawsuit, one-time)
- **Credential Compromise**: $126k (fresh stolen credentials → account takeover)
- **Email Auth (Phishing/BEC)**: $91k (missing SPF/DKIM/DMARC → wire fraud)

Each attack family represents a **different pathway** to a breach:
- WordPress hack ≠ credential theft ≠ phishing attack
- An attacker exploiting WordPress doesn't prevent a separate BEC scam
- Fresh stolen credentials create immediate account takeover risk independent of WordPress
- ADA lawsuit is completely separate from cyber attacks

**The Math Logic**:
- Each family is **capped at its family maximum** to prevent double-counting within that family
- But families **add together** because they're independent attack vectors
- Result: Multiple vulnerabilities across different families = multiple $300k breach pathways

**Analogy**: If your house has an unlocked front door, unlocked back door, and open window, your total burglary risk is ~$900k (3 × $300k), not $300k, because each entry point is independent.

---

## Why $300,000?

The $300,000 baseline represents the **typical total cost of a serious security incident** for an SMB, based on:

### Real-World Incident Costs (2023-2025 Data)

| Cost Component | Typical Range | Source |
|----------------|---------------|--------|
| **Ransomware payment** | $50K - $150K | FBI IC3 2024 Report |
| **Incident response** | $30K - $80K | Verizon DBIR 2024 |
| **Business downtime** | $50K - $200K | Ponemon Cost of Cyber Crime 2024 |
| **Legal/forensics** | $20K - $60K | Industry benchmarks |
| **Notification/PR** | $10K - $40K | GDPR/state breach laws |
| **Cyber insurance deductible** | $25K - $100K | Commercial policies |
| **Revenue loss** | Varies widely | Customer churn, reputation |

**Average total**: $185K - $630K depending on severity and company size

**Our anchor ($300K)**: Conservative middle estimate for SMB ($1M-$50M revenue)

### Why Not Higher/Lower?

- **Not $1M+**: That's enterprise-scale (Fortune 500). Our target market is SMBs.
- **Not $50K**: That's a "minor incident" (phishing, single compromised account). We model **breach-level events**.
- **$300K is realistic**: Matches insurance policy limits, Verizon DBIR SMB data, and SBA cyber incident surveys.

---

## How We Calculate EAL: Step-by-Step

### Step 1: Identify the Attack Type

Every vulnerability finding maps to an **attack type** that represents the realistic threat scenario:

| Attack Type | What It Means | Prevalence | Notes |
|-------------|---------------|------------|-------|
| **CREDENTIAL_COMPROMISE** | Stolen passwords lead to account takeover, ransomware, data theft | 0.50 (50%) | Universal risk, verified active employees |
| **WORDPRESS_COMPROMISE** | WordPress CVE exploitation leads to site defacement, malware injection, data theft | 0.45 (45%) | **Conditional on WordPress presence** |
| **SITE_HACK** | Web vulnerabilities (XSS, SQLi, exposed databases) lead to data breaches | 0.25 (25%) | Universal risk |
| **PHISHING_BEC** | Email authentication gaps enable phishing/BEC attacks | 0.18 (18%) | Universal risk |
| **MALWARE** | Endpoint compromise leads to ransomware/data exfiltration | 0.12 (12%) | Universal risk |
| **CLIENT_SIDE_SECRET_EXPOSURE** | Exposed API keys lead to unauthorized access/data theft | 0.08 (8%) | When exposure detected |
| **GDPR_VIOLATION** | Privacy violations trigger regulatory fines | 0.07 (7%) | Universal risk |
| **PCI_COMPLIANCE_FAILURE** | Payment data exposure triggers fines/lawsuits | 0.06 (6%) | Universal risk |

**Prevalence** = The likelihood that this attack path will be successfully exploited within a year, based on historical attack data.

**Important Notes**:
- **WordPress prevalence is CONDITIONAL**: The 0.35 (35%) prevalence applies **only to companies that run WordPress**. In our dataset, only ~7.9% of scanned companies use WordPress. When WordPress is detected, that subset faces 35% annual exploitation risk.
- **Universal vs. Conditional risks**: Most attack types apply to all companies (universal). WordPress and some specialized risks only apply when that technology is present (conditional).
- **These are probabilistic estimates**: EAL represents expected annual loss based on statistical models, not guaranteed breach costs. Think of it like insurance actuarial tables — reflects average risk for companies with similar profiles.

### Step 2: Apply Severity Multiplier

Not all vulnerabilities are equally dangerous. We apply severity multipliers:

| Severity | Multiplier | Rationale |
|----------|------------|-----------|
| **CRITICAL** | **5.0x** | Remotely exploitable, no auth required, active exploits in the wild |
| **HIGH** | **2.5x** | Exploitable with low complexity, high impact |
| **MEDIUM** | **1.0x** | Requires user interaction or specific conditions |
| **LOW** | **0.3x** | Difficult to exploit or low impact |

### Step 3: Apply Breach Recency Factor (Credentials Only)

For **credential breach findings**, we apply a **recency multiplier** based on how old the breach is:

| Breach Age | Recency Factor | Rationale |
|------------|----------------|-----------|
| **0-1 year (fresh stealer)** | **1.0x** | Active malware, session cookies likely valid, passwords current |
| **2-3 years** | 0.7x | Some credentials still valid, lower session cookie risk |
| **4-5 years** | 0.5x | Many passwords changed, mainly email-only exposure |
| **6-10 years** | 0.3x | Mostly stale, but email addresses still enable phishing |
| **10+ years (or unknown)** | 0.3x | Conservative default for undated non-stealer breaches |

**UPDATED (Jan 2025)**: When breach source is **infostealer malware** (RedLine, Raccoon, Vidar, etc.) with **NO breach_date**, we treat it as **1.5 years old** (18 months), applying a **0.7x** recency factor.

**Why 1.5 years (not 0.5)?**
- LeakCheck does NOT timestamp individual stealer records - only indexes them continuously
- Assuming all undated stealer logs are "fresh" (0.5 years) may overstate risk
- Using 1.5 years is a moderate assumption that still treats stealer data as more concerning than regular undated breaches (10+ years)
- This results in ~40% lower EAL for undated stealer findings vs the previous assumption

**Example Impact**:
- Undated stealer (1.5 years, 0.7x): $300k × 0.45 × 5.0 × 0.50 × **0.7** = **$236k** (before family cap)
- Dated fresh stealer (<1 year, 1.0x): $300k × 0.45 × 5.0 × 0.50 × **1.0** = **$337k** (before family cap)
- 10-year-old breach: $300k × 0.45 × 5.0 × 0.50 × **0.3** = **$101k** (before family cap)

### Step 4: Apply Custom Multiplier

Some finding types have **custom multipliers** based on real-world impact:

| Finding Type | Attack Type | Custom Multiplier | Why |
|--------------|-------------|-------------------|-----|
| `CRITICAL_BREACH_EXPOSURE` | CREDENTIAL_COMPROMISE | 0.50 | Credentials already stolen, high conversion to breach |
| `MISSING_TLS_CERTIFICATE` | SITE_HACK | 0.80 | No encryption = easy man-in-the-middle attacks |
| `EMAIL_SECURITY_WEAKNESS` | PHISHING_BEC | 0.30 | Enables phishing but requires attacker action |
| `WP_PLUGIN_VULNERABILITY` | WORDPRESS_COMPROMISE | Varies by CVSS | Real CVEs with known exploits |

### Step 5: Calculate EAL

```
Base Impact = ($300,000 × prevalence) × severity_multiplier × custom_multiplier

EAL (Most Likely) = Base Impact × 1.0
EAL (Low)         = Base Impact × 0.5  (conservative estimate)
EAL (High)        = Base Impact × 1.5  (worst-case estimate)
```

**We report the "Most Likely" (ML) value by default.**

---

## Example Calculation: CRITICAL WordPress Vulnerability

A company's website runs WordPress with a **CRITICAL vulnerability** (CVE-2024-XXXXX) in a popular plugin:

### Step-by-Step

1. **Attack Type**: WORDPRESS_COMPROMISE
2. **Prevalence**: 0.35 (35% chance of successful exploitation **given WordPress is present**)
3. **Severity**: CRITICAL (5.0x multiplier)
4. **Custom Multiplier**: 1.0 (verified CVE)

### Calculation

```
Base Impact = $300,000 × 0.35 = $105,000
With Severity = $105,000 × 5.0 = $525,000
Final EAL (ML) = $525,000 × 1.0 = $525,000
```

**But wait!** This exceeds our FAIR cap for WordPress vulnerabilities.

### Family-Level Capping with Logarithmic Scaling

To prevent linear accumulation while acknowledging that more vulnerabilities = more attack surface, we use **logarithmic scaling** for family caps:

```
Family Cap = $300,000 × prevalence × (1 + ln(finding_count))
```

**Example caps for WordPress (0.45 prevalence):**

| Finding Count | Cap Formula | Result |
|---------------|-------------|--------|
| 1 finding | $300k × 0.45 × (1 + ln(1)) | **$135,000** |
| 10 findings | $300k × 0.45 × (1 + ln(10)) | **$446,000** |
| 50 findings | $300k × 0.45 × (1 + ln(50)) | **$663,000** |
| 200 findings | $300k × 0.45 × (1 + ln(200)) | **$850,000** |

**Example caps for Credential Compromise (0.50 prevalence):**

| Finding Count | Cap Formula | Result |
|---------------|-------------|--------|
| 1 finding | $300k × 0.50 × (1 + ln(1)) | **$150,000** |
| 10 findings | $300k × 0.50 × (1 + ln(10)) | **$495,000** |
| 50 findings | $300k × 0.50 × (1 + ln(50)) | **$737,000** |

**Why logarithmic scaling?**

1. **Diminishing returns**: 200 findings ≈ 6.3× the cap of 1 finding (not 200×)
2. **Defensible**: Follows FAIR methodology for sub-additive risk aggregation
3. **Real-world alignment**: A site with 200 vulnerabilities is more likely to be exploited than one with 10, but each additional vulnerability adds less marginal risk
4. **Industry data support**: Patchstack 2025 shows 11.6% of WordPress CVEs are actively exploited; Sucuri 2024 shows 40% reinfection rates for compromised sites

**The math logic**:
- 1 finding: Single attack vector, cap at base prevalence × anchor
- N findings: Attack surface grows, but exploitation is sub-linear (attackers only need ONE successful exploit)
- Log scaling captures this: more vulns = more risk, but not proportionally more

**Final WordPress EAL (200 findings, capped)**: ~$850,000

### Important Context: WordPress Detection Rate

In our dataset of 5,852 scanned companies:
- **7.9% (463 companies)** were detected running WordPress
- **92.1% (5,389 companies)** show $0 WordPress EAL (WordPress not present)
- **Of the 7.9% running WordPress**: Average total exposure is **$151,629** (2X baseline risk)

**This means**: WordPress prevalence (0.35) is **conditional on WordPress presence**, not a universal 35% risk. If you don't run WordPress, your WordPress EAL is $0. If you do run WordPress, you face the 35% annual exploitation risk reflected in the model.

---

## Special Cases

### ADA Compliance (Binary, One-Time Liability)

ADA compliance violations are treated as **binary, one-time exposure**:

- **If ADA issues are found**: $35,000 (average settlement cost)
- **If no ADA issues**: $0

**⚠️ Critical Distinction: NOT Annual Risk**

Unlike other risk families (credentials, WordPress, etc.), ADA exposure is **one-time, not annual**:
- You either get sued once ($35K settlement) or you don't ($0)
- **This is NOT $35K/year recurring** — it's a single event risk
- Once remediated, ADA risk drops to $0 **permanently** (unless new violations introduced)

**Why We Emphasize ADA**

Despite being a one-time risk (not annual recurring), we highlight ADA because:

1. **Trivial to fix**: Most ADA violations can be remediated in hours or days
   - Add alt text to images
   - Fix keyboard navigation
   - Improve color contrast
   - Add ARIA labels to forms

2. **Complete risk elimination**: Fix the violations → $0 exposure forever
   - Unlike credential breaches (historical, can't undo)
   - Unlike WordPress (requires ongoing updates)
   - ADA fixes are **permanent** once implemented

3. **High ROI**: Spend $2,000-$10,000 once → eliminate $35,000 lawsuit risk
   - One of the highest ROI security/compliance fixes
   - No ongoing maintenance required (if done correctly)

**Why $35K?**
- Based on actual ADA website lawsuit settlements (2020-2024 data)
- Average settlement: $35,000 - $45,000
- We use $35K as conservative baseline

**Severity bands** (LOW, MOST LIKELY, HIGH) categorize the **likelihood** of a lawsuit, but the financial exposure is constant:
- LOW: Minor violations, low plaintiff incentive
- MOST LIKELY: Moderate violations, standard settlement territory
- HIGH: Blocking violations on transactional flows, high lawsuit risk

All bands map to $35K exposure because settlements don't vary much by violation severity.

**In Your Report**: When you see "$35K ADA compliance exposure," remember:
- This is a **one-time** lawsuit risk, not annual
- Fix it once, eliminate the risk **permanently**
- One of the easiest and highest-ROI security actions you can take

### Credential Compromise (Prevalence-Based)

Credential findings come in three severity levels based on **what was exposed**:

| Finding Type | What's Exposed | Attack Multiplier |
|--------------|----------------|-------------------|
| `EMAIL_BREACH_EXPOSURE` | Just email addresses | 0.20 (enables phishing) |
| `PASSWORD_BREACH_EXPOSURE` | Email + password pairs | 0.35 (enables account takeover) |
| `CRITICAL_BREACH_EXPOSURE` | Active infostealer malware dumps | 0.50 (current session tokens, MFA bypass) |

**Why graduated?**
- Email-only requires phishing (lower success rate)
- Email+password enables direct login (medium success rate)
- Infostealer dumps include cookies/tokens (high success rate)

**Calculation**:
```
Email-only:  $300K × 0.45 × 0.20 = $27,000
Password:    $300K × 0.45 × 0.35 = $47,250
Infostealer: $300K × 0.45 × 0.50 = $67,500
```

Then capped at family max: `$300K × 0.45 = $135,000`

### Denial of Wallet (Daily Costs)

DoW attacks exploit exposed cloud databases/APIs to **run up cloud bills**:

**Tier-based daily ranges**:
- **Tier 1 (Firebase/Firestore)**: $10K - $75K/day (request-priced, unbounded)
- **Tier 2 (Supabase/Neon)**: $500 - $10K/day (compute-bounded)
- **Tier 3 (S3/GCS)**: $1K - $15K/day (egress-bounded)

**Why daily?**
- Attacks last 1-3 days before detection (budget alerts arrive AFTER damage)
- We report **daily exposure** separately from annual EAL
- Annual extrapolation: multiply by 30/90/365 days for scenarios

**Based on real incidents**:
- Firebase attack: $70K in 1 day, $121K in 2 days (2022)
- Firestore RPS attack: $40K/day (2023)
- S3 egress abuse: $5K/day (2024)

---

## Aggregation: How Individual Findings Become Total EAL

### Per-Scan Aggregation

1. **Group findings by attack family** (WORDPRESS_COMPROMISE, CREDENTIAL_COMPROMISE, etc.)
2. **Sum EAL values within each family**
3. **Cap each family** at its prevalence-weighted max: `$300K × prevalence`
4. **Sum capped family totals** to get overall cyber EAL
5. **Add ADA** (binary) and **DoW** (daily) separately

### Example: Company with Multiple Findings

| Finding | Attack Family | Raw EAL |
|---------|---------------|---------|
| WordPress CVE #1 (CRITICAL) | WORDPRESS_COMPROMISE | $525,000 |
| WordPress CVE #2 (HIGH) | WORDPRESS_COMPROMISE | $262,500 |
| WordPress CVE #3 (MEDIUM) | WORDPRESS_COMPROMISE | $105,000 |
| Password breach exposure | CREDENTIAL_COMPROMISE | $47,250 |
| Missing SPF record | PHISHING_BEC | $16,200 |
| ADA violations | ADA_COMPLIANCE | $35,000 |

**Step 1: Sum by family**
- WORDPRESS_COMPROMISE: $892,500
- CREDENTIAL_COMPROMISE: $47,250
- PHISHING_BEC: $16,200

**Step 2: Apply caps**
- WORDPRESS_COMPROMISE: min($892,500, $105,000) = **$105,000** ← CAPPED
- CREDENTIAL_COMPROMISE: min($47,250, $135,000) = **$47,250**
- PHISHING_BEC: min($16,200, $54,000) = **$16,200**

**Step 3: Sum capped totals**
- Cyber EAL: $105,000 + $47,250 + $16,200 = **$168,450**
- Compliance (ADA): **$35,000**
- **Total EAL: $203,450**

**Why capping matters**: Without caps, this company would show $995,950 total EAL — unrealistic because multiple WordPress vulns don't cause multiple $300K breaches.

---

## Confidence Intervals (Low / ML / High)

We provide three estimates for each EAL:

| Interval | Multiplier | What It Means |
|----------|------------|---------------|
| **Low** | 0.5x | Conservative estimate (50% of base impact) |
| **ML (Most Likely)** | 1.0x | Baseline estimate (what we report by default) |
| **High** | 1.5x | Worst-case estimate (50% higher) |

**Why intervals?**
- Cybersecurity risk is probabilistic, not deterministic
- Different companies have different risk tolerances
- Insurance/finance teams often want conservative (low) vs worst-case (high) scenarios

**Most reports show ML (Most Likely) values.**

---

## Data Sources & Validation

### Industry Benchmarks
- **Verizon Data Breach Investigations Report (DBIR)** — breach costs, attack prevalence
- **FBI Internet Crime Complaint Center (IC3)** — ransomware payment data
- **Ponemon Institute** — cost of cyber crime studies
- **NIST NVD (CVE database)** — vulnerability severity scoring (CVSS)
- **OWASP Top 10** — web application attack prevalence

### Real-World Incident Data
- **2023-2025 ransomware payments**: $50K - $150K average (IC3)
- **WordPress exploitation rate**: 35% of vulnerable sites see exploitation within 90 days (Wordfence)
- **Credential stuffing success**: 0.5-2% of stolen credentials are reused successfully (Akamai)
- **ADA lawsuit settlements**: $25K - $45K average (UsableNet 2024 report)

### Sanity Checks (5,852 Company Dataset)

| Validation Check | Result | Status |
|------------------|--------|--------|
| Mean EAL within SMB range ($50K-$150K) | $83,715 | ✅ PASS |
| Median < Mean (right-skewed distribution) | $62,775 < $83,715 | ✅ PASS |
| 95th percentile < $300K anchor | P95 = $215K | ✅ PASS |
| Email security hit rate (should be high) | 93.7% | ✅ PASS |
| Breach exposure hit rate (should be high) | 81.8% | ✅ PASS |
| API module sanity (Shodan/LeakCheck/AbuseIPDB non-zero) | All non-zero | ✅ PASS |

---

## Comparison to Other Models

### How SimplCyber EAL Compares

| Model | Anchor Point | Strengths | Limitations |
|-------|--------------|-----------|-------------|
| **SimplCyber EAL** | $300K SMB breach | FAIR-inspired, prevalence-weighted, family-capped | Conservative (may underestimate for enterprises) |
| **FAIR (enterprise)** | $1M+ | Gold standard for large orgs | Overestimates for SMBs |
| **CVSS Score** | 0-10 scale | Universal vulnerability scoring | No financial context |
| **Cyber insurance** | Policy limits | Real actuarial data | Varies widely by carrier/industry |
| **Compliance fines** | Regulatory max | Legal requirements | Rare in practice for SMBs |

**SimplCyber is optimized for SMBs** ($1M-$50M revenue) and intentionally conservative to avoid "scare tactics" while still representing real financial risk.

---

## ⚠️ Important: Understanding Probabilistic Risk Estimates

### EAL is NOT a Guarantee or Prediction

**What EAL represents**:
- **Expected Annual Loss (EAL)** is a **probabilistic risk estimate** based on statistical models
- It represents the **average expected cost** for companies with similar vulnerability profiles
- It is NOT a prediction that you WILL be breached or lose exactly this amount

### Think of EAL Like Insurance Premiums

**Car insurance analogy**:
- Your premium reflects **risk factors** (age, car type, driving record)
- Insurance companies use actuarial tables showing: "Drivers with your profile have X% crash rate and $Y average claim"
- Your $1,200 annual premium does NOT mean you'll crash and file a $1,200 claim this year
- It means: "Statistically, drivers like you cost us $1,200/year on average across thousands of policyholders"

**SimplCyber EAL works the same way**:
- Your $83,715 EAL does NOT mean you'll definitely be breached for $83,715 this year
- It means: "Companies with vulnerabilities like yours face $83,715 in average annual cyber risk based on historical breach data"

### Actual Outcomes: Three Scenarios

In any given year, companies with $83,715 EAL will experience:

1. **Nothing happens (most common)**: No breach, $0 actual cost
   - Your vulnerabilities exist, but attackers don't exploit them (this year)
   - You got lucky, or your other defenses worked

2. **Partial event**: Minor incident, costs less than EAL
   - Phishing attempt blocked, small credential compromise detected early
   - Actual cost: $5,000 - $40,000

3. **Major event (rare)**: Serious breach, costs match or exceed EAL
   - Ransomware, data breach, business disruption
   - Actual cost: $100,000 - $500,000+

**The EAL ($83,715) is the weighted average across all three scenarios.**

### How to Use EAL in Decision-Making

**✅ Good uses of EAL**:
- Prioritizing which vulnerabilities to fix first (highest EAL = highest priority)
- Justifying security budget to leadership ("We're facing $83K in annual cyber risk")
- Comparing risk across time (track EAL reduction after remediation)
- Setting cyber insurance coverage levels
- Benchmarking against peer companies

**❌ Bad uses of EAL**:
- "We WILL lose $83,715 this year" (No — it's an average, not a prediction)
- "Our budget should be exactly $83,715" (No — you might spend more or less)
- "If we don't fix this, we'll be breached on this exact date" (No — timing is unpredictable)

### Communicating EAL to Stakeholders

**For CFOs/Finance**:
> "Our cybersecurity risk analysis shows $83,715 in expected annual loss based on identified vulnerabilities. This represents the average cost companies with similar security gaps face, similar to how insurance premiums reflect actuarial risk. Fixing the top 5 issues could reduce this exposure by 40-60%."

**For Boards/Executives**:
> "We face material cybersecurity risk. Our vulnerability assessment quantifies this at $83,715 annually using industry-standard FAIR methodology. This doesn't mean we'll definitely be breached, but it reflects our statistical exposure based on current defenses."

**For Technical Teams**:
> "EAL gives us a data-driven way to prioritize remediation. WordPress vulnerabilities show $105K capped family exposure — that's our highest-impact fix."

---

## Updates & Recalibration

### November 2025 Update ($250K → $300K)

**What changed**:
- ANCHOR_ANNUAL_LOSS: $250,000 → **$300,000**
- CREDENTIAL_COMPROMISE prevalence: 0.40 → **0.45**
- WORDPRESS_COMPROMISE prevalence: 0.30 → **0.35**

**Why**:
- 2024 breach cost data showed SMB incidents averaging $280K-$320K (up from $220K-$260K in 2022-2023)
- Credential compromise and WordPress exploitation rates increased in 2024 data
- Ransomware payments escalated 15-20% year-over-year

**Impact on results**:
- Mean EAL increased ~12% ($74,747 → $83,715)
- Median EAL increased ~10% ($57,068 → $62,775)
- Distribution shape unchanged (still right-skewed)

### Recalibration Schedule

We recalibrate EAL annually based on:
- Industry breach cost reports (Verizon DBIR, Ponemon, IBM)
- Ransomware payment data (FBI IC3, Coveware)
- Attack prevalence trends (exploit-db, CISA KEV)
- Insurance claims data (when available)

**Next scheduled update**: Q4 2025 (after 2025 DBIR release)

---

## Frequently Asked Questions

### Why don't you just use CVSS scores?

CVSS (0-10 scale) measures **technical severity** but not **financial impact**. A CVSS 9.8 vulnerability might have:
- $0 impact (on an isolated dev server)
- $500K impact (on production database)

EAL converts technical findings into **business risk** that CFOs and insurance underwriters understand.

### Why is my company's EAL higher/lower than average?

**Higher EAL** drivers:
- WordPress usage (2X baseline risk)
- Heavy credential exposure (breach databases + infostealers)
- Missing email authentication (enables BEC)
- Exposed cloud databases (DoW risk)

**Lower EAL** drivers:
- Strong TLS/HTTPS
- Good email authentication (SPF/DKIM/DMARC)
- No WordPress
- Clean breach databases

**The median company ($62,775) typically has**: email auth gaps + some breach exposure + moderate ADA issues.

### Does higher EAL mean I'll definitely get breached?

No. EAL is **expected annual loss** — a probabilistic estimate, not a prediction.

Think of it like car insurance:
- Your premium reflects **risk factors** (age, driving record, car type)
- Doesn't mean you'll crash this year
- But statistically, drivers with your profile have X% crash rate

EAL shows: "Companies with your vulnerabilities face $X in annual cyber risk on average."

### Can I reduce my EAL?

Yes! Prioritize fixes by EAL impact:

**Highest ROI fixes**:
1. **Remediate ADA violations** → **Eliminates $35K risk PERMANENTLY** (one-time fix, trivial effort, 2-5 days)
2. **Fix email authentication** (SPF/DKIM/DMARC) → Reduces PHISHING_BEC family
3. **Update WordPress + plugins** → Reduces WORDPRESS_COMPROMISE family
4. **Enforce MFA** → Reduces CREDENTIAL_COMPROMISE impact
5. **Fix CRITICAL TLS issues** → Reduces SITE_HACK family

**Why ADA is #1**: Unlike other risks (annual/recurring), ADA is a **one-time lawsuit risk** that can be **completely eliminated** with a few days of work. Fix alt text, keyboard nav, color contrast → $0 ADA exposure forever.

**After remediation**: Re-scan to see updated EAL. Typical reductions: 30-50% after addressing top 5 findings.

### Why does my WordPress site show higher EAL than average?

**Answer**: WordPress prevalence (0.35 or 35%) is **conditional on WordPress presence**, not a universal risk.

**What this means**:
- If you **don't run WordPress**: Your WordPress EAL = $0 (not applicable)
- If you **do run WordPress**: You face 35% annual exploitation risk

**In our dataset (5,852 companies)**:
- **7.9%** run WordPress → Average total EAL: **$151,629** (2X baseline)
- **92.1%** don't run WordPress → WordPress EAL: $0

**Why WordPress sites show 2X risk**:
- WordPress powers 40%+ of the web → large attack surface
- Public exploit databases (WPScan) catalog known vulnerabilities
- Automated scanners constantly probe for outdated plugins
- One vulnerable plugin can compromise entire site

**Mitigation**: Keep WordPress core + all plugins updated. WordPress sites that stay current show significantly lower EAL.

### Is ADA compliance risk really $35K per year?

**No!** This is a common misunderstanding.

**ADA is a ONE-TIME risk, not annual**:
- You either get sued once ($35K settlement) OR you don't ($0)
- **NOT $35K/year recurring** like other cyber risks
- Once you fix the violations, risk drops to $0 **permanently**

**Why it shows up in your report**:
- We include it because it's **trivial to fix** (2-5 days of work)
- Fixing it **permanently eliminates** the $35K lawsuit risk
- Unlike breaches (can't undo historical exposure), ADA fixes are **permanent**

**Typical fixes**:
- Add alt text to images (1-2 days)
- Fix keyboard navigation (1 day)
- Improve color contrast (few hours)
- Add ARIA labels to forms (1 day)

**ROI**: Spend $2,000-$10,000 once → eliminate $35,000 lawsuit risk forever. This is one of the highest ROI security/compliance actions.

**Bottom line**: Don't think of ADA as "$35K annual risk." Think of it as "$35K lawsuit waiting to happen, fixable in a week, permanently."

### What if I disagree with a prevalence estimate?

EAL prevalence factors come from published industry research (Verizon DBIR, Wordfence, etc.), but we understand every business is different.

**If you have stronger controls**:
- Internal security team monitoring 24/7
- Multi-factor authentication enforced
- Regular penetration testing
- Security awareness training

Your **actual** risk may be lower than the statistical baseline. Use EAL as a **starting point** for risk discussions, not an absolute truth.

**For custom risk modeling**: Enterprise customers can request adjusted prevalence factors based on security maturity assessments.

---

## Technical Implementation

### Database Schema

**Core tables**:
- `attack_meta` — Attack type definitions with prevalence and raw_weight
- `finding_type_mapping` — Maps finding types to attack types with custom multipliers
- `severity_weight` — Severity multipliers (CRITICAL: 5.0x, HIGH: 2.5x, etc.)
- `risk_constants` — System parameters (ANCHOR_ANNUAL_LOSS = 300000)
- `findings` — Individual findings with calculated EAL values (eal_low, eal_ml, eal_high)

### Calculation Flow

1. **Scan completes** → Findings inserted into `findings` table
2. **Database trigger** (`calculate_finding_eal()`) fires on INSERT/UPDATE
3. **Trigger logic**:
   - Looks up attack_type from `finding_type_mapping`
   - Retrieves prevalence, raw_weight from `attack_meta`
   - Applies severity multiplier from `severity_weight`
   - Applies custom multiplier from `finding_type_mapping`
   - Calculates eal_low/ml/high using confidence constants
   - Stores values on `findings` row
4. **Aggregation view** (`scan_eal_summary`) rolls up findings:
   - Groups by attack_type_code
   - Sums within families
   - Applies prevalence caps
   - Returns total_eal_ml, cyber_eal, compliance_eal

### Migration Files

- `apps/workers/eal-migration.sql` — Main EAL system setup
- `apps/workers/eal-credcomp-migration.sql` — Credential compromise recalibration
- `apps/workers/wp-hybrid-migration.sql` — WordPress prevalence update
- `apps/workers/migrations/2026-01-11_eal_log_scaling.sql` — Log scaling implementation

---

## Defensible Sources (v2.3)

The logarithmic family cap scaling and updated prevalence values are grounded in the following industry research:

### Exploitation Rates

| Source | Key Finding |
|--------|-------------|
| **Patchstack State of WordPress Security 2025** | 11.6% of WordPress CVEs are actively exploited or expected to be exploited |
| **Sucuri SiteCheck 2024** | 4.3% of all WordPress sites compromised annually; 40% reinfection rate |
| **FIRST EPSS** | Only 1.5% of all CVEs are observed being exploited (WordPress-specific rates are higher) |
| **Wordfence 2024** | 35% of WordPress vulnerabilities remain unpatched; attacks begin within 4 hours of disclosure |

### Incident Costs

| Source | Key Finding |
|--------|-------------|
| **IBM Cost of Data Breach 2024** | Global average breach cost: $4.88M; credential compromise average: $4.81M |
| **Verizon DBIR 2025** | Credential abuse is #1 initial access vector (22%); vulnerability exploitation up 34% YoY |
| **Techaisle 2024** | SMB average breach cost: $1.2M; upper midmarket: $28.6M |
| **Ponemon Institute** | Average cost per credential theft incident: $779,797 |

### Logarithmic Scaling Justification

| Source | Key Finding |
|--------|-------------|
| **FAIR Institute Standard v3.0** | Risk aggregation should account for correlations; not linearly additive |
| **Munich Re Cyber Insurance** | Sub-additive risk aggregation is industry standard for cyber insurance pricing |
| **NIST Vulnerability Aggregation Research** | Multiple vulnerabilities on same attack surface don't multiply incident cost |

### Why 0.45 for WordPress (was 0.35)

- Patchstack data shows **11.6% active exploitation rate** for WordPress CVEs
- Sucuri shows **4.3% annual compromise rate** with **40% reinfection**
- Combined with verified vulnerability presence, 0.45 reflects the heightened risk of actively-scanning attackers targeting known WordPress vulnerabilities

### Why 0.50 for Credentials (was 0.45)

- IBM shows credential compromise is **most costly attack vector** ($4.81M average)
- Verizon DBIR shows credential abuse is **#1 initial access method** (22%)
- SimplCyber now **verifies active employment** for infostealer findings, increasing confidence in exposure validity
- 10-11 month average dwell time for credential breaches justifies higher prevalence

---

## Document History

- **v2.3** (Jan 2026): Logarithmic family cap scaling, WORDPRESS_COMPROMISE=0.45, CREDENTIAL_COMPROMISE=0.50
  - Family caps now use `anchor × prevalence × (1 + ln(finding_count))` instead of flat caps
  - WordPress prevalence increased 0.35 → 0.45 based on Patchstack 2025 exploitation data (11.6% active exploitation rate)
  - Credential prevalence increased 0.45 → 0.50 reflecting verified active employee credential exposure
  - Sources: Patchstack State of WordPress Security 2025, Sucuri SiteCheck 2024, IBM Cost of Data Breach 2024
- **v2.2** (Jan 2026): Undated infostealer freshness factor 0.5 → 1.5 years (conservative estimate)
- **v2.0** (Nov 2025): $300K anchor, CREDENTIAL_COMPROMISE=0.45, WORDPRESS_COMPROMISE=0.35
- **v1.5** (Oct 2025): $250K anchor, FAIR-style family capping introduced
- **v1.0** (Aug 2025): Initial EAL system

---

**For questions or recalibration requests, contact**: [technical team]
**Data sources updated**: November 2025
**Next review**: Q4 2025
