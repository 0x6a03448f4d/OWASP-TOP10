# API06: Unrestricted Access to Sensitive Business Flows - Attack Vectors

## Table of Contents
- [Understanding Business Flow Attack Vectors](#understanding-business-flow-attack-vectors)
- [Common Attack Patterns](#common-attack-patterns)
- [Application Flaws That Enable Attacks](#application-flaws-that-enable-attacks)
- [Detection Evasion Techniques](#detection-evasion-techniques)
- [What Attackers Look For](#what-attackers-look-for)

## Understanding Business Flow Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY**  
> This document describes attack concepts for educational purposes. Understanding these patterns helps developers build better defenses.

An **attack vector** for business flow abuse is the method attackers use to automate or excessively use sensitive business functionality in ways that harm the business. Unlike traditional attacks that breach security controls, these attacks exploit the intended functionality at scales or patterns that were never intended.

### The Core Attack Flow

```
1. Reconnaissance
   ↓
   Identify sensitive business flows (purchases, registrations, etc.)
   ↓
   Map API endpoints and parameters
   ↓
   Understand timing and validation

2. Automation Development
   ↓
   Reverse engineer API calls
   ↓
   Build automation scripts/bots
   ↓
   Test on development/staging if accessible

3. Evasion Implementation
   ↓
   Add delays to mimic human behavior
   ↓
   Rotate IPs, user agents, device IDs
   ↓
   Distribute across multiple accounts

4. Execution
   ↓
   Launch automated attack
   ↓
   Monitor for detection/blocking
   ↓
   Adjust evasion tactics as needed

5. Exploitation
   ↓
   Achieve business objective (scalping, fraud, etc.)
```

## Common Attack Patterns

### 1. Ticket/Inventory Scalping

**What it is**: Automated bulk purchasing of limited-availability items for resale.

**Attack Flow**:
```
Bot monitoring: Poll /api/tickets/availability every 100ms
↓
Detection: New inventory released
↓
Rapid execution:
  - 100+ simultaneous purchase requests
  - Reserves entire inventory in <2 seconds
  - Completes checkout before humans can react
↓
Result: All inventory purchased by bots
```

**Why It Works**:
- No detection of purchase velocity
- Cart reservation without time limits
- No behavioral analysis (instant checkout)
- Weak device fingerprinting
- No monitoring of simultaneous purchases

**Real-World Example**:
```
Concert tickets go on sale at 10:00 AM
- 10:00:00 - Tickets available: 50,000
- 10:00:05 - Bot network submits 25,000 requests
- 10:00:10 - All tickets reserved by bots
- 10:01:00 - Legitimate users see "SOLD OUT"
- 10:05:00 - Tickets appear on resale sites at 5x price
```

### 2. Flash Sale Abuse

**What it is**: Exploiting time-limited promotions through automation.

**Attack Flow**:
```
Pre-attack preparation:
  - Reverse engineer mobile app API
  - Identify product IDs for sale items
  - Pre-populate cart with items
  - Pre-fill shipping/payment info
↓
At sale start (millisecond precision):
  - Automated checkout on pre-filled carts
  - Submit 1000+ purchase requests
  - Complete transactions before sale UI even loads for humans
↓
Result: Sale inventory depleted instantly
```

**Why It Works**:
- No monitoring of pre-sale cart activity
- No checkout time analysis
- Accepts pre-computed requests
- No correlation between browsing and purchasing
- Allows instant checkout without viewing

**Technique Details**:
- Bots prepare requests before sale starts
- Use time synchronization (NTP) for precise timing
- Send all requests in first 100-500ms of sale
- Bypass UI flow entirely via direct API calls

### 3. Coupon/Discount Stacking

**What it is**: Exploiting multiple discounts beyond intended limits.

**Attack Flow**:
```
Discovery:
  - Find coupon code patterns or generation logic
  - Test multiple coupons on single transaction
  - Identify lack of stacking limits
↓
Exploitation:
  - Apply 20-50 coupon codes to single order
  - Stack percentage discounts (20% + 15% + 10%...)
  - Combine with loyalty points, referrals
  - Achieve 90%+ discount
↓
Result: Items purchased at near-zero cost
```

**Why It Works**:
- No limit on coupons per transaction
- No validation of coupon combinations
- Discount calculations stack multiplicatively
- No anomaly detection on total discount
- API doesn't track historical coupon usage

**Example Exploit**:
```http
POST /api/checkout
{
  "items": [{"id": 123, "price": 100.00}],
  "coupons": [
    "SAVE20",    // -20%
    "WELCOME15", // -15%  
    "FLASH10",   // -10%
    "LOYAL25",   // -25%
    "REFER30"    // -30%
  ],
  "loyalty_points": 5000,
  "referral_credit": 50.00
}
// Final price: $0.02 (instead of $100)
```

### 4. Inventory Reservation Squatting

**What it is**: Reserving items in carts to prevent legitimate purchases.

**Attack Flow**:
```
Bot actions:
  - Add all available inventory to cart
  - Hold reservation without purchasing
  - Wait until reservation expires
  - Immediately re-reserve items
↓
Legitimate users:
  - See items "in stock"
  - Attempt to add to cart
  - Receive "out of stock" error
  - Leave frustrated
↓
Result: Artificial scarcity, no actual sales
```

**Why It Works**:
- Cart reservations don't expire quickly enough
- No limit on items per cart
- Reservation renewal allowed
- No detection of reservation patterns
- Can reserve without intention to purchase

**Attack Variants**:
- Competitive denial: Prevent competitor from selling
- Price manipulation: Create scarcity to drive up prices
- Ransom: "Remove reservations for payment"

### 5. Review/Rating Manipulation

**What it is**: Automated posting of fake reviews to manipulate ratings.

**Attack Flow**:
```
Account preparation:
  - Create 1000+ fake accounts
  - Age accounts (appear legitimate)
  - Vary account details (different emails, IPs)
↓
Review campaign:
  - Post negative reviews on competitor (1-star)
  - Post positive reviews on own business (5-star)
  - Vary review timing and content
  - Use AI-generated unique review text
↓
Result: Manipulated ratings affecting consumer decisions
```

**Why It Works**:
- No review velocity limits per account
- No verification of actual purchase/visit
- No pattern detection across reviews
- Easy account creation
- No content uniqueness validation

**Sophistication Levels**:
```
Basic: Same review text, obvious patterns
Medium: Varied text, randomized timing
Advanced: AI-generated unique reviews, realistic patterns
Elite: Aged accounts, verified purchases, coordinated campaigns
```

### 6. Referral/Bonus Farming

**What it is**: Gaming referral programs for financial gain.

**Attack Flow**:
```
Setup:
  - Create master account
  - Create 100+ referee accounts (fake emails, VMs)
  - Use different IPs, devices for each
↓
Execution:
  - Refer fake accounts to master account
  - Complete minimum required actions
  - Trigger referral bonuses
  - Withdraw/spend accumulated rewards
↓
Result: Thousands in fraudulent rewards
```

**Why It Works**:
- No validation of referee authenticity
- No detection of related accounts
- Minimal requirements to trigger bonus
- Easy account creation
- No monitoring of referral patterns

**Example Scenario**:
```
App offers $50 for each referral
Bot creates 200 accounts = $10,000 in bonuses
Each account does minimum required action
Master account withdraws accumulated credit
```

### 7. Appointment/Booking Blocking

**What it is**: Automated booking of all available slots to resell or deny competitors.

**Attack Flow**:
```
Monitoring:
  - Bot checks /api/appointments/available
  - Identifies new slots as they open
↓
Instant booking:
  - Books all available slots within seconds
  - Uses fake/temporary contact details
  - Holds appointments without showing up
↓
Resale:
  - Charges premium to release slots
  - Or: Denies competitor access to appointments
↓
Result: Legitimate customers can't book appointments
```

**Why It Works**:
- No booking velocity limits
- No verification of booking intent
- Cancellation without penalty
- API allows bulk booking
- No tracking of no-show patterns

### 8. Account Creation Flooding

**What it is**: Mass creation of accounts for various fraudulent purposes.

**Attack Flow**:
```
Automation:
  - Generate email addresses (disposable/temporary services)
  - Solve or bypass CAPTCHA (solving services)
  - Fill registration forms programmatically
  - Create 1000+ accounts per hour
↓
Usage:
  - Claim new user bonuses
  - Distribute abuse across accounts
  - Inflate metrics/vanity numbers
  - Prepare for referral fraud
↓
Result: Polluted user base, wasted resources
```

**Why It Works**:
- Weak email verification (disposable emails accepted)
- Simple or bypassable CAPTCHA
- No registration rate limiting
- No device fingerprinting
- Welcome bonuses easy to claim

### 9. Price Scraping / Competitive Intelligence

**What it is**: Automated harvesting of pricing and inventory data.

**Attack Flow**:
```
Setup:
  - Map product catalog API endpoints
  - Identify pagination and filtering
  - Build scraping infrastructure
↓
Execution:
  - Request all product pages sequentially
  - Parse prices, availability, descriptions
  - Store in competitor database
  - Repeat hourly/daily for price tracking
↓
Result: Complete competitive intelligence database
```

**Why It Works**:
- Public APIs with no authentication
- No rate limiting on product endpoints
- Detailed product data exposed
- No detection of scraping patterns
- Sequential access allowed

**Business Impact**:
- Competitors undercut prices in real-time
- Market strategy exposed
- Proprietary product data stolen
- Inventory levels monitored

### 10. Flash Claim Abuse

**What it is**: Automated claiming of limited promotional items.

**Attack Flow**:
```
Preparation:
  - Monitor for promotion announcements
  - Reverse engineer claim API
  - Set up automation
↓
Execution:
  - Submit claim requests at precise time
  - Use multiple accounts if limited per user
  - Complete claims faster than humans possible
↓
Result: All promotional items claimed by bots
```

**Example**:
```
Company offers first 1000 users free product
Promotion starts at 3 PM
- 3:00:00 PM - Promotion goes live
- 3:00:01 PM - Bot submits 1000 claims
- 3:00:02 PM - All items claimed
- 3:01:00 PM - Real users arrive, see "SOLD OUT"
```

### 11. Vote/Poll Manipulation

**What it is**: Automated voting to skew poll results.

**Attack Flow**:
```
Target identification:
  - Find voting/poll API endpoint
  - Understand voting rules (one vote per user/IP/etc.)
↓
Bypass mechanisms:
  - Create multiple accounts
  - Rotate IP addresses
  - Clear cookies/sessions
  - Automate voting process
↓
Execution:
  - Submit thousands of votes
  - Skew results in desired direction
↓
Result: Fraudulent poll results
```

**Why It Works**:
- Weak vote validation (IP-only, cookie-based)
- Easy account creation
- No behavioral analysis
- No correlation with actual user engagement

### 12. Credential Stuffing at Scale

**What it is**: Testing stolen credentials to hijack accounts.

**Attack Flow**:
```
Preparation:
  - Obtain credential dumps (username:password)
  - Set up distributed infrastructure
  - Develop login automation
↓
Execution:
  - Test thousands of credentials per minute
  - Rotate IPs to avoid blocking
  - Identify successful logins
  - Extract valuable accounts
↓
Result: Account takeover for further abuse
```

**Why It Works**:
- No login attempt rate limiting
- No account lockout after failures
- No CAPTCHA after failed attempts
- Weak breach detection
- API accepts high login velocity

### 13. API Parameter Tampering for Discounts

**What it is**: Manipulating API request parameters to alter prices.

**Attack Flow**:
```
Discovery:
  - Intercept checkout API request
  - Identify price parameters in request
  - Test modifying price values
↓
Exploitation:
  - Change price from $100 to $1
  - Modify discount percentage
  - Alter quantity discounts
  - Change currency to lower value
↓
Result: Unauthorized price modifications
```

**Example**:
```http
POST /api/checkout
{
  "item_id": 123,
  "price": 1.00,        // Changed from 100.00
  "discount": 90,       // Changed from 0
  "currency": "VND"     // Changed from "USD"
}
// Server trusts client-provided price
```

### 14. Bulk Data Extraction

**What it is**: Extracting entire databases through API pagination.

**Attack Flow**:
```
Discovery:
  - Find paginated API endpoints
  - Identify user data in responses
  - Understand pagination mechanism
↓
Automation:
  - Request page 1, 2, 3... until end
  - Extract user emails, profiles, data
  - Store in database
  - Repeat for all resources
↓
Result: Complete database export
```

**Example**:
```
GET /api/users?page=1&limit=100
GET /api/users?page=2&limit=100
...
GET /api/users?page=1000&limit=100
// Extract 100,000 user records
```

### 15. Distributed Denial of Business (DDoBusiness)

**What it is**: Overwhelming business logic without crashing servers.

**Attack Flow**:
```
Target selection:
  - Identify expensive business operations
  - Find operations that lock resources
  - Locate processes that trigger background jobs
↓
Execution:
  - Trigger resource-intensive operations
  - Create pending transactions that need manual review
  - Generate reports that consume CPU/DB
  - Reserve inventory that blocks legitimate sales
↓
Result: Business disruption without technical outage
```

**Examples**:
- Creating 10,000 pending orders requiring manual fraud review
- Generating 1,000 complex reports simultaneously
- Reserving all appointment slots
- Requesting 5,000 password resets (email system overload)

## Application Flaws That Enable Attacks

### 1. Lack of Behavioral Analysis

**Flaw**: Only checking authentication, not behavior patterns.

**Enables**:
- Instant purchases without browsing
- Machine-speed transactions
- Predictable timing patterns

### 2. No Device Fingerprinting

**Flaw**: Not tracking device identity across requests.

**Enables**:
- Account creation abuse
- Session replay attacks
- Distributed attacks appearing as single user

### 3. Insufficient Time-Based Validation

**Flaw**: Not validating realistic time gaps between actions.

**Enables**:
- Checkout completed in milliseconds
- Immediate add-to-cart then purchase
- Superhuman form completion speeds

### 4. Client-Side Validation Only

**Flaw**: Trusting client-provided data (prices, limits, etc.).

**Enables**:
- Price manipulation
- Quantity limit bypass
- Discount stacking

### 5. Weak Account Creation Controls

**Flaw**: Easy to create unlimited accounts.

**Enables**:
- Referral fraud
- Review manipulation
- Per-user limit bypass

### 6. No Cross-Request Correlation

**Flaw**: Each request evaluated independently.

**Enables**:
- Distributed attacks across accounts
- Pattern evasion
- Velocity limit bypass

### 7. Predictable Resource IDs

**Flaw**: Sequential or guessable identifiers.

**Enables**:
- Inventory enumeration
- Scheduled item discovery (before public release)
- Targeted scalping of specific items

### 8. Absence of Risk Scoring

**Flaw**: All requests treated equally.

**Enables**:
- High-risk transactions processed normally
- No differentiation between bot and human
- Missed fraud indicators

## Detection Evasion Techniques

### Human Behavior Simulation

**Technique**: Bots mimic human interaction patterns.

**Methods**:
- Random delays between actions (2-8 seconds)
- Mouse movement and scrolling simulation
- Realistic typing speeds
- Varied user agents and screen resolutions
- Session replaying of real user behavior

### IP Rotation and Distribution

**Technique**: Avoid IP-based detection.

**Methods**:
- Residential proxy networks (millions of IPs)
- Mobile carrier proxies (rotating IPs)
- Cloud providers with IP rotation
- Tor exit nodes
- Distributed bot networks (each bot different IP)

### Account Aging and Reputation

**Technique**: Build legitimate-looking accounts.

**Methods**:
- Create accounts weeks/months before attack
- Perform normal activities to build history
- Maintain activity patterns similar to real users
- Purchase low-value items to establish trust
- Engage with non-target content

### Fingerprint Randomization

**Technique**: Prevent device tracking.

**Methods**:
- Rotate user agents
- Randomize browser fingerprints
- Use anti-detection browsers
- Spoof canvas fingerprints
- Vary screen resolutions and capabilities

## What Attackers Look For

### Target Identification

Attackers seek APIs with:

1. **High-Value Business Flows**
   - Limited inventory items
   - Financial transactions
   - Reward/bonus systems
   - Appointment booking

2. **Weak Protection Indicators**
   - No CAPTCHA or bot detection
   - Simple rate limiting only
   - Client-side validation
   - Publicly documented APIs

3. **Easy Automation**
   - Simple authentication
   - RESTful design (predictable)
   - Minimal state management
   - Direct parameter access

4. **Low Detection Risk**
   - No behavioral monitoring
   - No anomaly alerts
   - Slow response to abuse
   - No account suspension

### Reconnaissance Steps

```
1. API Discovery
   - Review mobile app traffic
   - Check JavaScript source code
   - Use API documentation if public
   - Test endpoints for authentication requirements

2. Flow Analysis
   - Map complete user journey
   - Identify required steps
   - Find optional vs. mandatory fields
   - Test validation rules

3. Limit Testing
   - Test rate limits
   - Check per-user restrictions
   - Verify resource limits
   - Identify bypass opportunities

4. Automation Development
   - Build proof-of-concept bot
   - Test on low-value targets first
   - Refine evasion techniques
   - Scale up for main attack

5. Execution
   - Launch attack
   - Monitor for detection
   - Adjust tactics real-time
   - Extract value before shutdown
```

## Key Takeaways

1. **Business flow attacks exploit intended functionality**, not security vulnerabilities
2. **Automation is the weapon**, not malicious payloads
3. **Detection requires behavioral analysis**, not just rate limiting
4. **Evasion techniques are sophisticated**, mimicking human behavior
5. **Prevention needs multi-layered approach**: device fingerprinting, behavioral analysis, risk scoring
6. **Business context matters**: What's normal for browsing is suspicious for purchasing
7. **Continuous monitoring essential**: Bots adapt, defenses must too

## Next Steps

- **[Prevention Guide](prevention.md)**: Learn comprehensive protection strategies
- **[Code Examples](examples.md)**: See secure implementations across frameworks
- **[Hands-On Lab](lab/api06-business-logic-lab/)**: Practice detecting and preventing business logic abuse
