# M06: Inadequate Privacy Controls - Lab Instructions

## Introduction

This hands-on lab guides you through discovering and understanding privacy violations in mobile applications. You'll explore excessive data collection, permission abuse, PII leakage, and lack of user consent mechanisms.

**Learning Approach**: This lab uses a scenario-based methodology where you'll act as both a privacy auditor and security researcher, identifying violations and proposing solutions.

---

## Lab Structure

The lab is divided into **5 phases**:

1. **Phase 1**: Permission Analysis - Understanding excessive permission requests
2. **Phase 2**: Background Tracking - Discovering hidden data collection
3. **Phase 3**: PII Leakage Detection - Finding personally identifiable information in logs
4. **Phase 4**: Contact Harvesting - Analyzing mass data collection
5. **Phase 5**: Privacy Controls Implementation - Fixing the violations

---

## Phase 1: Permission Analysis

### Objective
Understand how excessive permission requests violate user privacy and create security risks.

### Scenario
You're auditing a "Restaurant Finder" mobile app that requests numerous permissions at startup.

### Steps

1. **Access the Permission Simulator**:
   - Navigate to http://localhost:5106
   - Click on **"Permission Request Simulator"**

2. **Observe the Permission Requests**:
   - Click **"Request All Permissions"**
   - Review the list of permissions requested
   - Note which permissions seem excessive

3. **Analyze the Response**:
   ```bash
   curl -X POST http://localhost:5106/api/permissions/request \
     -H "Content-Type: application/json" \
     -d '{
       "permissions": [
         "location",
         "camera",
         "contacts",
         "microphone",
         "storage",
         "phone_state",
         "calendar",
         "sms"
       ]
     }'
   ```

4. **Review the Server Response**:
   - Note the server's logging of permission grants
   - Observe any data collection triggered by permissions

### Questions to Consider

1. **Which permissions are necessary** for a restaurant finder app's core functionality?
2. **Which permissions are excessive** and violate privacy principles?
3. **What's the privacy impact** of requesting all permissions at app launch?
4. **How does this compare** to privacy-by-design principles?

### Expected Findings

- ❌ **Excessive permissions**: SMS, calendar, phone state not needed
- ❌ **No justification**: Permissions requested without explanation
- ❌ **Bundled requests**: All permissions requested simultaneously
- ❌ **Forced consent**: App blocks functionality if permissions denied

### Privacy Violations Identified

| Permission | Necessary? | Privacy Risk | Alternative |
|------------|-----------|--------------|-------------|
| Location | ✓ (Coarse) | Medium | Request when searching, use approximate location |
| Camera | ✓ (Contextual) | Low | Request only when user takes photo |
| Contacts | ✗ | **Critical** | Use contact picker for single contact |
| Microphone | ✗ | **High** | Not needed for restaurant app |
| Storage | Partial | Medium | Use scoped storage / photo picker |
| Phone State | ✗ | **High** | Not needed |
| Calendar | ✗ | **High** | Not needed (or request when saving reservation) |
| SMS | ✗ | **Critical** | Not needed |

---

## Phase 2: Background Tracking Discovery

### Objective
Discover how apps track users continuously in the background without awareness or consent.

### Scenario
The restaurant app claims to only use location "when you search," but actually tracks 24/7.

### Steps

1. **Simulate Background Tracking**:
   - Navigate to **"Background Data Collection"** section
   - Click **"Start Background Tracking"**
   - Observe the tracking frequency and data collected

2. **Monitor Network Requests**:
   - Open Browser DevTools (F12)
   - Go to **Network** tab
   - Click **"Start Tracking"**
   - Watch the periodic requests to `/api/track-location`

3. **Analyze Tracking Data**:
   ```bash
   # Simulate location tracking
   for i in {1..5}; do
     curl -X POST http://localhost:5106/api/track-location \
       -H "Content-Type: application/json" \
       -d "{
         \"latitude\": 37.$((7700 + RANDOM % 100)),
         \"longitude\": -122.$((4100 + RANDOM % 100)),
         \"timestamp\": $(date +%s),
         \"app_state\": \"background\"
       }"
     sleep 2
   done
   ```

4. **View Collected Location History**:
   ```bash
   curl http://localhost:5106/api/location-history?user_id=demo_user
   ```

### Questions to Consider

1. **How often is location tracked** in the background?
2. **What data is collected** beyond just coordinates?
3. **Is this disclosed** to users in the app's UI?
4. **What could an attacker infer** from this location history?

### Expected Findings

- ❌ **Continuous tracking**: Location sent every 30-60 seconds in background
- ❌ **High precision**: Precise coordinates (not approximate)
- ❌ **Metadata collection**: App state, battery level, network type
- ❌ **Permanent storage**: Complete location history stored
- ❌ **No user control**: No way to disable background tracking
- ❌ **Deceptive**: Contradicts "only when you search" claim

### Privacy Impact Analysis

**What can be inferred from background location data:**

```
Location History Analysis:
├─ Home Address: Most common location 10PM-6AM
├─ Work Address: Most common location 9AM-5PM
├─ Commute Pattern: Route and timing
├─ Visited Places:
│  ├─ Medical facilities (health conditions)
│  ├─ Places of worship (religion)
│  ├─ Political venues (political affiliation)
│  └─ Entertainment venues (interests, socioeconomic status)
├─ Social Network: Overlapping locations with others
└─ Behavior Patterns: Routines, habits, lifestyle
```

**Regulatory Violations:**
- GDPR: Purpose limitation (tracking beyond stated purpose)
- CCPA: Right to know (users unaware of tracking)
- Platform policies: Background location without clear disclosure

---

## Phase 3: PII Leakage Detection

### Objective
Identify personally identifiable information leaking through logs, analytics, and error messages.

### Scenario
The app logs user actions for debugging, but includes sensitive personal data.

### Steps

1. **Trigger User Actions**:
   - Navigate to **"PII Leakage Demonstration"**
   - Fill out the **"User Profile Form"** with sample data:
     - Email: john.doe@example.com
     - Name: John Doe
     - Phone: 555-123-4567
     - Address: 123 Main St, Anytown, CA 90210

2. **Submit the Form**:
   - Click **"Update Profile"**
   - Watch the browser console for logged data

3. **Check Server Logs**:
   ```bash
   # View Docker logs
   docker-compose logs | grep -A 5 "Profile update"
   ```

4. **Test Analytics Endpoint**:
   ```bash
   curl -X POST http://localhost:5106/api/analytics/track \
     -H "Content-Type: application/json" \
     -d '{
       "event": "profile_update",
       "user_email": "john.doe@example.com",
       "user_name": "John Doe",
       "user_phone": "555-123-4567",
       "user_address": "123 Main St, Anytown, CA 90210",
       "timestamp": 1705334400
     }'
   ```

5. **Simulate Error with PII**:
   ```bash
   curl -X POST http://localhost:5106/api/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "MySecretPassword123!"
     }'
   ```

### Questions to Consider

1. **What PII is visible** in application logs?
2. **Where are logs sent** (local file, cloud service, analytics platform)?
3. **Who has access** to these logs?
4. **What's the retention period** for logged PII?
5. **Is logging PII necessary** for debugging or analytics?

### Expected Findings

**PII Found in Logs:**

```python
# Server log example (from Docker logs):
[INFO] Profile update request for user: john.doe@example.com
[INFO] Updating profile data: {"email":"john.doe@example.com","name":"John Doe","phone":"555-123-4567","address":"123 Main St, Anytown, CA 90210"}
[INFO] Profile updated successfully for user john.doe@example.com

[WARNING] Login failed for email: user@example.com with password: MySecretPassword123!
```

**Privacy Violations:**
- ❌ **Email addresses** in logs (PII)
- ❌ **Full names** in logs (PII)
- ❌ **Phone numbers** in logs (PII)
- ❌ **Physical addresses** in logs (PII)
- ❌ **Passwords** in logs (**CRITICAL** - both security and privacy violation)

**Analytics PII Exposure:**
```json
{
  "event": "profile_update",
  "user_email": "john.doe@example.com",  // PII sent to third-party
  "user_name": "John Doe",               // PII
  "user_phone": "555-123-4567",          // PII
  "user_address": "123 Main St..."       // PII
}
```

### GDPR Article 5(1)(f) Violation

> "Processed in a manner that ensures appropriate security of the personal data, including protection against unauthorized or unlawful processing"

Logging PII violates this principle because:
- Logs often have broader access than production databases
- Logs sent to third-party services (analytics, crash reporting)
- Logs retained longer than necessary
- Logs not encrypted at rest

---

## Phase 4: Contact Harvesting Analysis

### Objective
Understand how apps harvest entire contact lists and share with third parties.

### Scenario
The app offers a "Find Friends" feature but uploads all contacts to build a social graph.

### Steps

1. **Simulate Contact Upload**:
   - Navigate to **"Contact Harvesting Demo"**
   - Click **"Upload Sample Contacts"**

2. **Observe the Payload**:
   - Open Browser DevTools → Network tab
   - Click **"Upload Contacts"**
   - Inspect the POST request to `/api/contacts/upload`

3. **View the Request Payload**:
   ```bash
   curl -X POST http://localhost:5106/api/contacts/upload \
     -H "Content-Type: application/json" \
     -d '{
       "user_id": "demo_user",
       "contacts": [
         {
           "name": "Alice Johnson",
           "phones": ["+1-555-0101"],
           "emails": ["alice@example.com"],
           "company": "Tech Corp"
         },
         {
           "name": "Bob Smith",
           "phones": ["+1-555-0102", "+1-555-0103"],
           "emails": ["bob@example.com", "bob.smith@company.com"],
           "birthday": "1985-03-15"
         }
       ]
     }'
   ```

4. **Check Third-Party Sharing**:
   ```bash
   # View server logs for data broker references
   docker-compose logs | grep "data broker"
   ```

### Questions to Consider

1. **How many contacts are uploaded** (user's intent vs. actual)?
2. **What information is collected** about each contact?
3. **Did the contact owners consent** to this data collection?
4. **Where is the data sent** (app servers, third-party data brokers)?
5. **Can contact owners delete** their data?

### Expected Findings

**Contact Data Collected:**

```javascript
// Per contact:
{
  "name": "Full legal name",
  "phones": ["All phone numbers"],
  "emails": ["All email addresses"],
  "addresses": ["Physical addresses"],
  "company": "Employer information",
  "birthday": "Date of birth",
  "notes": "Personal notes",
  "social_profiles": ["Social media handles"]
}
```

**Privacy Violations:**

- ❌ **Mass collection**: Entire contact list uploaded (not just selected friends)
- ❌ **Non-user exposure**: People who never agreed to terms
- ❌ **Excessive data**: Birthdays, addresses, companies not needed for "find friends"
- ❌ **Third-party sharing**: Contacts sold to data brokers
- ❌ **Permanent storage**: No expiration or deletion
- ❌ **No consent mechanism**: Contact owners can't opt out or delete
- ❌ **Shadow profiles**: Data on non-users used to build profiles

### GDPR Violations

**Article 6 (Lawfulness of Processing)**:
- No legal basis for processing non-user data
- Consent required from each contact owner, not just app user

**Article 7 (Conditions for Consent)**:
- Contact owners never gave consent
- App user cannot consent on behalf of contacts

**Penalty**: Up to €20 million or 4% of global annual revenue

---

## Phase 5: Privacy Controls Implementation

### Objective
Design and implement proper privacy controls to fix the violations discovered.

### Scenario
You're the privacy engineer tasked with fixing the privacy violations in the restaurant app.

### Exercise 1: Fix Permission Requests

**Current (Vulnerable)**:
```javascript
// Request all permissions at app launch
const permissions = [
  'location', 'camera', 'contacts', 'microphone',
  'storage', 'phone_state', 'calendar', 'sms'
];
requestPermissions(permissions); // All at once, no context
```

**Your Task**: Design a privacy-friendly permission strategy

**Solution Checklist**:
- [ ] Identify truly necessary permissions
- [ ] Request permissions contextually (when feature used)
- [ ] Provide clear explanation before requesting
- [ ] Request minimum scope (coarse vs. fine location)
- [ ] Offer alternative functionality if denied

**Proposed Solution**:
```javascript
// Only request necessary permissions, contextually
function onSearchNearbyRestaurants() {
  if (!hasPermission('location')) {
    showExplanation({
      title: "Location Permission",
      message: "To find restaurants near you, we need your approximate location.\n\n" +
               "• Only used when you search\n" +
               "• Never tracked in background\n" +
               "• You can deny and enter location manually",
      onAccept: () => requestPermission('location', scope: 'coarse'),
      onDeny: () => showManualLocationEntry()
    });
  } else {
    searchNearby();
  }
}
```

### Exercise 2: Eliminate Background Tracking

**Current (Vulnerable)**:
```python
# Continuous background tracking
def track_location_background():
    while True:
        location = get_precise_location()
        send_to_server(location)
        time.sleep(30)  # Every 30 seconds
```

**Your Task**: Design location usage that respects privacy

**Solution Checklist**:
- [ ] Only request location when app is in use
- [ ] Use one-time location request (not continuous)
- [ ] Use approximate location when sufficient
- [ ] Don't store location history
- [ ] Provide user control to disable

**Proposed Solution**:
```python
# Privacy-friendly approach
def search_nearby_restaurants():
    # Only when user explicitly searches
    if user_consents_to_location():
        # One-time request
        location = get_approximate_location()  # Coarse, not fine
        
        # Use immediately, don't store
        restaurants = search_restaurants_near(location)
        
        # Don't send to server or log
        return restaurants
    else:
        # Alternative: manual location entry
        return prompt_manual_location()
```

### Exercise 3: Privacy-Safe Logging

**Current (Vulnerable)**:
```python
# Logs with PII
logger.info(f"Login attempt for email: {user_email}")
logger.debug(f"Password: {password}")  # CRITICAL!
logger.info(f"User data: {user_object}")
```

**Your Task**: Implement privacy-safe logging

**Solution Checklist**:
- [ ] Never log passwords or credentials
- [ ] Use hashed identifiers instead of emails
- [ ] Log user IDs, not personal information
- [ ] Auto-redact PII patterns
- [ ] Minimize logging of user actions

**Proposed Solution**:
```python
import hashlib

def hash_identifier(identifier):
    """Create privacy-safe log identifier"""
    return hashlib.sha256(identifier.encode()).hexdigest()[:16]

# Privacy-safe logging
user_hash = hash_identifier(user_email)
logger.info(f"Login attempt for user_hash={user_hash}")
# NEVER log password
logger.info(f"Login successful for user_id={user.id}")  # Use ID, not email
```

### Exercise 4: Contact Selection (Not Harvesting)

**Current (Vulnerable)**:
```python
# Upload all contacts
contacts = get_all_contacts()  # ALL contacts!
upload_to_server(contacts)
```

**Your Task**: Implement privacy-respecting contact sharing

**Solution Checklist**:
- [ ] Use platform contact picker
- [ ] User selects specific contacts
- [ ] Don't upload to server
- [ ] Use platform share sheet
- [ ] Process locally only

**Proposed Solution**:
```python
# Use platform contact picker
def invite_friend():
    # Let user pick ONE contact
    contact = show_contact_picker()  # System UI, user selects
    
    if contact:
        # Use platform share sheet - data never leaves device
        share_invitation_via_platform(
            contact=contact,
            message="Check out this restaurant app!"
        )
        # NO server upload, NO storage
```

### Exercise 5: Implement Consent Management

**Your Task**: Design a granular consent system

**Requirements**:
- [ ] Separate consent for analytics, advertising, personalization
- [ ] Clear explanation of each data use
- [ ] Easy to revoke consent
- [ ] Delete data when consent revoked
- [ ] Implement GDPR data export
- [ ] Implement GDPR data deletion

**Proposed Solution**:
```python
class ConsentManager:
    CONSENT_TYPES = ['analytics', 'advertising', 'personalization']
    
    def request_consent(self, consent_type):
        """Show clear explanation and request consent"""
        explanation = {
            'analytics': 'Anonymous usage stats to improve the app. No personal info.',
            'advertising': 'Personalized ads. You can disable and still use the app.',
            'personalization': 'Customize content based on your preferences.'
        }
        
        user_choice = show_consent_dialog(
            title=consent_type.title(),
            message=explanation[consent_type],
            options=['Accept', 'Decline']
        )
        
        self.save_consent(consent_type, user_choice == 'Accept')
        return user_choice == 'Accept'
    
    def revoke_consent(self, consent_type):
        """Revoke consent and delete associated data"""
        self.save_consent(consent_type, False)
        self.delete_data_for_purpose(consent_type)
    
    def export_user_data(self):
        """GDPR Article 15: Right to access"""
        return {
            'profile': get_user_profile(),
            'consents': get_all_consents(),
            'analytics_events': get_analytics_data(),
            'export_date': datetime.now()
        }
    
    def delete_all_user_data(self):
        """GDPR Article 17: Right to erasure"""
        delete_user_profile()
        delete_analytics_data()
        delete_all_user_sessions()
        log_data_deletion_for_compliance()
```

---

## Phase 6: Compliance Validation

### Objective
Validate that privacy controls meet regulatory requirements.

### GDPR Compliance Checklist

**Data Protection Principles (Article 5)**:

- [ ] **Lawfulness**: Legal basis for processing (consent, contract, legitimate interest)
- [ ] **Purpose Limitation**: Data used only for stated purpose
- [ ] **Data Minimization**: Collect only necessary data
- [ ] **Accuracy**: Keep data accurate and up to date
- [ ] **Storage Limitation**: Delete data when no longer needed
- [ ] **Integrity and Confidentiality**: Secure data appropriately

**User Rights (Articles 15-22)**:

- [ ] **Right to Access** (Article 15): Users can export their data
- [ ] **Right to Rectification** (Article 16): Users can correct data
- [ ] **Right to Erasure** (Article 17): Users can delete their data
- [ ] **Right to Object** (Article 21): Users can opt out of processing

**Consent Requirements (Article 7)**:

- [ ] **Freely Given**: No forced consent, app works without all permissions
- [ ] **Specific**: Separate consent for each purpose
- [ ] **Informed**: Clear explanation of data use
- [ ] **Unambiguous**: Affirmative action required (opt-in, not opt-out)

### CCPA Compliance Checklist

**Consumer Rights**:

- [ ] **Right to Know**: Disclose what data is collected
- [ ] **Right to Delete**: Users can request deletion
- [ ] **Right to Opt-Out**: "Do Not Sell My Personal Information" option
- [ ] **Non-Discrimination**: Equal service whether or not user exercises rights

### Platform Compliance (iOS/Android)

**iOS App Store**:

- [ ] Privacy nutrition labels accurate
- [ ] Purpose strings clear and specific
- [ ] App Tracking Transparency prompt shown
- [ ] No circumventing permission system

**Google Play**:

- [ ] Data safety section accurate
- [ ] Privacy policy linked and accessible
- [ ] Prominent disclosure for background location
- [ ] No deceptive data collection

---

## Advanced Challenges

### Challenge 1: Differential Privacy

Implement differential privacy for analytics to collect aggregate data without exposing individuals.

**Task**: Modify analytics to add mathematical noise
```python
def track_with_differential_privacy(metric, value):
    # Add Laplace noise to preserve privacy
    epsilon = 1.0  # Privacy budget
    noise = laplace(0, 1/epsilon)
    noisy_value = value + noise
    
    send_to_analytics(metric, noisy_value)
    # Individual values protected, aggregates accurate
```

### Challenge 2: On-Device Processing

Move sensitive data processing from server to device.

**Task**: Implement local ML instead of server-side processing
```python
# Instead of:
def analyze_user_behavior():
    user_data = collect_all_user_actions()
    send_to_server(user_data)  # Privacy risk!
    
# Use on-device processing:
def analyze_user_behavior_locally():
    user_data = get_local_data()
    local_model = load_ml_model()  # TensorFlow Lite, Core ML
    insights = local_model.predict(user_data)
    # Data never leaves device!
```

### Challenge 3: Privacy Budget

Implement a "privacy budget" system that limits data collection.

**Task**: Track and limit data collection per user
```python
class PrivacyBudget:
    def __init__(self, user_id):
        self.user_id = user_id
        self.budget = 100  # Privacy units
    
    def request_data_collection(self, data_type, cost):
        if self.budget >= cost:
            self.budget -= cost
            return True  # Allow collection
        else:
            return False  # Deny - privacy budget exhausted
```

---

## Reflection Questions

After completing the lab, consider:

1. **Business vs. Privacy**: How do you balance product features with user privacy?
2. **Default Settings**: Should privacy protections be opt-in or opt-out?
3. **Transparency**: How much detail should users receive about data collection?
4. **Enforcement**: Who ensures apps comply with privacy regulations?
5. **Future of Privacy**: What emerging technologies enable better privacy?

---

## Key Takeaways

1. **Permission Minimalism**: Request only necessary permissions, contextually
2. **Data Minimization**: Collect only what you absolutely need
3. **User Control**: Give users meaningful privacy choices
4. **Transparency**: Be honest about data collection and use
5. **Privacy by Design**: Build privacy into products from the start
6. **Regulatory Compliance**: GDPR, CCPA, and platform policies are not optional
7. **Ethical Imperative**: Privacy is a fundamental human right

---

## Next Steps

1. **Review Prevention Guide**: See [prevention.md](../../prevention.md) for implementation patterns
2. **Study Real Cases**: Research privacy violations by major apps
3. **Practice Privacy Audits**: Analyze apps you use daily
4. **Implement Privacy Controls**: Apply learnings to your projects
5. **Stay Updated**: Follow platform privacy guideline changes

---

## Additional Resources

- **GDPR Text**: https://gdpr-info.eu/
- **CCPA Guide**: https://oag.ca.gov/privacy/ccpa
- **Apple Privacy**: https://developer.apple.com/privacy/
- **Android Privacy**: https://developer.android.com/privacy/best-practices
- **OWASP Mobile**: https://owasp.org/www-project-mobile-security-testing-guide/

---

**Congratulations!** You've completed the Inadequate Privacy Controls lab. You now understand how to identify privacy violations and implement privacy-respecting mobile applications.

**Remember**: Users trust you with their most personal data. Honor that trust with privacy-first design.
