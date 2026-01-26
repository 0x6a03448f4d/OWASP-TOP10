# M06: Inadequate Privacy Controls - Code Examples

## Table of Contents
1. [Introduction](#introduction)
2. [Vulnerable Examples](#vulnerable-examples)
3. [Secure Examples](#secure-examples)
4. [Common Patterns](#common-patterns)
5. [Framework-Specific Examples](#framework-specific-examples)
6. [Comparison Tables](#comparison-tables)

---

## Introduction

This document provides practical code examples demonstrating inadequate privacy controls and their secure alternatives. All examples are production-ready and follow platform best practices for iOS (Swift) and Android (Kotlin/Java).

**Learning Objectives**:
- Recognize privacy anti-patterns in code
- Implement privacy-by-design alternatives
- Use platform privacy APIs correctly
- Handle permissions responsibly
- Implement user consent mechanisms

**Disclaimer**: Vulnerable examples are marked with ✗ and should NEVER be used in production applications.

---

## Vulnerable Examples

### Example 1: Excessive Permission Requests (Android)

**✗ VULNERABLE**: Requesting all permissions at app startup

```kotlin
// ❌ DON'T DO THIS - Privacy Violation
class SplashActivity : AppCompatActivity() {
    
    private val REQUIRED_PERMISSIONS = arrayOf(
        Manifest.permission.CAMERA,
        Manifest.permission.RECORD_AUDIO,
        Manifest.permission.ACCESS_FINE_LOCATION,
        Manifest.permission.ACCESS_BACKGROUND_LOCATION,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.WRITE_CONTACTS,
        Manifest.permission.READ_CALENDAR,
        Manifest.permission.WRITE_CALENDAR,
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.READ_SMS,
        Manifest.permission.SEND_SMS,
        Manifest.permission.READ_EXTERNAL_STORAGE,
        Manifest.permission.WRITE_EXTERNAL_STORAGE,
        Manifest.permission.BODY_SENSORS,
        Manifest.permission.ACCESS_COARSE_LOCATION
    )
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)
        
        // Request everything immediately - Privacy Violation!
        if (!hasAllPermissions()) {
            ActivityCompat.requestPermissions(
                this,
                REQUIRED_PERMISSIONS,
                REQUEST_CODE_ALL_PERMISSIONS
            )
        } else {
            proceedToMainActivity()
        }
    }
    
    private fun hasAllPermissions(): Boolean {
        return REQUIRED_PERMISSIONS.all {
            ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
        }
    }
    
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        
        // Block app if not all permissions granted - Forced Consent!
        if (grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
            proceedToMainActivity()
        } else {
            Toast.makeText(this, "App requires all permissions to function", Toast.LENGTH_LONG).show()
            finish() // Close app - Privacy & UX violation!
        }
    }
}
```

**Why This is Vulnerable**:
- ❌ Requests 14+ permissions simultaneously (overwhelming users)
- ❌ Requests at app launch (no context for why needed)
- ❌ Forces users to grant all permissions (coercion)
- ❌ Blocks app functionality if denied (forced consent)
- ❌ No explanation for each permission
- ❌ Requests background location without justification
- ❌ Many permissions likely unnecessary for core functionality

---

### Example 2: Background Location Tracking (iOS)

**✗ VULNERABLE**: Continuous background location tracking

```swift
// ❌ DON'T DO THIS - Privacy Violation
import CoreLocation

class LocationTracker: NSObject, CLLocationManagerDelegate {
    
    let locationManager = CLLocationManager()
    var locationHistory: [CLLocation] = []
    
    override init() {
        super.init()
        setupLocationTracking()
    }
    
    func setupLocationTracking() {
        locationManager.delegate = self
        
        // Request "Always" permission immediately - Privacy Violation!
        locationManager.requestAlwaysAuthorization()
        
        // Aggressive tracking settings
        locationManager.desiredAccuracy = kCLLocationAccuracyBest // Highest precision
        locationManager.distanceFilter = 10 // Update every 10 meters
        locationManager.allowsBackgroundLocationUpdates = true // Background tracking
        locationManager.pausesLocationUpdatesAutomatically = false // Never pause
        locationManager.showsBackgroundLocationIndicator = false // Try to hide indicator
        
        // Start tracking immediately
        locationManager.startUpdatingLocation()
        locationManager.startMonitoringSignificantLocationChanges()
    }
    
    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        for location in locations {
            // Store all locations - Privacy Violation!
            locationHistory.append(location)
            
            // Send to server immediately - even in background!
            sendLocationToServer(location)
        }
    }
    
    func sendLocationToServer(_ location: CLLocation) {
        let payload: [String: Any] = [
            "user_id": UserSession.shared.userId,
            "latitude": location.coordinate.latitude,
            "longitude": location.coordinate.longitude,
            "altitude": location.altitude,
            "speed": location.speed,
            "course": location.course,
            "accuracy": location.horizontalAccuracy,
            "timestamp": location.timestamp.timeIntervalSince1970,
            "app_state": UIApplication.shared.applicationState.rawValue,
            "battery_level": UIDevice.current.batteryLevel
        ]
        
        // Send even if app is in background
        API.post("/tracking/location", json: payload)
    }
    
    // Persist tracking across app restarts
    func applicationDidFinishLaunching() {
        setupLocationTracking() // Restart tracking
    }
}
```

**Why This is Vulnerable**:
- ❌ Requests "Always" permission (most invasive)
- ❌ No explanation why background tracking needed
- ❌ Tracks with highest precision (not necessary for most use cases)
- ❌ Updates every 10 meters (excessive frequency)
- ❌ Never pauses (continuous battery drain + privacy invasion)
- ❌ Tries to hide background indicator (deceptive)
- ❌ Stores complete location history
- ❌ Sends to server even in background
- ❌ No user control to disable tracking

---

### Example 3: Contact Harvesting (Android)

**✗ VULNERABLE**: Uploading entire contact list without disclosure

```java
// ❌ DON'T DO THIS - Privacy Violation
public class ContactSyncService extends IntentService {
    
    public ContactSyncService() {
        super("ContactSyncService");
    }
    
    @Override
    protected void onHandleIntent(Intent intent) {
        // Silently upload all contacts - Privacy Violation!
        uploadAllContacts();
    }
    
    private void uploadAllContacts() {
        List<ContactData> contacts = new ArrayList<>();
        
        // Query ALL contacts - Privacy Violation!
        Cursor cursor = getContentResolver().query(
            ContactsContract.Contacts.CONTENT_URI,
            null, null, null, null
        );
        
        if (cursor != null && cursor.getCount() > 0) {
            while (cursor.moveToNext()) {
                String contactId = cursor.getString(
                    cursor.getColumnIndex(ContactsContract.Contacts._ID)
                );
                String name = cursor.getString(
                    cursor.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME)
                );
                
                // Extract all phone numbers
                List<String> phoneNumbers = getPhoneNumbers(contactId);
                
                // Extract all emails
                List<String> emails = getEmails(contactId);
                
                // Extract postal addresses
                List<String> addresses = getPostalAddresses(contactId);
                
                // Extract organizations
                String company = getOrganization(contactId);
                
                // Extract birthday
                String birthday = getBirthday(contactId);
                
                // Extract notes
                String notes = getNotes(contactId);
                
                // Extract social profiles
                List<String> socialProfiles = getSocialProfiles(contactId);
                
                // Create contact object with EVERYTHING
                ContactData contact = new ContactData(
                    name, phoneNumbers, emails, addresses,
                    company, birthday, notes, socialProfiles
                );
                
                contacts.add(contact);
            }
            cursor.close();
        }
        
        // Upload to server - Privacy Violation!
        uploadToServer(contacts);
        
        // Also sell to third-party data brokers - Severe Privacy Violation!
        sellToDataBrokers(contacts);
    }
    
    private void uploadToServer(List<ContactData> contacts) {
        JSONArray jsonArray = new JSONArray();
        
        for (ContactData contact : contacts) {
            try {
                JSONObject json = new JSONObject();
                json.put("name", contact.name);
                json.put("phones", new JSONArray(contact.phoneNumbers));
                json.put("emails", new JSONArray(contact.emails));
                json.put("addresses", new JSONArray(contact.addresses));
                json.put("company", contact.company);
                json.put("birthday", contact.birthday);
                json.put("notes", contact.notes);
                json.put("social_profiles", new JSONArray(contact.socialProfiles));
                jsonArray.put(json);
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        
        // Send entire contact list
        RequestBody body = RequestBody.create(
            MediaType.parse("application/json"),
            jsonArray.toString()
        );
        
        Request request = new Request.Builder()
            .url("https://api.example.com/contacts/bulk-upload")
            .post(body)
            .build();
        
        try {
            Response response = httpClient.newCall(request).execute();
            Log.d("ContactSync", "Uploaded " + contacts.size() + " contacts");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private void sellToDataBrokers(List<ContactData> contacts) {
        // Privacy Violation: Selling user's contact data
        // to third-party data brokers
        String[] brokers = {
            "https://databroker1.com/api/ingest",
            "https://databroker2.com/api/buy",
            "https://advertiser-data.com/upload"
        };
        
        for (String broker : brokers) {
            // Send contacts to each broker
            // ...
        }
    }
}
```

**Why This is Vulnerable**:
- ❌ Harvests ALL contacts (not just ones user wants to share)
- ❌ Collects excessive data (addresses, birthdays, notes, social profiles)
- ❌ Uploads contacts of non-users (they never consented!)
- ❌ Runs as background service (user unaware)
- ❌ No disclosure that contacts are uploaded
- ❌ Sells to third-party data brokers
- ❌ Permanent storage of contacts
- ❌ No way for contact owners to delete their data
- ❌ Violates GDPR, CCPA, and ethical standards

---

### Example 4: PII in Logs (Kotlin)

**✗ VULNERABLE**: Logging personally identifiable information

```kotlin
// ❌ DON'T DO THIS - Privacy Violation
class UserAuthenticationService {
    
    fun login(email: String, password: String): LoginResult {
        // PII LEAKAGE: Email in logs
        Log.d("Auth", "Login attempt for email: $email")
        
        // CRITICAL VULNERABILITY: Password in logs!
        Log.d("Auth", "Password submitted: $password")
        
        val user = userRepository.findByEmail(email)
        
        if (user != null) {
            // PII LEAKAGE: Entire user object (contains PII)
            Log.d("Auth", "User found: $user")
            // user.toString() might contain: name, email, address, phone, SSN, etc.
            
            if (verifyPassword(password, user.passwordHash)) {
                val token = generateAuthToken(user)
                
                // PII LEAKAGE: Session token in logs
                Log.d("Auth", "Login successful. Token: $token")
                
                // PII LEAKAGE: User details in analytics
                Analytics.track("user_login", mapOf(
                    "user_id" to user.id,
                    "email" to user.email,              // PII!
                    "name" to user.fullName,            // PII!
                    "phone" to user.phoneNumber,        // PII!
                    "address" to user.address,          // PII!
                    "ip_address" to getClientIp(),      // PII!
                    "device_id" to getDeviceId()        // PII!
                ))
                
                return LoginResult.Success(user, token)
            } else {
                // PII LEAKAGE: Failed attempts reveal valid emails
                Log.w("Auth", "Invalid password for user: $email")
                return LoginResult.InvalidCredentials
            }
        }
        
        return LoginResult.UserNotFound
    }
    
    fun updateUserProfile(userId: String, profileData: ProfileUpdateRequest) {
        // PII LEAKAGE: Complete profile data in logs
        Log.d("Profile", "Updating user $userId with data: ${profileData.toJson()}")
        // profileData contains: name, address, phone, DOB, SSN, etc.
        
        val user = userRepository.findById(userId)
        
        // PII LEAKAGE: Before and after states
        Log.d("Profile", "Old profile: $user")
        
        user.apply {
            name = profileData.name
            address = profileData.address
            phoneNumber = profileData.phoneNumber
            dateOfBirth = profileData.dateOfBirth
            socialSecurityNumber = profileData.ssn // Should NEVER be logged!
        }
        
        userRepository.save(user)
        
        // PII LEAKAGE: Updated profile
        Log.d("Profile", "New profile: $user")
    }
    
    fun processPayment(cardNumber: String, cvv: String, amount: Double) {
        // CRITICAL PII LEAKAGE: Credit card details in logs!
        Log.d("Payment", "Processing payment of $$amount")
        Log.d("Payment", "Card number: $cardNumber") // NEVER LOG!
        Log.d("Payment", "CVV: $cvv") // NEVER LOG!
        
        try {
            paymentGateway.charge(cardNumber, cvv, amount)
            Log.d("Payment", "Payment successful for card ending in ${cardNumber.takeLast(4)}")
        } catch (e: Exception) {
            // PII LEAKAGE: Exception might contain card details in stack trace
            Log.e("Payment", "Payment failed", e)
        }
    }
}
```

**Why This is Vulnerable**:
- ❌ Logs email addresses (PII)
- ❌ Logs passwords in plaintext (CRITICAL security + privacy violation)
- ❌ Logs complete user objects (exposes all PII)
- ❌ Logs session tokens (security risk)
- ❌ Sends PII to analytics
- ❌ Logs credit card numbers and CVV (PCI-DSS violation + privacy violation)
- ❌ Logs before/after states (doubles PII exposure)
- ❌ Exception stack traces may contain sensitive data
- ❌ Logs are often sent to third-party services (Crashlytics, Datadog, etc.)

---

### Example 5: Clipboard Snooping (Swift)

**✗ VULNERABLE**: Reading clipboard without user awareness

```swift
// ❌ DON'T DO THIS - Privacy Violation
class ClipboardMonitor {
    
    private var timer: Timer?
    private var lastChangeCount: Int = 0
    private var collectedClipboardData: [(content: String, timestamp: Date)] = []
    
    func startMonitoring() {
        // Check clipboard every 500ms - Privacy Violation!
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.checkClipboard()
        }
    }
    
    private func checkClipboard() {
        let pasteboard = UIPasteboard.general
        
        // Detect if clipboard changed
        if pasteboard.changeCount != lastChangeCount {
            lastChangeCount = pasteboard.changeCount
            
            // Read clipboard content - Privacy Violation!
            if let string = pasteboard.string {
                processClipboardContent(string)
            }
            
            // Also read URLs
            if let url = pasteboard.url {
                processClipboardURL(url)
            }
            
            // Also read images
            if let image = pasteboard.image {
                processClipboardImage(image)
            }
        }
    }
    
    private func processClipboardContent(_ content: String) {
        // Store clipboard history - Privacy Violation!
        collectedClipboardData.append((content: content, timestamp: Date()))
        
        // Analyze content type
        let contentType = analyzeContentType(content)
        
        // Send to analytics - Privacy Violation!
        Analytics.track("clipboard_access", properties: [
            "content_type": contentType,
            "content_length": content.count,
            "content": content, // FULL CLIPBOARD CONTENT!
            "timestamp": Date().timeIntervalSince1970
        ])
        
        // If sensitive data detected, send to special endpoint
        if isSensitiveData(content) {
            sendSensitiveDataToServer(content, type: contentType)
        }
    }
    
    private func analyzeContentType(_ content: String) -> String {
        if isPassword(content) { return "password" }
        if isCreditCard(content) { return "credit_card" }
        if isEmail(content) { return "email" }
        if isPhoneNumber(content) { return "phone_number" }
        if isCryptoAddress(content) { return "crypto_wallet" }
        if isURL(content) { return "url" }
        return "unknown"
    }
    
    private func isSensitiveData(_ content: String) -> Bool {
        return isPassword(content) || 
               isCreditCard(content) || 
               isCryptoAddress(content)
    }
    
    private func sendSensitiveDataToServer(_ content: String, type: String) {
        // Exfiltrate sensitive clipboard data - Privacy Violation!
        let payload: [String: Any] = [
            "user_id": currentUserId,
            "content": content,
            "type": type,
            "timestamp": Date().timeIntervalSince1970,
            "source_app": getPreviousApp() // If detectable
        ]
        
        API.post("/clipboard/sensitive", json: payload)
    }
    
    // Start monitoring when app becomes active
    func applicationDidBecomeActive() {
        startMonitoring()
    }
}
```

**Why This is Vulnerable**:
- ❌ Polls clipboard continuously (every 500ms)
- ❌ Reads clipboard without user action
- ❌ Collects passwords, credit cards, crypto wallets
- ❌ Stores clipboard history
- ❌ Sends full clipboard content to analytics
- ❌ Sends sensitive data to server
- ❌ No user awareness or consent
- ❌ Violates user trust and platform policies
- ❌ (iOS 14+) Triggers paste notification repeatedly

---

## Secure Examples

### Example 1: Contextual Permission Requests (Android)

**✓ SECURE**: Request permissions only when needed with clear explanation

```kotlin
// ✅ SECURE APPROACH
class RestaurantMapActivity : AppCompatActivity() {
    
    private val locationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        when {
            permissions[Manifest.permission.ACCESS_COARSE_LOCATION] == true -> {
                // Coarse location granted - sufficient!
                loadNearbyRestaurants()
            }
            else -> {
                // Permission denied - provide alternative
                showManualLocationEntry()
            }
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_restaurant_map)
        
        // DON'T request permissions here!
        // Wait for user to trigger location-based feature
    }
    
    // Only request when user wants to find nearby restaurants
    fun onFindNearbyClicked() {
        when {
            // Already have permission
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.ACCESS_COARSE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED -> {
                loadNearbyRestaurants()
            }
            
            // Should show rationale
            shouldShowRequestPermissionRationale(
                Manifest.permission.ACCESS_COARSE_LOCATION
            ) -> {
                showLocationPermissionRationale()
            }
            
            // First time asking
            else -> {
                requestLocationPermission()
            }
        }
    }
    
    private fun showLocationPermissionRationale() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Location Permission")
            .setMessage(
                "To show nearby restaurants, we need your approximate location.\n\n" +
                "✓ Only used when you search for restaurants\n" +
                "✓ Never tracked in the background\n" +
                "✓ Not shared with third parties\n" +
                "✓ You can revoke this permission anytime in Settings"
            )
            .setPositiveButton("Grant Permission") { _, _ ->
                requestLocationPermission()
            }
            .setNegativeButton("Not Now") { _, _ ->
                showManualLocationEntry()
            }
            .show()
    }
    
    private fun requestLocationPermission() {
        // Request ONLY coarse location (more privacy-friendly)
        locationPermissionLauncher.launch(
            arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION)
        )
    }
    
    private fun showManualLocationEntry() {
        // Provide alternative if permission denied
        MaterialAlertDialogBuilder(this)
            .setTitle("Enter Location")
            .setMessage("Enter your city or ZIP code to find restaurants")
            .setView(R.layout.manual_location_entry)
            .setPositiveButton("Search") { dialog, _ ->
                val view = (dialog as AlertDialog).findViewById<EditText>(R.id.location_input)
                val location = view?.text.toString()
                searchByManualLocation(location)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}
```

**Why This is Secure**:
- ✅ Requests permission only when user triggers location feature
- ✅ Shows clear explanation before requesting
- ✅ Requests only coarse location (not fine)
- ✅ Lists specific privacy protections
- ✅ Provides alternative functionality if denied
- ✅ No forced consent
- ✅ Respects user's "don't ask again" choice

---

### Example 2: Privacy-Friendly Location (iOS)

**✓ SECURE**: Request minimal location access with transparency

```swift
// ✅ SECURE APPROACH
import CoreLocation

class WeatherViewController: UIViewController, CLLocationManagerDelegate {
    
    let locationManager = CLLocationManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        locationManager.delegate = self
        
        // DON'T request location here!
        // Wait for user to trigger feature
    }
    
    // Only request when user wants weather for current location
    @IBAction func getCurrentLocationWeatherTapped() {
        let status = locationManager.authorizationStatus
        
        switch status {
        case .notDetermined:
            // First time - show explanation then request
            showLocationPermissionExplanation()
            
        case .denied, .restricted:
            // Permission denied - show settings prompt
            showLocationDeniedAlert()
            
        case .authorizedWhenInUse, .authorizedAlways:
            // Permission granted - fetch weather
            requestCurrentLocationWeather()
            
        @unknown default:
            break
        }
    }
    
    private func showLocationPermissionExplanation() {
        let alert = UIAlertController(
            title: "Location for Weather",
            message: """
            We need your location to show accurate weather for your area.
            
            ✓ Only used when you request current location weather
            ✓ Never tracked in the background
            ✓ Approximate location is sufficient
            ✓ Not stored or shared
            
            You can choose "Precise: Off" for extra privacy.
            """,
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
            // Request ONLY "When In Use" - NEVER "Always"
            self.locationManager.requestWhenInUseAuthorization()
        })
        
        alert.addAction(UIAlertAction(title: "Manual Location", style: .cancel) { _ in
            self.showManualLocationPicker()
        })
        
        present(alert, animated: true)
    }
    
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        
        if status == .authorizedWhenInUse || status == .authorizedAlways {
            // Check if user chose approximate location
            if manager.accuracyAuthorization == .reducedAccuracy {
                print("✓ User chose approximate location (more private)")
            } else {
                print("User chose precise location")
            }
            
            requestCurrentLocationWeather()
        }
    }
    
    private func requestCurrentLocationWeather() {
        // Configure for minimal privacy impact
        locationManager.desiredAccuracy = kCLLocationAccuracyKilometer // Approximate OK
        locationManager.requestLocation() // One-time request
    }
    
    func locationManager(_ manager: CLLocationManager, 
                        didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.first else { return }
        
        // Use location immediately, don't store
        fetchWeather(latitude: location.coordinate.latitude,
                    longitude: location.coordinate.longitude) { weather in
            self.displayWeather(weather)
        }
        
        // ✅ DON'T store location history
        // ✅ Use and discard
    }
    
    func locationManager(_ manager: CLLocationManager, 
                        didFailWithError error: Error) {
        // Provide fallback
        showManualLocationPicker()
    }
    
    private func showLocationDeniedAlert() {
        let alert = UIAlertController(
            title: "Location Access Disabled",
            message: "To get weather for your current location, please enable location access in Settings.",
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(title: "Open Settings", style: .default) { _ in
            if let settingsUrl = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(settingsUrl)
            }
        })
        
        alert.addAction(UIAlertAction(title: "Enter City Manually", style: .cancel) { _ in
            self.showManualLocationPicker()
        })
        
        present(alert, animated: true)
    }
}
```

**Why This is Secure**:
- ✅ Requests "When In Use" only (never "Always")
- ✅ Shows detailed explanation before requesting
- ✅ Uses approximate accuracy (kCLLocationAccuracyKilometer)
- ✅ Supports iOS 14+ approximate location choice
- ✅ One-time location request (not continuous tracking)
- ✅ Doesn't store location history
- ✅ Provides alternative manual entry
- ✅ Respects user's denial gracefully

---

### Example 3: Privacy-Safe Contact Selection (Android)

**✓ SECURE**: Let user select specific contacts instead of harvesting all

```kotlin
// ✅ SECURE APPROACH
class InviteFriendsActivity : AppCompatActivity() {
    
    private val contactPickerLauncher = registerForActivityResult(
        ActivityResultContracts.PickContact()
    ) { contactUri ->
        contactUri?.let { handleSelectedContact(it) }
    }
    
    fun onInviteFriendClicked() {
        // ✅ Use contact picker - no READ_CONTACTS permission needed!
        contactPickerLauncher.launch(null)
    }
    
    private fun handleSelectedContact(contactUri: Uri) {
        // User selected ONE contact - respect that
        val contact = getContactDetails(contactUri)
        
        contact?.let {
            // Only process the ONE contact user chose
            sendInvitation(it)
            
            // ✅ DON'T upload to server
            // ✅ DON'T store permanently
            // ✅ Use only for immediate purpose (sending invite)
        }
    }
    
    private fun getContactDetails(uri: Uri): Contact? {
        val cursor = contentResolver.query(uri, null, null, null, null)
        
        cursor?.use {
            if (it.moveToFirst()) {
                val name = it.getString(it.getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME))
                
                // Get phone number (if available)
                val contactId = it.getString(it.getColumnIndex(ContactsContract.Contacts._ID))
                val phoneNumber = getPhoneNumber(contactId)
                
                // Get email (if available)
                val email = getEmail(contactId)
                
                return Contact(name, phoneNumber, email)
            }
        }
        
        return null
    }
    
    private fun sendInvitation(contact: Contact) {
        // ✅ Use platform share mechanism instead of server upload
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, "Check out this restaurant app!")
            
            // If SMS available
            contact.phoneNumber?.let {
                putExtra("address", it)
            }
        }
        
        // Let user choose how to send (SMS, email, WhatsApp, etc.)
        startActivity(Intent.createChooser(shareIntent, "Invite ${contact.name}"))
        
        // ✅ Contact data never leaves device
        // ✅ User in control of invitation method
        // ✅ No server-side contact storage
    }
}

data class Contact(
    val name: String,
    val phoneNumber: String?,
    val email: String?
)
```

**Why This is Secure**:
- ✅ Uses contact picker (no READ_CONTACTS permission required)
- ✅ User selects specific contact (not entire contact list)
- ✅ Uses platform share sheet for invitation
- ✅ Contact data never uploaded to server
- ✅ No permanent storage of contact information
- ✅ User controls invitation method
- ✅ Respects contact owner's privacy (they're not in database)

---

### Example 4: Privacy-Safe Logging (Kotlin)

**✓ SECURE**: Log events without PII

```kotlin
// ✅ SECURE APPROACH
class SecureUserAuthenticationService {
    
    private val logger = PrivacyAwareLogger(this::class.java)
    
    fun login(email: String, password: String): LoginResult {
        // ✅ Log event without PII
        logger.info("Login attempt initiated")
        
        // ✅ If identifier needed, use hashed version
        val userIdHash = hashIdentifier(email)
        logger.info("Login attempt for user_hash=$userIdHash")
        
        // ✅ NEVER log password
        // logger.debug("Password: $password") // NO!
        
        val user = userRepository.findByEmail(email)
        
        if (user != null) {
            // ✅ Log with user ID, not email
            logger.info("User ${user.id} authentication in progress")
            
            if (verifyPassword(password, user.passwordHash)) {
                val token = generateAuthToken(user)
                
                // ✅ Log success without sensitive data
                logger.info("User ${user.id} logged in successfully")
                
                // ✅ Send minimal analytics
                secureAnalytics.track("user_login", mapOf(
                    "user_id" to user.id, // Internal ID only
                    "method" to "email",  // Method, not actual email
                    "timestamp" to System.currentTimeMillis()
                    // ✅ No PII: email, name, phone, address, etc.
                ))
                
                return LoginResult.Success(user, token)
            } else {
                // ✅ Don't reveal whether email is valid
                logger.warn("Authentication failed for user_hash=$userIdHash")
                return LoginResult.InvalidCredentials
            }
        }
        
        logger.warn("Authentication failed for user_hash=$userIdHash")
        return LoginResult.InvalidCredentials // Same response as wrong password
    }
    
    private fun hashIdentifier(identifier: String): String {
        // One-way hash for privacy-safe logging
        return MessageDigest.getInstance("SHA-256")
            .digest(identifier.toByteArray())
            .joinToString("") { "%02x".format(it) }
            .take(16) // First 16 characters
    }
}

// Custom logger that automatically redacts PII
class PrivacyAwareLogger(private val clazz: Class<*>) {
    
    private val logger = LoggerFactory.getLogger(clazz)
    
    fun info(message: String) {
        logger.info(sanitize(message))
    }
    
    fun warn(message: String) {
        logger.warn(sanitize(message))
    }
    
    fun error(message: String, throwable: Throwable? = null) {
        logger.error(sanitize(message), sanitizeException(throwable))
    }
    
    private fun sanitize(message: String): String {
        var sanitized = message
        
        // Redact email addresses
        sanitized = sanitized.replace(
            Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
            "[EMAIL_REDACTED]"
        )
        
        // Redact phone numbers
        sanitized = sanitized.replace(
            Regex("\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b"),
            "[PHONE_REDACTED]"
        )
        
        // Redact credit card numbers
        sanitized = sanitized.replace(
            Regex("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"),
            "[CARD_REDACTED]"
        )
        
        // Redact SSN
        sanitized = sanitized.replace(
            Regex("\\b\\d{3}-\\d{2}-\\d{4}\\b"),
            "[SSN_REDACTED]"
        )
        
        // Redact IP addresses
        sanitized = sanitized.replace(
            Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"),
            "[IP_REDACTED]"
        )
        
        return sanitized
    }
    
    private fun sanitizeException(throwable: Throwable?): Throwable? {
        // In production, consider filtering stack trace
        // or using a custom exception type without sensitive data
        return throwable
    }
}
```

**Why This is Secure**:
- ✅ Logs events without PII
- ✅ Uses hashed identifiers if needed
- ✅ Never logs passwords, tokens, or sensitive data
- ✅ Auto-redacts PII patterns (email, phone, credit cards)
- ✅ Analytics contain minimal data
- ✅ Uses internal IDs, not user-facing identifiers
- ✅ Doesn't reveal valid/invalid emails (prevents enumeration)

---

### Example 5: Consent Management (Swift)

**✓ SECURE**: Granular user consent with transparency

```swift
// ✅ SECURE APPROACH
class ConsentManager {
    
    enum ConsentType: String, CaseIterable {
        case analytics
        case advertising
        case crashReporting
        case personalizedContent
        
        var title: String {
            switch self {
            case .analytics: return "Analytics"
            case .advertising: return "Personalized Advertising"
            case .crashReporting: return "Crash Reporting"
            case .personalizedContent: return "Personalized Content"
            }
        }
        
        var description: String {
            switch self {
            case .analytics:
                return "Help us improve the app by sending anonymous usage statistics. No personal information is collected."
            case .advertising:
                return "Show ads tailored to your interests. You'll still see ads if disabled, but they won't be personalized."
            case .crashReporting:
                return "Automatically send crash reports to help us fix bugs. Reports don't contain personal information."
            case .personalizedContent:
                return "Customize app content based on your preferences and usage patterns."
            }
        }
    }
    
    private let defaults = UserDefaults.standard
    
    func showConsentDialog(from viewController: UIViewController) {
        let alert = UIAlertController(
            title: "Your Privacy Choices",
            message: "Choose which features you'd like to enable. You can change these anytime in Settings.",
            preferredStyle: .alert
        )
        
        // Create custom view with switches
        let consentView = createConsentView()
        alert.view.addSubview(consentView)
        
        // Constrain view
        consentView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            consentView.topAnchor.constraint(equalTo: alert.view.topAnchor, constant: 80),
            consentView.leadingAnchor.constraint(equalTo: alert.view.leadingAnchor, constant: 20),
            consentView.trailingAnchor.constraint(equalTo: alert.view.trailingAnchor, constant: -20)
        ])
        
        alert.addAction(UIAlertAction(title: "Save", style: .default) { _ in
            self.saveConsents(from: consentView)
        })
        
        alert.addAction(UIAlertAction(title: "Privacy Policy", style: .default) { _ in
            self.openPrivacyPolicy()
            // Show dialog again after reading policy
            self.showConsentDialog(from: viewController)
        })
        
        viewController.present(alert, animated: true)
    }
    
    func hasConsent(for type: ConsentType) -> Bool {
        return defaults.bool(forKey: "consent_\(type.rawValue)")
    }
    
    func grantConsent(for type: ConsentType) {
        defaults.set(true, forKey: "consent_\(type.rawValue)")
        defaults.set(Date(), forKey: "consent_\(type.rawValue)_timestamp")
        applyConsent(for: type, granted: true)
    }
    
    func revokeConsent(for type: ConsentType) {
        defaults.set(false, forKey: "consent_\(type.rawValue)")
        defaults.set(Date(), forKey: "consent_\(type.rawValue)_revoked_timestamp")
        applyConsent(for: type, granted: false)
    }
    
    func revokeAllConsents() {
        for type in ConsentType.allCases {
            revokeConsent(for: type)
        }
        
        // Delete all collected data
        deleteAllUserData()
    }
    
    private func applyConsent(for type: ConsentType, granted: Bool) {
        switch type {
        case .analytics:
            Analytics.setEnabled(granted)
            if !granted {
                Analytics.deleteAllData()
            }
            
        case .advertising:
            AdService.setPersonalizationEnabled(granted)
            if !granted {
                AdService.resetAdvertisingId()
            }
            
        case .crashReporting:
            Crashlytics.setCrashlyticsCollectionEnabled(granted)
            
        case .personalizedContent:
            PersonalizationEngine.setEnabled(granted)
            if !granted {
                PersonalizationEngine.clearUserProfile()
            }
        }
    }
    
    private func deleteAllUserData() {
        Analytics.deleteAllData()
        AdService.resetAdvertisingId()
        PersonalizationEngine.clearUserProfile()
        
        // Log deletion for compliance
        print("✓ All user data deleted per user request")
    }
    
    // ✅ GDPR Right to Access
    func exportUserData() -> URL? {
        let userData: [String: Any] = [
            "consent_preferences": getUserConsents(),
            "analytics_events": Analytics.exportEvents(),
            "personalization_data": PersonalizationEngine.exportProfile(),
            "export_timestamp": Date().ISO8601Format()
        ]
        
        // Create JSON file
        guard let jsonData = try? JSONSerialization.data(withJSONObject: userData, options: .prettyPrinted) else {
            return nil
        }
        
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("my_data_export.json")
        
        try? jsonData.write(to: fileURL)
        
        return fileURL
    }
    
    private func getUserConsents() -> [String: Any] {
        var consents: [String: Any] = [:]
        
        for type in ConsentType.allCases {
            consents[type.rawValue] = [
                "granted": hasConsent(for: type),
                "timestamp": defaults.object(forKey: "consent_\(type.rawValue)_timestamp") as? Date
            ]
        }
        
        return consents
    }
}
```

**Why This is Secure**:
- ✅ Granular consent (not all-or-nothing)
- ✅ Clear explanation for each consent type
- ✅ Easy to revoke consent
- ✅ Immediately applies consent changes
- ✅ Deletes data when consent revoked
- ✅ Implements GDPR right to access (data export)
- ✅ Implements GDPR right to erasure (data deletion)
- ✅ Links to privacy policy
- ✅ User-friendly interface

---

## Common Patterns

### Pattern 1: Permission Request Timing

| ❌ Anti-Pattern | ✅ Best Practice |
|----------------|------------------|
| Request at app launch | Request when feature is triggered |
| Bundle multiple permissions | Request one permission at a time |
| No explanation | Show clear rationale before requesting |
| Block app if denied | Provide alternative functionality |

### Pattern 2: Location Precision

| ❌ Anti-Pattern | ✅ Best Practice |
|----------------|------------------|
| Always request FINE location | Use COARSE when sufficient |
| Request ALWAYS permission | Use WHEN_IN_USE only |
| Continuous tracking | One-time location request |
| Store location history | Use and discard |

### Pattern 3: Data Collection

| ❌ Anti-Pattern | ✅ Best Practice |
|----------------|------------------|
| Collect all contacts | Use contact picker (one at a time) |
| Upload to server | Process locally |
| Permanent storage | Temporary/session storage |
| Share with third parties | Keep data on-device |

### Pattern 4: Logging

| ❌ Anti-Pattern | ✅ Best Practice |
|----------------|------------------|
| Log email addresses | Log hashed identifiers |
| Log passwords | Never log credentials |
| Log full user objects | Log user IDs only |
| Log credit card numbers | Never log payment details |

---

## Framework-Specific Examples

### Android: Photo Picker (Android 13+)

```kotlin
// ✅ Modern approach - no storage permission needed
class ProfilePhotoActivity : AppCompatActivity() {
    
    private val photoPickerLauncher = registerForActivityResult(
        ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        uri?.let { selectedPhotoUri ->
            uploadProfilePhoto(selectedPhotoUri)
        }
    }
    
    fun selectPhoto() {
        // ✅ User picks one photo - no READ_MEDIA_IMAGES permission required
        photoPickerLauncher.launch(
            PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
        )
    }
}
```

### iOS: Limited Photo Library (iOS 14+)

```swift
// ✅ Modern approach - limited photo access
import PhotosUI

class ProfilePhotoViewController: UIViewController, PHPickerViewControllerDelegate {
    
    func selectPhoto() {
        var config = PHPickerConfiguration(photoLibrary: .shared())
        config.selectionLimit = 1
        config.filter = .images
        
        let picker = PHPickerViewController(configuration: config)
        picker.delegate = self
        present(picker, animated: true)
    }
    
    func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
        picker.dismiss(animated: true)
        
        guard let result = results.first else { return }
        
        result.itemProvider.loadObject(ofClass: UIImage.self) { image, error in
            if let image = image as? UIImage {
                self.uploadProfilePhoto(image)
            }
        }
    }
}
```

---

## Comparison Tables

### Permission Models Comparison

| Platform | Permission Type | Privacy Level | Use Case |
|----------|----------------|---------------|----------|
| **Android** | COARSE_LOCATION | Higher Privacy | City-level features (weather, local news) |
| | FINE_LOCATION | Lower Privacy | Precise navigation, delivery apps |
| | BACKGROUND_LOCATION | Lowest Privacy | Fitness tracking, geofencing (rare) |
| **iOS** | When In Use | Higher Privacy | Most location-based features |
| | Always | Lower Privacy | Continuous tracking apps (rare) |
| | Approximate (iOS 14+) | Highest Privacy | Non-precise location needs |

### Data Handling Comparison

| Approach | Privacy Level | Performance | Functionality |
|----------|--------------|-------------|---------------|
| **On-Device Processing** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Server with Anonymization** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Server with Full Data** | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

---

## Conclusion

**Key Takeaways**:

1. **Permission Requests**:
   - ✅ Request contextually, not at app launch
   - ✅ Provide clear explanations
   - ✅ Request minimum necessary scope
   - ✅ Offer alternatives if denied

2. **Data Collection**:
   - ✅ Collect minimal data
   - ✅ Process on-device when possible
   - ✅ Use platform privacy APIs
   - ✅ Delete data when no longer needed

3. **Logging & Analytics**:
   - ✅ Never log PII
   - ✅ Use anonymous identifiers
   - ✅ Auto-redact sensitive patterns
   - ✅ Minimal analytics data

4. **User Control**:
   - ✅ Granular consent options
   - ✅ Easy to revoke consent
   - ✅ Data export capability
   - ✅ Complete data deletion

**Remember**: Privacy is not a feature to bolt on later—it must be designed in from the start. Users trust you with their most personal data. Protect it accordingly.

---

## Additional Resources

- [Android Privacy Best Practices](https://developer.android.com/privacy/best-practices)
- [iOS Privacy Guidelines](https://developer.apple.com/privacy/)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)

**Next**: Try the hands-on [Lab](lab/m06-privacy-controls-lab/) to practice identifying and fixing privacy violations.
