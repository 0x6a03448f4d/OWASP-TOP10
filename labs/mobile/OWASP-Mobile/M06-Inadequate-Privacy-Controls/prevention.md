# M06: Inadequate Privacy Controls - Prevention

## Table of Contents
1. [Introduction](#introduction)
2. [Prevention Strategy Overview](#prevention-strategy-overview)
3. [Minimal Permission Requests](#minimal-permission-requests)
4. [Runtime Permission Handling](#runtime-permission-handling)
5. [Privacy-by-Design Principles](#privacy-by-design-principles)
6. [Data Minimization](#data-minimization)
7. [User Consent Mechanisms](#user-consent-mechanisms)
8. [Secure Data Collection Patterns](#secure-data-collection-patterns)
9. [Third-Party SDK Management](#third-party-sdk-management)
10. [Privacy Testing and Validation](#privacy-testing-and-validation)
11. [Platform-Specific Guidelines](#platform-specific-guidelines)
12. [Prevention Checklist](#prevention-checklist)

---

## Introduction

Preventing inadequate privacy controls requires a fundamental shift in how mobile applications are designed and developed. Unlike traditional security measures that protect against external threats, privacy controls protect users from the application itself.

**Core Prevention Philosophy**:
```
Security Question: "How do we protect user data from attackers?"
Privacy Question: "How do we protect users from ourselves?"

Privacy-First Approach:
1. Collect only what you absolutely need
2. Request permissions only when needed
3. Explain clearly why you need data
4. Give users control over their data
5. Delete data when no longer needed
6. Never share without explicit consent
```

This guide provides actionable implementation patterns for building privacy-respecting mobile applications.

---

## Prevention Strategy Overview

### The Privacy Development Lifecycle

```
Phase 1: Design
├─ Privacy Impact Assessment
├─ Data minimization planning
├─ Permission audit
└─ User control design

Phase 2: Implementation
├─ Minimal permission requests
├─ Just-in-time permission prompts
├─ Local processing where possible
├─ Secure data handling
└─ Privacy-safe logging

Phase 3: Integration
├─ Third-party SDK audit
├─ Data flow mapping
├─ Privacy policy alignment
└─ Consent mechanism implementation

Phase 4: Testing
├─ Permission testing
├─ Data flow analysis
├─ Network traffic inspection
├─ Privacy regression tests
└─ User testing

Phase 5: Maintenance
├─ Regular privacy audits
├─ SDK updates and reviews
├─ User feedback monitoring
└─ Compliance verification
```

### Privacy Maturity Model

| Level | Description | Characteristics |
|-------|-------------|-----------------|
| **1. Unaware** | No privacy considerations | Excessive permissions, PII in logs, no user control |
| **2. Reactive** | Minimum compliance | Basic privacy policy, permissions when required |
| **3. Proactive** | Privacy by default | Minimal data collection, user controls, clear consent |
| **4. Privacy-First** | Privacy as feature | On-device processing, transparency, user empowerment |
| **5. Privacy Leader** | Industry standard setter | Open source privacy tools, advocacy, innovation |

**Goal**: Reach Level 3+ for all production applications.

---

## Minimal Permission Requests

### Principle: Only Request What You Need

**✗ Anti-Pattern**: Request all possible permissions upfront

```kotlin
// DON'T DO THIS
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Request everything at once
        val permissions = arrayOf(
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_BACKGROUND_LOCATION,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE,
            Manifest.permission.READ_CALENDAR,
            Manifest.permission.BODY_SENSORS
        )
        
        requestPermissions(permissions, 1)
    }
}
```

**✓ Best Practice**: Request only necessary permissions, contextually

```kotlin
// SECURE APPROACH
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Don't request any permissions at startup
        // Wait for user to trigger features that need them
    }
    
    private fun onScanQRCodeClicked() {
        // Only request camera when user wants to scan QR code
        when {
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED -> {
                // Permission already granted
                openQRScanner()
            }
            
            shouldShowRequestPermissionRationale(Manifest.permission.CAMERA) -> {
                // Show explanation before requesting
                showCameraPermissionRationale {
                    requestCameraPermission()
                }
            }
            
            else -> {
                // First time asking
                requestCameraPermission()
            }
        }
    }
    
    private fun showCameraPermissionRationale(onAccept: () -> Unit) {
        AlertDialog.Builder(this)
            .setTitle("Camera Permission Needed")
            .setMessage("We need camera access to scan QR codes for login. " +
                       "Your camera is only used when you tap 'Scan QR Code' " +
                       "and is never accessed in the background.")
            .setPositiveButton("Grant Permission") { _, _ -> onAccept() }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun requestCameraPermission() {
        requestPermissions(arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA)
    }
}
```

### Permission Necessity Audit

**For each permission, ask**:
```yaml
1. Is this permission absolutely necessary?
   - Can we achieve the same functionality without it?
   - Can we use a less invasive alternative?

2. When do we need it?
   - At app launch? (Usually NO)
   - When user triggers specific feature? (Usually YES)
   - Continuously in background? (Rarely justified)

3. What's the minimum scope?
   - Precise location vs. approximate?
   - Full photo library vs. photo picker?
   - Foreground vs. background access?

4. How long do we need it?
   - One-time use?
   - During app session?
   - Continuous background access?
```

**Example Audit**:
```
App: Restaurant Finder

❌ REMOVE: READ_CONTACTS
   - Not necessary for core functionality
   - "Share with friends" can use platform share sheet

❌ REMOVE: ACCESS_BACKGROUND_LOCATION
   - App doesn't need background tracking
   - Only need location when user searches

✓ KEEP: ACCESS_COARSE_LOCATION (not FINE)
   - City-level location sufficient for restaurant search
   - More privacy-friendly than precise location

✓ KEEP: CAMERA (contextual)
   - Only for photo upload feature
   - Request when user taps "Add Photo"
```

---

## Runtime Permission Handling

### iOS: Purpose Strings and Contextual Requests

**Info.plist Configuration**:
```xml
<!-- SECURE: Clear, specific purpose strings -->
<key>NSLocationWhenInUseUsageDescription</key>
<string>We need your location to show nearby restaurants when you search. Your location is never tracked in the background.</string>

<key>NSCameraUsageDescription</key>
<string>We need camera access to let you upload photos of dishes to your reviews. Photos are only taken when you tap the camera button.</string>

<key>NSPhotoLibraryUsageDescription</key>
<string>We need photo library access to let you choose existing photos for your reviews.</string>

<key>NSContactsUsageDescription</key>
<string>We need contacts access to help you invite friends to join the app. We never upload your contacts to our servers.</string>

<!-- DON'T REQUEST unless absolutely necessary -->
<!-- <key>NSLocationAlwaysAndWhenInUseUsageDescription</key> -->
<!-- Background location should be rarely needed -->
```

**Swift: Contextual Permission Requests**:
```swift
// SECURE APPROACH
import CoreLocation

class RestaurantSearchViewController: UIViewController {
    let locationManager = CLLocationManager()
    
    func searchNearbyRestaurants() {
        // Check current authorization status
        let status = locationManager.authorizationStatus
        
        switch status {
        case .notDetermined:
            // First time - request permission
            requestLocationPermission()
            
        case .denied, .restricted:
            // Show settings prompt
            showLocationDeniedAlert()
            
        case .authorizedWhenInUse, .authorizedAlways:
            // Permission granted - proceed
            performSearch()
            
        @unknown default:
            break
        }
    }
    
    private func requestLocationPermission() {
        // Show rationale first (custom UI)
        let alert = UIAlertController(
            title: "Location Permission",
            message: "We need your location to find restaurants near you. " +
                     "Your location is only used when you search and is " +
                     "never tracked in the background.",
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
            // Request only "When In Use" - never "Always"
            self.locationManager.requestWhenInUseAuthorization()
        })
        
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        
        present(alert, animated: true)
    }
    
    private func showLocationDeniedAlert() {
        let alert = UIAlertController(
            title: "Location Access Disabled",
            message: "To search for nearby restaurants, please enable location " +
                     "access in Settings > Privacy > Location Services.",
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(title: "Open Settings", style: .default) { _ in
            if let settingsUrl = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(settingsUrl)
            }
        })
        
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        
        present(alert, animated: true)
    }
}
```

### Android: Granular Permission Requests

**Manifest Declaration**:
```xml
<!-- SECURE: Only declare permissions you actually use -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    
    <!-- Request minimal location permission -->
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
    
    <!-- Only if precise location absolutely necessary -->
    <!-- <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" /> -->
    
    <!-- Camera for photo upload -->
    <uses-permission android:name="android.permission.CAMERA" />
    
    <!-- DON'T request background location unless critical -->
    <!-- <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" /> -->
    
    <!-- Use Photo Picker instead of full storage access (Android 13+) -->
    <!-- <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" 
         android:maxSdkVersion="32" /> -->
    
</manifest>
```

**Kotlin: Runtime Permission Pattern**:
```kotlin
// SECURE: Permission request with explanation
class RestaurantMapActivity : AppCompatActivity() {
    
    private val locationPermissionRequest = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        when {
            permissions[Manifest.permission.ACCESS_COARSE_LOCATION] == true -> {
                // Coarse location granted - sufficient for most use cases
                loadNearbyRestaurants()
            }
            permissions[Manifest.permission.ACCESS_FINE_LOCATION] == true -> {
                // Fine location granted
                loadNearbyRestaurants()
            }
            else -> {
                // Permission denied
                showPermissionDeniedMessage()
            }
        }
    }
    
    fun searchNearby() {
        when {
            // Check if we already have permission
            ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.ACCESS_COARSE_LOCATION
            ) == PackageManager.PERMISSION_GRANTED -> {
                loadNearbyRestaurants()
            }
            
            // Should we show rationale?
            shouldShowRequestPermissionRationale(
                Manifest.permission.ACCESS_COARSE_LOCATION
            ) -> {
                showLocationRationale()
            }
            
            // Request permission
            else -> {
                requestLocationPermission()
            }
        }
    }
    
    private fun showLocationRationale() {
        MaterialAlertDialogBuilder(this)
            .setTitle("Location Permission")
            .setMessage(
                "To show restaurants near you, we need approximate location access. " +
                "\n\n• Only used when you search" +
                "\n• Never tracked in background" +
                "\n• You can revoke anytime in Settings"
            )
            .setPositiveButton("Grant Permission") { _, _ ->
                requestLocationPermission()
            }
            .setNegativeButton("Not Now", null)
            .show()
    }
    
    private fun requestLocationPermission() {
        // Request only coarse location (more privacy-friendly)
        locationPermissionRequest.launch(
            arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION)
        )
    }
}
```

### Permission Request Best Practices

```
DO:
✓ Request permissions contextually (when feature is used)
✓ Explain why you need each permission
✓ Request minimum necessary scope (coarse vs fine, when-in-use vs always)
✓ Provide alternative functionality if permission denied
✓ Respect user's "don't ask again" choice
✓ Implement graceful degradation

DON'T:
✗ Request all permissions at app launch
✗ Bundle multiple unrelated permissions together
✗ Use vague or misleading explanations
✗ Block core functionality for optional permissions
✗ Repeatedly prompt after denial
✗ Implement "permission walls" that force consent
```

---

## Privacy-by-Design Principles

### 1. Data Minimization

**Principle**: Collect only the data you absolutely need.

**Example: User Profile**:
```kotlin
// ✗ EXCESSIVE DATA COLLECTION
data class UserProfile(
    val id: String,
    val email: String,
    val password: String,          // ✗ Store hash only
    val fullName: String,
    val dateOfBirth: Date,        // ✗ Not needed
    val gender: String,            // ✗ Not needed
    val phoneNumber: String,       // ✗ Optional
    val address: Address,          // ✗ Optional
    val socialSecurityNumber: String, // ✗ Never collect
    val creditCardNumber: String,  // ✗ Never store
    val mothersMaidenName: String, // ✗ Not needed
    val ipAddress: String,         // ✗ Don't store permanently
    val deviceId: String,          // ✗ Use session ID instead
    val installedApps: List<String>, // ✗ Privacy violation
    val locationHistory: List<Location>, // ✗ Don't store unless necessary
    val browsingHistory: List<String>    // ✗ Privacy violation
)

// ✓ MINIMAL DATA COLLECTION
data class UserProfile(
    val id: String,
    val email: String,
    val passwordHash: String,  // ✓ Hashed, not plaintext
    val displayName: String,   // ✓ User-chosen, not full legal name
    val createdAt: Date
)

// Optional fields in separate table, only if user provides
data class OptionalProfile(
    val userId: String,
    val phoneNumber: String?,  // Only if user adds
    val avatarUrl: String?     // Only if user uploads
)
```

### 2. Purpose Limitation

**Principle**: Use data only for the stated purpose.

```swift
// ✓ SECURE: Explicit purpose declaration
struct DataUsagePolicy {
    let purpose: String
    let dataTypes: [DataType]
    let retention: TimeInterval
    let sharingAllowed: Bool
    
    static let locationForSearch = DataUsagePolicy(
        purpose: "Find nearby restaurants when you search",
        dataTypes: [.location],
        retention: 0, // Don't store - use and discard
        sharingAllowed: false
    )
    
    static let photoForReview = DataUsagePolicy(
        purpose: "Display your photo with your restaurant review",
        dataTypes: [.photo],
        retention: .infinity, // Store as long as review exists
        sharingAllowed: true // Public review, user aware
    )
}

class LocationService {
    func getCurrentLocation(for purpose: DataUsagePolicy) async throws -> Location {
        // Verify purpose allows location access
        guard purpose.dataTypes.contains(.location) else {
            throw PrivacyError.purposeViolation
        }
        
        let location = try await CLLocationManager().requestLocation()
        
        // Use only for stated purpose
        if purpose.retention == 0 {
            // Don't store - return and discard
            return location
        } else {
            // Store with purpose metadata for audit
            try await storeLocation(location, purpose: purpose)
            return location
        }
    }
}
```

### 3. Storage Limitation

**Principle**: Delete data when no longer needed.

```kotlin
// ✓ SECURE: Automatic data deletion
class DataRetentionManager {
    
    // Define retention policies
    enum class RetentionPolicy(val duration: Duration) {
        SESSION(Duration.ZERO),           // Delete after session
        SHORT_TERM(Duration.ofDays(30)),  // 30 days
        MEDIUM_TERM(Duration.ofDays(90)), // 90 days
        LEGAL_MINIMUM(Duration.ofYears(1)), // Compliance requirement
        USER_CONTROLLED(Duration.INFINITE)  // User decides when to delete
    }
    
    data class DataWithRetention(
        val data: Any,
        val category: DataCategory,
        val policy: RetentionPolicy,
        val createdAt: Instant
    )
    
    // Automatically delete expired data
    suspend fun cleanupExpiredData() {
        val now = Instant.now()
        
        // Session data - delete after logout
        sessionStorage.clear()
        
        // Search history - delete after 30 days
        database.query("""
            DELETE FROM search_history
            WHERE created_at < ?
        """, now.minus(RetentionPolicy.SHORT_TERM.duration))
        
        // Temporary location data - delete immediately after use
        database.query("""
            DELETE FROM temp_locations
            WHERE created_at < ?
        """, now.minus(Duration.ofHours(1)))
        
        // Analytics events - delete after 90 days
        database.query("""
            DELETE FROM analytics_events
            WHERE created_at < ?
        """, now.minus(RetentionPolicy.MEDIUM_TERM.duration))
        
        // User-generated content - keep until user deletes
        // (No automatic deletion)
    }
    
    // Schedule regular cleanup
    fun scheduleRetentionCleanup() {
        WorkManager.getInstance(context)
            .enqueueUniquePeriodicWork(
                "data_retention_cleanup",
                ExistingPeriodicWorkPolicy.KEEP,
                PeriodicWorkRequestBuilder<DataCleanupWorker>(1, TimeUnit.DAYS)
                    .build()
            )
    }
}
```

### 4. On-Device Processing

**Principle**: Process data locally when possible.

```swift
// ✓ SECURE: On-device ML processing
import CoreML
import Vision

class ImageRecognitionService {
    
    func recognizeFood(in image: UIImage) async throws -> [FoodItem] {
        // ✓ Process on-device using Core ML
        // ✗ DON'T send image to server for recognition
        
        guard let model = try? VNCoreMLModel(for: FoodRecognitionModel().model) else {
            throw RecognitionError.modelLoadFailed
        }
        
        let request = VNCoreMLRequest(model: model)
        
        let handler = VNImageRequestHandler(cgImage: image.cgImage!, options: [:])
        try handler.perform([request])
        
        guard let results = request.results as? [VNClassificationObservation] else {
            return []
        }
        
        // All processing done locally - image never leaves device
        return results.map { FoodItem(name: $0.identifier, confidence: $0.confidence) }
    }
    
    // ✗ AVOID: Server-side processing when not necessary
    func recognizeFoodServer(image: UIImage) async throws -> [FoodItem] {
        // Privacy violation: Sends image to server
        let imageData = image.jpegData(compressionQuality: 0.8)
        
        // Image may contain:
        // - Location EXIF data
        // - Faces of people
        // - Private information visible in background
        
        let response = try await API.post("/recognize", body: imageData)
        return try JSONDecoder().decode([FoodItem].self, from: response)
    }
}
```

**On-Device Processing Examples**:
```yaml
Use Local Processing For:
  ✓ Image recognition (Core ML, TensorFlow Lite)
  ✓ Text recognition (Vision, ML Kit)
  ✓ Face detection (Vision, ML Kit)
  ✓ Natural language processing (Core ML, on-device NLP)
  ✓ Activity recognition (CoreMotion, Activity Recognition)
  ✓ Keyword spotting (Speech framework)
  
Benefits:
  - Privacy: Data never leaves device
  - Speed: No network latency
  - Offline: Works without internet
  - Cost: No server processing fees
```

---

## Data Minimization

### Implement Granular Photo Access

**✗ Old Approach**: Request full photo library access

```swift
// DON'T DO THIS (iOS < 14)
import Photos

func requestPhotoLibraryAccess() {
    PHPhotoLibrary.requestAuthorization { status in
        if status == .authorized {
            // Now has access to ALL photos - privacy risk
            self.accessAllPhotos()
        }
    }
}
```

**✓ Modern Approach**: Use Photo Picker (iOS 14+, Android 13+)

```swift
// SECURE: Limited Photo Picker (iOS 14+)
import PhotosUI

class ProfileViewController: UIViewController, PHPickerViewControllerDelegate {
    
    func selectProfilePhoto() {
        // ✓ User selects specific photo - no library access needed
        var config = PHPickerConfiguration()
        config.selectionLimit = 1
        config.filter = .images
        
        let picker = PHPickerViewController(configuration: config)
        picker.delegate = self
        present(picker, animated: true)
    }
    
    func picker(_ picker: PHPickerViewController, 
                didFinishPicking results: [PHPickerResult]) {
        picker.dismiss(animated: true)
        
        guard let result = results.first else { return }
        
        // Access only the selected photo - not entire library
        result.itemProvider.loadObject(ofClass: UIImage.self) { image, error in
            if let image = image as? UIImage {
                self.uploadProfilePhoto(image)
            }
        }
    }
}
```

```kotlin
// SECURE: Photo Picker (Android 13+)
class ProfileActivity : AppCompatActivity() {
    
    private val photoPickerLauncher = registerForActivityResult(
        ActivityResultContracts.PickVisualMedia()
    ) { uri ->
        // User selected one photo - no storage permission needed
        uri?.let { uploadProfilePhoto(it) }
    }
    
    fun selectProfilePhoto() {
        // ✓ Use photo picker - no READ_EXTERNAL_STORAGE permission required
        photoPickerLauncher.launch(
            PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)
        )
    }
    
    // For older Android versions, request minimal permission
    private val legacyPhotoLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let { uploadProfilePhoto(it) }
    }
}
```

### Location Precision Reduction

**✓ Use Coarse Location When Sufficient**:

```kotlin
// SECURE: Request coarse location for city-level needs
class WeatherService {
    
    suspend fun getCurrentWeather(): WeatherData {
        // ✓ Coarse location sufficient for weather
        // Accuracy: ~2-5 km (city block)
        val location = getCoarseLocation()
        
        return fetchWeather(location.latitude, location.longitude)
    }
    
    private suspend fun getCoarseLocation(): Location {
        // Only request ACCESS_COARSE_LOCATION permission
        val fusedLocationClient = LocationServices.getFusedLocationProviderClient(context)
        
        return suspendCoroutine { continuation ->
            fusedLocationClient.lastLocation.addOnSuccessListener { location ->
                continuation.resume(location)
            }
        }
    }
}

// Only use fine location when truly necessary
class NavigationService {
    
    suspend fun startTurnByTurnNavigation() {
        // ✓ Turn-by-turn requires precise location - justified
        val location = getPreciseLocation()
        
        startNavigation(location)
    }
    
    private suspend fun getPreciseLocation(): Location {
        // REQUEST ACCESS_FINE_LOCATION only for navigation feature
        // ...
    }
}
```

**iOS: Approximate Location (iOS 14+)**:
```swift
// SECURE: Request approximate location
class WeatherViewController: UIViewController, CLLocationManagerDelegate {
    let locationManager = CLLocationManager()
    
    func requestLocation() {
        locationManager.delegate = self
        
        // ✓ Request approximate location
        // User can choose "Precise: Off" in permission dialog
        locationManager.requestWhenInUseAuthorization()
    }
    
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        if manager.accuracyAuthorization == .reducedAccuracy {
            // User chose approximate location
            // Accuracy: ~10km radius
            print("Approximate location granted")
        } else {
            // User chose precise location
            print("Precise location granted")
        }
        
        manager.requestLocation()
    }
    
    func locationManager(_ manager: CLLocationManager, 
                        didUpdateLocations locations: [CLLocation]) {
        guard let location = locations.first else { return }
        
        // ✓ Use location only for weather - don't store
        fetchWeather(for: location) { weather in
            self.displayWeather(weather)
        }
        
        // ✓ Don't store location history
    }
}
```

---

## User Consent Mechanisms

### Transparent Consent UI

**✓ Clear, Specific Consent**:

```kotlin
// SECURE: Granular consent management
data class ConsentPreferences(
    val analytics: ConsentStatus,
    val advertising: ConsentStatus,
    val locationTracking: ConsentStatus,
    val crashReporting: ConsentStatus,
    val personalizedContent: ConsentStatus
) {
    enum class ConsentStatus {
        NOT_ASKED,
        GRANTED,
        DENIED,
        WITHDRAWN
    }
}

class ConsentManager(private val context: Context) {
    
    private val prefs = context.getSharedPreferences("consent_prefs", Context.MODE_PRIVATE)
    
    fun showConsentDialog() {
        MaterialAlertDialogBuilder(context)
            .setTitle("Your Privacy Choices")
            .setMessage(
                "We respect your privacy. Please choose which data collection " +
                "features you'd like to enable. You can change these anytime in Settings."
            )
            .setView(R.layout.consent_dialog)
            .setPositiveButton("Save Preferences") { dialog, _ ->
                saveConsentPreferences(dialog)
            }
            .setNeutralButton("Learn More") { _, _ ->
                openPrivacyPolicy()
            }
            .setCancelable(false)
            .show()
    }
    
    private fun saveConsentPreferences(dialog: DialogInterface) {
        val view = (dialog as AlertDialog).findViewById<View>(R.id.consent_form)!!
        
        val analytics = view.findViewById<CheckBox>(R.id.consent_analytics).isChecked
        val advertising = view.findViewById<CheckBox>(R.id.consent_advertising).isChecked
        val location = view.findViewById<CheckBox>(R.id.consent_location).isChecked
        
        // ✓ Save granular preferences
        prefs.edit {
            putBoolean("analytics_consent", analytics)
            putBoolean("advertising_consent", advertising)
            putBoolean("location_tracking_consent", location)
            putLong("consent_timestamp", System.currentTimeMillis())
        }
        
        // ✓ Apply immediately
        applyConsentPreferences()
    }
    
    private fun applyConsentPreferences() {
        if (!hasAnalyticsConsent()) {
            // Disable analytics
            Analytics.setEnabled(false)
        }
        
        if (!hasAdvertisingConsent()) {
            // Disable advertising
            AdService.setEnabled(false)
        }
        
        if (!hasLocationTrackingConsent()) {
            // Stop location tracking
            LocationTracker.stop()
        }
    }
    
    fun hasAnalyticsConsent(): Boolean {
        return prefs.getBoolean("analytics_consent", false)
    }
    
    fun revokeAllConsent() {
        prefs.edit {
            clear()
            putBoolean("consent_revoked", true)
            putLong("revocation_timestamp", System.currentTimeMillis())
        }
        
        // ✓ Delete all collected data
        deleteAllUserData()
    }
}
```

**Consent Dialog XML**:
```xml
<!-- res/layout/consent_dialog.xml -->
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:orientation="vertical"
    android:padding="16dp">
    
    <!-- Analytics Consent -->
    <CheckBox
        android:id="@+id/consent_analytics"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Analytics"
        android:checked="false"/>
    
    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Help us improve the app by sending anonymous usage statistics. No personal information is collected."
        android:textSize="12sp"
        android:layout_marginBottom="16dp"/>
    
    <!-- Advertising Consent -->
    <CheckBox
        android:id="@+id/consent_advertising"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Personalized Advertising"
        android:checked="false"/>
    
    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Show personalized ads based on your interests. If disabled, you'll still see ads, but they won't be personalized."
        android:textSize="12sp"
        android:layout_marginBottom="16dp"/>
    
    <!-- Location Tracking Consent -->
    <CheckBox
        android:id="@+id/consent_location"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Location-Based Features"
        android:checked="false"/>
    
    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="Enable location-based recommendations. Your location is only used when the app is open and is never shared with third parties."
        android:textSize="12sp"/>
    
</LinearLayout>
```

### GDPR/CCPA Compliance

**✓ Data Subject Rights Implementation**:

```swift
// SECURE: Implement user data rights
class PrivacyComplianceManager {
    
    // Right to Access (GDPR Article 15)
    func exportUserData(userId: String) async throws -> URL {
        // Collect all user data
        let userData = UserDataExport(
            profile: try await fetchUserProfile(userId),
            reviews: try await fetchUserReviews(userId),
            photos: try await fetchUserPhotos(userId),
            searchHistory: try await fetchSearchHistory(userId),
            preferences: try await fetchPreferences(userId)
        )
        
        // Generate JSON export
        let jsonData = try JSONEncoder().encode(userData)
        
        // Save to file
        let fileURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("user_data_\(userId).json")
        try jsonData.write(to: fileURL)
        
        return fileURL
    }
    
    // Right to Erasure (GDPR Article 17)
    func deleteAllUserData(userId: String) async throws {
        // Delete from all systems
        try await database.transaction {
            // User profile
            try await deleteUserProfile(userId)
            
            // User-generated content
            try await deleteUserReviews(userId)
            try await deleteUserPhotos(userId)
            
            // Activity data
            try await deleteSearchHistory(userId)
            try await deleteLocationHistory(userId)
            try await deleteAnalyticsData(userId)
            
            // Preferences
            try await deletePreferences(userId)
            
            // Session data
            try await deleteSessionData(userId)
            
            // Backups (mark for deletion)
            try await markForDeletionInBackups(userId)
        }
        
        // Notify third parties
        try await notifyThirdPartiesToDelete(userId)
        
        // Log deletion for compliance
        try await logDataDeletion(userId, reason: "User request")
    }
    
    // Right to Portability (GDPR Article 20)
    func generatePortableData(userId: String) async throws -> Data {
        // Export in machine-readable format (JSON)
        let userData = try await exportUserData(userId: userId)
        return try Data(contentsOf: userData)
    }
    
    // Right to Object (GDPR Article 21)
    func disableProcessing(userId: String, purpose: ProcessingPurpose) async {
        switch purpose {
        case .directMarketing:
            try await setMarketingPreference(userId, enabled: false)
        case .profiling:
            try await setProfilingPreference(userId, enabled: false)
        case .analytics:
            try await setAnalyticsPreference(userId, enabled: false)
        }
    }
    
    // CCPA: Do Not Sell My Personal Information
    func optOutOfDataSale(userId: String) async throws {
        // Stop sharing with data brokers
        try await setDataSharingPreference(userId, allowSale: false)
        
        // Notify partners to stop processing
        try await notifyPartnersOfOptOut(userId)
        
        // Display opt-out status
        try await updatePrivacyDashboard(userId, optedOut: true)
    }
}
```

---

## Secure Data Collection Patterns

### Privacy-Safe Logging

**✗ Insecure Logging** (PII leakage):
```java
// DON'T DO THIS
public class AuthService {
    private static final Logger log = Logger.getLogger(AuthService.class);
    
    public User login(String email, String password) {
        log.info("Login attempt: " + email); // ✗ PII in logs
        log.debug("Password: " + password);  // ✗ CRITICAL - password in logs!
        
        User user = userRepository.findByEmail(email);
        log.info("User found: " + user.toString()); // ✗ Entire user object
        
        return user;
    }
}
```

**✓ Privacy-Safe Logging**:
```kotlin
// SECURE APPROACH
class AuthService {
    private val logger = LoggerFactory.getLogger(AuthService::class.java)
    
    fun login(email: String, password: String): User? {
        // ✓ Log event without PII
        logger.info("Login attempt for user")
        
        // ✓ Use hashed identifier if needed
        val userIdHash = hashUserId(email)
        logger.info("Login attempt for user_hash=$userIdHash")
        
        // ✗ NEVER log passwords
        // logger.debug("Password: $password")  // NO!
        
        val user = userRepository.findByEmail(email)
        
        if (user != null) {
            // ✓ Log success without sensitive data
            logger.info("Login successful for user_id=${user.id}")
            
            // ✗ DON'T log entire user object
            // logger.info("User: $user")  // NO!
        } else {
            logger.warn("Login failed: user not found")
            // ✓ Don't reveal whether email exists (security + privacy)
        }
        
        return user
    }
    
    private fun hashUserId(email: String): String {
        // One-way hash for privacy-safe logging
        return MessageDigest.getInstance("SHA-256")
            .digest(email.toByteArray())
            .joinToString("") { "%02x".format(it) }
            .take(16) // First 16 chars
    }
}

// Custom logger wrapper that sanitizes PII
class PrivacyAwareLogger(private val logger: Logger) {
    
    fun info(message: String) {
        logger.info(sanitizePII(message))
    }
    
    fun warn(message: String) {
        logger.warn(sanitizePII(message))
    }
    
    fun error(message: String, throwable: Throwable?) {
        logger.error(sanitizePII(message), sanitizeStackTrace(throwable))
    }
    
    private fun sanitizePII(message: String): String {
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
        
        // Redact credit cards
        sanitized = sanitized.replace(
            Regex("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b"),
            "[CARD_REDACTED]"
        )
        
        // Redact SSN
        sanitized = sanitized.replace(
            Regex("\\b\\d{3}-\\d{2}-\\d{4}\\b"),
            "[SSN_REDACTED]"
        )
        
        return sanitized
    }
    
    private fun sanitizeStackTrace(throwable: Throwable?): Throwable? {
        // Remove sensitive information from exception messages
        // This is complex - consider not logging stack traces with PII
        return throwable
    }
}
```

### Privacy-Safe Analytics

**✓ Anonymous Analytics**:

```swift
// SECURE: Anonymous analytics without PII
class PrivacyFriendlyAnalytics {
    
    func trackEvent(_ eventName: String, properties: [String: Any] = [:]) {
        var sanitizedProperties = properties
        
        // ✓ Remove PII from properties
        sanitizedProperties = removePII(from: sanitizedProperties)
        
        // ✓ Use anonymous user ID (rotates periodically)
        let anonymousId = getAnonymousUserId()
        
        // ✓ Send minimal device info
        let event = AnalyticsEvent(
            name: eventName,
            properties: sanitizedProperties,
            anonymousUserId: anonymousId,
            timestamp: Date(),
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
            osVersion: UIDevice.current.systemVersion,
            // ✗ DON'T send: device ID, advertising ID, precise location
        )
        
        sendEvent(event)
    }
    
    private func getAnonymousUserId() -> String {
        let userDefaults = UserDefaults.standard
        let key = "anonymous_user_id"
        
        // Check if we have an existing ID
        if let existingId = userDefaults.string(forKey: key) {
            // Check if it's expired (rotate every 30 days)
            let createdKey = "anonymous_user_id_created"
            if let created = userDefaults.object(forKey: createdKey) as? Date {
                if Date().timeIntervalSince(created) < 30 * 24 * 60 * 60 {
                    return existingId
                }
            }
        }
        
        // Generate new anonymous ID
        let newId = UUID().uuidString
        userDefaults.set(newId, forKey: key)
        userDefaults.set(Date(), forKey: createdKey)
        
        return newId
    }
    
    private func removePII(from properties: [String: Any]) -> [String: Any] {
        var cleaned = properties
        
        // Remove known PII keys
        let piiKeys = ["email", "phone", "name", "address", "ssn", "credit_card"]
        piiKeys.forEach { cleaned.removeValue(forKey: $0) }
        
        // Sanitize string values
        for (key, value) in cleaned {
            if let stringValue = value as? String {
                cleaned[key] = sanitizeString(stringValue)
            }
        }
        
        return cleaned
    }
    
    private func sanitizeString(_ value: String) -> String {
        // Remove email addresses
        var sanitized = value.replacingOccurrences(
            of: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
            with: "[EMAIL]",
            options: .regularExpression
        )
        
        // Remove phone numbers
        sanitized = sanitized.replacingOccurrences(
            of: "\\b\\d{3}[-.]?\\d{3}[-.]?\\d{4}\\b",
            with: "[PHONE]",
            options: .regularExpression
        )
        
        return sanitized
    }
    
    // ✓ Use aggregate analytics instead of individual tracking
    func trackAggregateMetric(_ metric: String, value: Double) {
        // Send aggregate data without user identifiers
        let aggregateEvent = [
            "metric": metric,
            "value": value,
            "timestamp": Date().timeIntervalSince1970
            // No user ID - purely aggregate
        ]
        
        sendEvent(aggregateEvent)
    }
}
```

---

## Third-Party SDK Management

### SDK Privacy Audit

**Pre-Integration Checklist**:

```yaml
Before Integrating Any SDK:

1. Privacy Policy Review:
   □ Does SDK collect user data?
   □ What specific data points?
   □ Is data shared with third parties?
   □ Where is data stored (jurisdiction)?
   □ Data retention period?

2. Permission Requirements:
   □ What permissions does SDK request?
   □ Are they necessary for functionality?
   □ Can we configure permissions?

3. Network Analysis:
   □ What endpoints does SDK contact?
   □ Frequency of network calls?
   □ Can we inspect payloads?
   □ Is traffic encrypted?

4. Compliance:
   □ GDPR compliant?
   □ CCPA compliant?
   □ COPPA compliant (if applicable)?
   □ SOC 2 certified?

5. Control:
   □ Can we disable data collection?
   □ Can we enable opt-out?
   □ Can we request data deletion?
   □ Can we control data sharing?

6. Alternatives:
   □ Can we implement functionality ourselves?
   □ Are there more privacy-friendly alternatives?
   □ Can we use on-device processing instead?
```

**SDK Configuration for Privacy**:

```kotlin
// SECURE: Configure SDKs with privacy settings
class SDKPrivacyConfigurator {
    
    fun configureFacebookSDK(application: Application) {
        // ✓ Disable automatic data collection
        FacebookSdk.setAutoLogAppEventsEnabled(false)
        FacebookSdk.setAdvertiserIDCollectionEnabled(false)
        
        // ✓ Enable limited data use (CCPA)
        FacebookSdk.setDataProcessingOptions(arrayOf("LDU"), 1, 1000)
        
        // ✓ Only collect with user consent
        if (hasAnalyticsConsent()) {
            FacebookSdk.setAutoLogAppEventsEnabled(true)
        }
    }
    
    fun configureFirebaseAnalytics() {
        // ✓ Disable automatic collection
        Firebase.analytics.setAnalyticsCollectionEnabled(false)
        
        // ✓ Enable only with consent
        if (hasAnalyticsConsent()) {
            Firebase.analytics.setAnalyticsCollectionEnabled(true)
        }
        
        // ✓ Disable advertising features
        Firebase.analytics.setUserProperty("allow_ad_personalization_signals", "false")
        
        // ✓ Set data retention to minimum
        // (Configure in Firebase Console: 2 months minimum)
    }
    
    fun configureAdjust() {
        val config = AdjustConfig(context, appToken, environment)
        
        // ✓ Disable third-party sharing by default
        config.setPreinstallTrackingEnabled(false)
        config.setDeviceKnown(false)
        
        // ✓ Only enable with consent
        if (hasAdvertisingConsent()) {
            config.setPreinstallTrackingEnabled(true)
        }
        
        Adjust.onCreate(config)
    }
    
    // Audit SDK network traffic
    fun auditSDKTraffic() {
        // Use OkHttp interceptor to log SDK requests
        val interceptor = object : Interceptor {
            override fun intercept(chain: Interceptor.Chain): Response {
                val request = chain.request()
                
                // Log for privacy audit
                Log.d("SDK_AUDIT", "Request to: ${request.url}")
                Log.d("SDK_AUDIT", "Headers: ${request.headers}")
                
                // Check for privacy violations
                if (containsPII(request)) {
                    Log.w("SDK_AUDIT", "⚠️  PII detected in request!")
                }
                
                return chain.proceed(request)
            }
        }
    }
}
```

### SDK Sandboxing

```swift
// SECURE: Isolate SDK data access
class SDKSandbox {
    
    // Create isolated environment for SDK
    func initializeSDKWithLimitedAccess() {
        // ✓ Don't pass real user data
        let sanitizedConfig = SDKConfiguration(
            // Use anonymous ID, not real user ID
            userId: getAnonymousId(),
            
            // Don't pass email
            // email: user.email,  // ✗ NO
            
            // Don't pass name
            // name: user.name,    // ✗ NO
            
            // Minimal device info
            deviceModel: "iOS", // Generic, not specific model
            osVersion: "15.0",  // Generic version
            
            // ✗ Don't pass: IDFA, device ID, location, contacts
        )
        
        ThirdPartySDK.initialize(config: sanitizedConfig)
    }
    
    // Proxy SDK calls to add privacy checks
    func trackSDKEvent(_ event: String, properties: [String: Any]) {
        // ✓ Filter properties before sending to SDK
        let safeProperties = properties.filter { key, value in
            // Whitelist approach - only allow safe properties
            let allowedKeys = ["screen_name", "button_clicked", "feature_used"]
            return allowedKeys.contains(key)
        }
        
        ThirdPartySDK.track(event, properties: safeProperties)
    }
}
```

---

## Privacy Testing and Validation

### Automated Privacy Tests

```kotlin
// Privacy regression tests
class PrivacyTests {
    
    @Test
    fun `verify no PII in logs`() {
        // Enable log capture
        val logCapture = LogCapture()
        logCapture.start()
        
        // Perform actions that trigger logging
        authService.login("user@example.com", "password123")
        userService.updateProfile(testUser)
        
        // Stop capture
        val logs = logCapture.stop()
        
        // Assert no PII in logs
        assertFalse(logs.contains("user@example.com"), "Email found in logs")
        assertFalse(logs.contains("password123"), "Password found in logs")
        assertFalse(logs.contains(testUser.phoneNumber), "Phone found in logs")
        assertFalse(logs.contains(testUser.address), "Address found in logs")
    }
    
    @Test
    fun `verify no excessive permissions requested`() {
        val manifestPermissions = getManifestPermissions()
        
        // Define necessary permissions for app
        val necessaryPermissions = setOf(
            Manifest.permission.INTERNET,
            Manifest.permission.CAMERA, // For QR code scanning
            Manifest.permission.ACCESS_COARSE_LOCATION // For restaurant search
        )
        
        // Verify only necessary permissions
        val excessivePermissions = manifestPermissions - necessaryPermissions
        assertTrue(
            excessivePermissions.isEmpty(),
            "Excessive permissions found: $excessivePermissions"
        )
    }
    
    @Test
    fun `verify analytics respects consent`() {
        // Revoke analytics consent
        consentManager.setAnalyticsConsent(false)
        
        // Trigger analytics event
        analytics.trackEvent("test_event")
        
        // Verify no network request made
        val networkCalls = networkMonitor.getCalls()
        assertFalse(
            networkCalls.any { it.url.contains("analytics.example.com") },
            "Analytics event sent without consent"
        )
    }
    
    @Test
    fun `verify location not collected in background`() {
        // Send app to background
        ActivityLifecycleMonitor.sendToBackground()
        
        // Wait 5 minutes
        Thread.sleep(5 * 60 * 1000)
        
        // Verify no location requests
        val locationRequests = LocationRequestMonitor.getRequests()
        assertTrue(
            locationRequests.isEmpty(),
            "Location requested in background"
        )
    }
    
    @Test
    fun `verify data deletion works`() {
        // Create user data
        val userId = createTestUser()
        userService.createReview(userId, testReview)
        locationService.saveLocation(userId, testLocation)
        
        // Request deletion
        privacyManager.deleteAllUserData(userId)
        
        // Verify all data deleted
        assertNull(userRepository.findById(userId))
        assertTrue(reviewRepository.findByUserId(userId).isEmpty())
        assertTrue(locationRepository.findByUserId(userId).isEmpty())
    }
}
```

### Manual Privacy Audit

```bash
# Privacy Audit Checklist

# 1. Network Traffic Analysis
$ mitmproxy --mode transparent --showhost
# Verify:
# □ No PII in URLs or headers
# □ No excessive data collection
# □ No data sent without consent
# □ All traffic encrypted (HTTPS)

# 2. Permission Analysis
# Android
$ adb shell dumpsys package com.example.app | grep permission
# iOS
$ ios-deploy --list-bundle-id
# Verify:
# □ Only necessary permissions declared
# □ Dangerous permissions have runtime requests
# □ Background permissions justified

# 3. Storage Analysis
# Android
$ adb shell
$ cd /data/data/com.example.app
$ find . -name "*.db"
$ sqlite3 database.db ".tables"
# Verify:
# □ No plaintext passwords
# □ No unnecessary PII storage
# □ Proper encryption for sensitive data

# 4. SDK Audit
$ exodus-standalone analyze app.apk
# Verify:
# □ All SDKs documented
# □ SDK privacy policies reviewed
# □ Minimal tracking SDKs
# □ SDK permissions justified

# 5. Privacy Policy Validation
# Compare policy vs actual behavior:
# □ Permissions match policy
# □ Data collection matches disclosure
# □ Third-party sharing disclosed
# □ Retention periods accurate
```

---

## Platform-Specific Guidelines

### iOS Privacy Best Practices

```swift
// iOS Privacy Checklist

// 1. ✓ App Tracking Transparency (iOS 14.5+)
import AppTrackingTransparency

func requestTrackingPermission() {
    ATTrackingManager.requestTrackingAuthorization { status in
        switch status {
        case .authorized:
            // Enable cross-app tracking
            enablePersonalizedAds()
        case .denied, .restricted, .notDetermined:
            // Disable tracking
            disablePersonalizedAds()
        @unknown default:
            break
        }
    }
}

// 2. ✓ Privacy Manifests (iOS 17+)
// Create PrivacyInfo.xcprivacy file
/*
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <false/>
    <key>NSPrivacyTrackingDomains</key>
    <array/>
    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeEmailAddress</string>
            <key>NSPrivacyCollectedDataTypeLinked</key>
            <true/>
            <key>NSPrivacyCollectedDataTypeTracking</key>
            <false/>
            <key>NSPrivacyCollectedDataTypePurposes</key>
            <array>
                <string>NSPrivacyCollectedDataTypePurposeAppFunctionality</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
*/

// 3. ✓ Clipboard Access (iOS 14+)
// Minimize clipboard access to avoid notifications
func handleClipboard() {
    // ✗ DON'T poll clipboard
    // Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
    //     let clipboard = UIPasteboard.general.string
    // }
    
    // ✓ Only access when user pastes
    // iOS automatically provides paste menu
}

// 4. ✓ Local Network Privacy (iOS 14+)
// Add NSLocalNetworkUsageDescription to Info.plist
// Only if truly necessary

// 5. ✓ Privacy Nutrition Labels
// Accurately declare in App Store Connect:
// - Data collection types
// - Linked to user
// - Used for tracking
// - Purposes
```

### Android Privacy Best Practices

```kotlin
// Android Privacy Checklist

// 1. ✓ Declare Data Safety (Google Play)
// In Play Console, accurately declare:
// - Data collected
// - Data shared
// - Security practices
// - Data deletion capability

// 2. ✓ Permission Auto-Reset (Android 11+)
// Permissions automatically revoked if app unused for months
// Handle gracefully:
class PermissionAwareActivity : AppCompatActivity() {
    override fun onResume() {
        super.onResume()
        
        // Re-check permissions (may have been auto-reset)
        if (!hasRequiredPermissions()) {
            explainWhyPermissionsNeeded()
        }
    }
}

// 3. ✓ Scoped Storage (Android 10+)
// Use scoped storage instead of broad storage access
class PhotoUploader {
    fun uploadPhoto() {
        // ✓ Use photo picker - no permission needed
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "image/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        startActivityForResult(intent, PICK_PHOTO)
        
        // ✗ DON'T request READ_EXTERNAL_STORAGE for single photo
    }
}

// 4. ✓ Background Location Disclosure (Android 10+)
// If requesting background location, show disclosure:
class LocationPermissionHelper {
    fun requestBackgroundLocation() {
        // First, ensure foreground permission granted
        if (hasForegroundLocationPermission()) {
            // Show detailed explanation for background
            showBackgroundLocationRationale {
                // Request background location separately
                requestPermissions(
                    arrayOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION),
                    REQUEST_BACKGROUND_LOCATION
                )
            }
        }
    }
}

// 5. ✓ Advertising ID Best Practices
fun getAdvertisingId() {
    // Check user consent first
    if (!hasAdvertisingConsent()) {
        return null // Don't access advertising ID
    }
    
    // Use advertising ID only for advertising
    val adInfo = AdvertisingIdClient.getAdvertisingIdInfo(context)
    if (adInfo.isLimitAdTrackingEnabled) {
        // User opted out - don't use for tracking
        return null
    }
    
    return adInfo.id
}
```

---

## Prevention Checklist

### Design Phase
- [ ] Conducted privacy impact assessment
- [ ] Documented all data collection with justification
- [ ] Designed minimal permission strategy
- [ ] Planned user privacy controls
- [ ] Designed data retention policies
- [ ] Identified privacy-by-design alternatives (on-device processing)

### Implementation Phase
- [ ] Request only necessary permissions
- [ ] Implement contextual permission requests
- [ ] Add clear permission rationale dialogs
- [ ] Implement privacy-safe logging (no PII)
- [ ] Use anonymous analytics identifiers
- [ ] Implement data minimization throughout
- [ ] Use platform privacy APIs (Photo Picker, Scoped Storage)
- [ ] Sanitize all data sent to third parties
- [ ] Implement consent management system
- [ ] Add user data export functionality
- [ ] Add user data deletion functionality
- [ ] Configure SDKs with privacy settings

### Testing Phase
- [ ] Tested permission flows
- [ ] Verified no PII in logs
- [ ] Analyzed network traffic for privacy leaks
- [ ] Tested analytics consent mechanism
- [ ] Verified background location not collected (if not needed)
- [ ] Tested data deletion works completely
- [ ] Audited all third-party SDKs
- [ ] Validated privacy policy matches implementation

### Compliance Phase
- [ ] Completed App Store Privacy Nutrition Label
- [ ] Completed Google Play Data Safety section
- [ ] Privacy policy written and accessible
- [ ] GDPR compliance verified (if applicable)
- [ ] CCPA compliance verified (if applicable)
- [ ] COPPA compliance verified (if applicable)
- [ ] Documented data flows
- [ ] Obtained legal review

### Maintenance Phase
- [ ] Scheduled regular privacy audits
- [ ] Monitoring user privacy feedback
- [ ] Reviewing SDK updates for privacy changes
- [ ] Updating privacy policy when changes occur
- [ ] Training team on privacy best practices
- [ ] Tracking regulatory changes

---

## Conclusion

Implementing adequate privacy controls is not a one-time task but an ongoing commitment:

**Key Principles**:
1. **Minimize**: Collect only what you need
2. **Contextualize**: Request permissions when needed, not upfront
3. **Explain**: Be transparent about data usage
4. **Control**: Give users meaningful choices
5. **Protect**: Secure data you collect
6. **Delete**: Remove data when no longer needed
7. **Audit**: Regularly review privacy practices

**Privacy as Competitive Advantage**:
- Builds user trust and loyalty
- Reduces regulatory risk
- Enables premium positioning
- Attracts privacy-conscious users
- Future-proofs against regulations

**Remember**: Users trust you with their most personal information. Honor that trust with privacy-first design.

---

## Additional Resources

- [Apple Privacy Guidelines](https://developer.apple.com/privacy/)
- [Android Privacy Best Practices](https://developer.android.com/privacy/best-practices)
- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework)
- [GDPR Official Text](https://gdpr-info.eu/)
- [CCPA Regulations](https://oag.ca.gov/privacy/ccpa)

**Next Steps**: See [Examples](examples.md) for detailed code implementations and [Lab](lab/m06-privacy-controls-lab/) for hands-on practice.
