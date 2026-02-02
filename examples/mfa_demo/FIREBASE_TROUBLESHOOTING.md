# Firebase Cloud Messaging Troubleshooting Guide

If the MFA Demo app is not receiving push notifications, follow this checklist to diagnose and fix the issue.

## 1. Verify Firebase Configuration

### Check google-services.json
- [ ] Ensure `google-services.json` exists in `examples/mfa_demo/` directory
- [ ] Verify the package name matches: `com.ibm.security.verifysdk.mfa.demoapp`
- [ ] Confirm the file contains valid Firebase project credentials


## 2. Check App Permissions

### Android 13+ (API 33+)
Push notifications require runtime permission on Android 13 and above.

**Check in app:**
1. Open the app
2. Look for notification permission prompt
3. Grant permission when asked

**Check in device settings:**
1. Go to **Settings > Apps > MFA Demo**
2. Tap **Notifications**
3. Ensure notifications are enabled

**Add permission request code if missing:**
```kotlin
// In MainActivity.onCreate()
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
        != PackageManager.PERMISSION_GRANTED) {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.POST_NOTIFICATIONS),
            REQUEST_NOTIFICATION_PERMISSION
        )
    }
}
```

## 3. Verify FCM Token Generation

### Check Logcat for Token
The FCM token should be logged when the app starts:

```bash
adb logcat | grep "FCM Token"
```

Expected output:
```
I/MainActivity: FCM Token: <long-token-string>
```

### If No Token Appears:
1. **Check Firebase initialization:**
   - Verify `google-services.json` is properly configured
   - Ensure Google Services plugin is applied in `build.gradle.kts`

2. **Check for errors:**
   ```bash
   adb logcat | grep -i "firebase\|fcm"
   ```

3. **Verify internet connection:**
   - Ensure device/emulator has internet access
   - FCM requires network connectivity to generate tokens

## 4. Test Firebase Service

### Verify Service Registration
Check if `MFAFirebaseMessagingService` is registered:

```bash
adb shell dumpsys package com.ibm.security.verifysdk.mfa.demoapp | grep -A 5 "Service"
```

Should show:
```
Service:
  com.ibm.security.verifysdk.mfa.demoapp.MFAFirebaseMessagingService
```

### Test with Firebase Console
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your project
3. Navigate to **Cloud Messaging**
4. Click **"Send your first message"**
5. Enter notification details
6. Click **"Send test message"**
7. Paste your FCM token
8. Click **"Test"**

## 5. Common Issues and Solutions

### Issue: "google-services.json not found"
**Solution:**
- Ensure file is in `examples/mfa_demo/` directory (not in `src/`)
- File name must be exactly `google-services.json` (case-sensitive)
- Rebuild project after adding the file

### Issue: "No FCM token generated"
**Solution:**
- Check internet connectivity
- Verify Firebase project is properly configured
- Ensure Google Services plugin is applied correctly
- Check for Firebase initialization errors in Logcat

### Issue: "Notifications not showing"
**Solution:**
- Grant notification permissions (Android 13+)
- Check notification channel is created (Android 8+)
- Verify app is not in battery optimization mode
- Check Do Not Disturb settings

### Issue: "Service not receiving messages"
**Solution:**
- Verify service is registered in AndroidManifest.xml
- Check intent filter is correct: `com.google.firebase.MESSAGING_EVENT`
- Ensure service is not exported (`android:exported="false"`)
- Verify package name matches in Firebase Console

### Issue: "Build fails with Google Services plugin error"
**Solution:**
- Ensure plugin is applied AFTER dependencies block
- Verify plugin version is compatible (4.4.0)
- Check that `google-services.json` is valid JSON

## 6. Debug Logging

### Enable Verbose Firebase Logging
Add to MainActivity.onCreate():
```kotlin
FirebaseMessaging.getInstance().isAutoInitEnabled = true
```

### Check All Firebase Logs
```bash
adb logcat -s FirebaseMessaging FirebaseInstanceId
```

### Monitor Notification Display
```bash
adb logcat | grep -i "notification"
```

## Additional Resources

- [Firebase Cloud Messaging Documentation](https://firebase.google.com/docs/cloud-messaging)
- [Android Notification Guide](https://developer.android.com/develop/ui/views/notifications)
- [Firebase Console](https://console.firebase.google.com/)
- [FCM Troubleshooting](https://firebase.google.com/docs/cloud-messaging/android/client#sample-play)