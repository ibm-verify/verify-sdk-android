# Push Notification Setup Guide for MFA Demo App

This guide explains how to configure push notifications for the MFA Demo app using Firebase Cloud Messaging (FCM) and IBM Verify.

## Prerequisites

- An IBM Verify tenant
- A Firebase project with Firebase Cloud Messaging enabled
- The MFA Demo app installed on an Android device

---

## IBM Verify (Server) Configuration

### 1. Create a Firebase Project

1. Go to the [Firebase Console](https://console.firebase.google.com/)
2. Create a new project or select an existing one
3. Enable **Firebase Cloud Messaging** for your project

### 2. Download the Service Account File

Download the Firebase service account JSON file as described in the [Firebase Admin SDK setup documentation](https://firebase.google.com/docs/admin/setup#initialize_the_sdk_in_non-google_environments).

This file contains the credentials needed for IBM Verify to send push notifications via Firebase.

### 3. Create an API Client

Create an API client in IBM Verify to upload the service account file:

1. Navigate to: `https://<your-tenant>/ui/admin/security/api-access/`
2. Create a new API client with the following entitlements:
   - **Manage push notification credentials**
   - **Read push notification credentials**

> **Note:** The API client is only needed to upload the service account file and can be disabled or removed afterwards.

### 4. Get an Access Token

Obtain an access token for the API client:

```bash
curl --request POST \
  --url https://<your-tenant>/v1.0/endpoint/default/token \
  --header 'accept: application/json' \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data client_id=<your-client-id> \
  --data client_secret=<your-client-secret> \
  --data grant_type=client_credentials
```

Replace:
- `<your-tenant>` with your IBM Verify tenant URL
- `<your-client-id>` with your API client ID
- `<your-client-secret>` with your API client secret

### 5. Upload the Service Account File

Upload the content of the service account JSON file to IBM Verify:

```bash
curl --request POST \
  --url https://<your-tenant>/config/v1.0/push-notification/credentials \
  --header 'accept: application/json' \
  --header 'authorization: Bearer <your-access-token>' \
  --header 'content-type: application/json' \
  --data '{
  "firebasePushConfig": {
    "productionCreds": {
      "serviceAccountJSON": {
        "type": "service_account",
        "project_id": "...",
        "private_key_id": "....",
        "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
        "client_email": "...iam.gserviceaccount.com",
        "client_id": "...",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/...",
        "universe_domain": "googleapis.com"
      }
    }
  },
  "appId": "com.ibm.security.verifysdk.mfa.demoapp"
}'
```

Replace:
- `<your-tenant>` with your IBM Verify tenant URL
- `<your-access-token>` with the access token from step 4
- The `serviceAccountJSON` object with the content from your downloaded service account file
- Ensure the `appId` matches your app's package ID (default: `com.ibm.security.verifysdk.mfa.demoapp`)

> **Important:** Make sure to properly escape the private key with `\n` for newlines.

For more details, see the [IBM Verify API documentation](https://docs.verify.ibm.com/verify/reference/createpushcredentials).

### 6. Verify the Upload

Confirm that the credentials were uploaded successfully:

```bash
curl --request GET \
  --url https://<your-tenant>/config/v1.0/push-notification/credentials \
  --header 'accept: application/json' \
  --header 'authorization: Bearer <your-access-token>'
```

This should return the push notification credentials you just uploaded.

---

## MFA Demo App Configuration

### 1. Configure Firebase Cloud Messaging

1. In the [Firebase Console](https://console.firebase.google.com/), select your project
2. Go to **Project Settings** > **General**
3. Under **Your apps**, click **Add app** and select **Android**
4. Register your app with the package ID: `com.ibm.security.verifysdk.mfa.demoapp`
5. Download the `google-services.json` file
6. Place the `google-services.json` file in the `examples/mfa_demo/` root folder

> **Security Warning:** The `google-services.json` file contains sensitive data. Ensure it is **not checked into source control**. The demo app includes a `google-services.json` file with dummy data for reference only.

### 2. Grant Push Notification Permissions

On your Android device:

1. Open **Settings** > **Apps** > **MFA Demo**
2. Go to **Notifications**
3. Enable notifications for the app

---

## Testing Push Notifications

### 1. Register an Account

1. Open the MFA Demo app
2. Scan a QR code to register a new authenticator account
3. Complete the registration process

### 2. Trigger a Test Verification

1. In IBM Verify, trigger a "Test" verification for the registered account
2. Select the appropriate authentication method (e.g., fingerprint, face, user presence)
3. The push notification should appear on your device
4. Open the notification to approve or deny the verification

### Troubleshooting

If push notifications are not working, refer to [FIREBASE_TROUBLESHOOTING.md](./FIREBASE_TROUBLESHOOTING.md) for debugging steps and common issues.

---

## Additional Resources

- [Firebase Cloud Messaging Documentation](https://firebase.google.com/docs/cloud-messaging)
- [IBM Verify API Reference](https://docs.verify.ibm.com/verify/reference)
- [Firebase Admin SDK Setup](https://firebase.google.com/docs/admin/setup)