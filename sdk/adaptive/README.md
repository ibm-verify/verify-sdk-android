# IBM Verify Adaptive SDK for Android

**Version:** 3.2.0
**Package:** `com.ibm.security.verifysdk.adaptive`
**Minimum API:** 29 (Android 10.0)
**Target API:** 36 (Android 16)

The adaptive component provides device assessment. Based on cloud risk policies, authentication and authorization challenges can be evaluated.

## Recent Improvements (v3.2.0)

- **Modern Lifecycle APIs**: Migrated from deprecated `LifecycleObserver` with `@OnLifecycleEvent` to `DefaultLifecycleObserver` for better type safety and compile-time checking
- **Updated Dependencies**: Uses Core SDK 3.2.0 with improved networking and error handling
- **Thread Safety**: Benefits from thread-safe NetworkHelper singleton
- **Better Error Handling**: Structured exception handling from Core SDK
- **Performance**: Lazy logging and optimized networking from Core SDK improvements

## Getting started

### Prerequisites

- Install and configure the
[Proxy SDK](https://github.com/IBM-Verify/adaptive-proxy-sdk-javascript) on a Node server by running `npm install adaptive-proxy-sdk`

- Generate and download the Trusteer SDK via IBM Verify admin portal for the application.

See [On-board a native application](https://docs.verify.ibm.com/verify/docs/on-boarding-a-native-application)

### Integrating with your project

See [here](../../README.md#integrating-with-your-project)

### API documentation
The Adaptive component API can be reviewed [here](https://ibm-verify.github.io/android/adaptive/docs/).


### Trusteer configuration settings

To start a device collection analysis, you will need to initialise a `TrusteerCollectionService` structure.  This structure is part of the Trusteer zip you can obtain via your tenant configuration or via the [IBM Verify Developer Portal](https://www.ibm.com/docs/en/security-verify?topic=applications-accessing-security-verify-developer-portal).  Also included in the Trusteer zip will be your `vendorId`, `clientId` and `clientKey`. 


## Usage

### Start the collection service
To start the collection, an instance `TrusteerAdaptiveCollection` is assigned to  `AdaptiveContext.collectionService`.

```kotlin
/** The vendor collection to be assigned to [AdaptiveContext.collectionService]. */
val trusteerCollection = TrusteerAdaptiveCollection(
    vendorId = "<your_vendor_id>",
    clientId = "<your_client_id>",
    clientKey = "<your_client_key>"
)

AdaptiveContext.collectionService = trusteerCollection
AdaptiveContext.start(targetContext)
```

### Stop the collection service
```kotlin
// Stop the collection process.
AdaptiveContext.stop()
```

### Implementing AdaptiveDelegate

The `AdaptiveDelegate` protocol needs to be implemented in order to expose the `assessment`, `generate` and `evaluate` functions.

```kotlin
// Implementing the `AdaptiveDelegate` interface as a singleton
object Adaptive: AdaptiveDelegate {

  // Implement the `assessment` function
  override fun assessment(sessionId: String, evaluationContext: String, completion: (Result<AdaptiveResult>) -> Unit) {
    // Send a request to the server to perform risk assessment for the given session ID using the Proxy SDK.
  }

  // Implement the `generate` method
  override fun generate(factor: AssessmentFactor, transactionId: String, completion: (Result<OtpGenerateResult?>) -> Unit) {
    // Send a request to the server to generate a verification for the given `factor` using the Proxy SDK.
  }

  // Implement the `evaluate` method
  override fun evaluate(evaluation: FactorEvaluation, evaluationContext: String, completion: (Result<AdaptiveResult>) -> Unit) {
    // Send a request to the server to evaluate a verification for the given `FactorEvaluation` using the Proxy SDK.
  }
}
```

### Perform a risk assessment

The purpose of the `assessment` function is to initiate a risk assessment via the [Proxy SDK](https://github.com/IBM-Security/adaptive-sdk-javascript). The implementation of the `assessment` function should send a request to the Proxy SDK.

Upon receiving the request, the server should call the Proxy SDK's
[`assess`](https://github.com/IBM-Security/adaptive-sdk-javascript/tree/develop#assess-a-policy) method, and respond accordingly.

Once a successful response is received, it can be classified into one of `AllowAssessmentResult`, `DenyAssessmentResult`, or `RequiresAssessmentResult` structures.

```kotlin
  // Perform risk assessment
  Adaptive.assessment(AdaptiveContext.sessionId, evaluationContext = "profile") { result ->
    // Error during assessment
    result.onFailure { println("Error: ${it.message}") }

    // Successful assessment
    result.onSuccess {
      when(it) {
        is AllowAssessmentResult -> { /* `allow` result */ }
        is RequiresAssessmentResult -> { /* `requires` result */ }
        else -> { /* `deny` result */ }
      }
    }
  }
```

### Perform a factor generation

The `generate` function is to generate a `AssessmentFactor` verification via the [Proxy SDK](https://github.com/IBM-Security/adaptive-sdk-javascript).

The implementation of this function should send a request to a server using the Proxy SDK. Upon receiving the request, the server should call the Proxy SDK's [`generateEmailOTP`](https://github.com/IBM-Security/adaptive-sdk-javascript/tree/develop#generate-an-email-otp-verification) or [`generateSMSOTP`](https://github.com/IBM-Security/adaptive-sdk-javascript/tree/develop#generate-an-sms-otp-verification) methods. The method to call should correspond to a `AssessmentFactor` type of the factor property. Typically, the server will not respond after generating these verifications.

The currently supported `AssessmentFactor` for generation are `Factor.EMAIL_OTP` and `Factor.SMS_OTP`.

```kotlin
  // Create a `AssessmentFactor` instance
  val assessmentFactor = AllowedFactor(Factor.SMS_OTP)

  // Generate verification
  // (The `transactionId` is received from the `assessment` method on a `requires` status.)
  Adaptive.generate(assessmentFactor, transactionId) { result ->
    // Error during generation
    result.onFailure { println("Couldn't generate SMS OTP.") }

    // Successful generation
    result.onSuccess { /* SMS OTP successfully sent, correlation received. */ }
  }
```

### Perform a factor evaluation

The implementation of this function should send a request to a server using the Proxy SDK. Upon receiving the request, the server should call the Proxy SDK's [`evaluateUsernamePassword`](https://github.com/IBM-Security/adaptive-sdk-javascript/tree/develop#evaluate-a-username-password-verification)
or [`evaluateOTP`](https://github.com/IBM-Security/adaptive-sdk-javascript/tree/develop#evaluate-an-otp-verification)
methods, and respond accordingly. The method to call should depend on the instance of `FactorEvaluation` (either
`PasswordEvaluation` or `OneTimePasscodeEvaluation`.

Once a successful response is received, it can be classified into one of `AllowAssessmentResult`, `DenyAssessmentResult` or
`RequiresAssessmentResult` structures, to be passed in the `completion` function.

```kotlin
  // Create a `FactorEvaluation` instance
  // (The `transactionId` is received from the `assessment` method on a `requires` status.)
  val passwordEvaluation = PasswordEvaluation(transactionId = transactionId, username = "username", password = "password")

  // Evaluate a factor verification
  Adaptive.evaluate(passwordEvaluation, evaluationContext = "profile") { result ->
    // Error during evaluation
    result.onFailure { println("Couldn't evaluate username/password.") }

    // Successful evaluation
    result.onSuccess {
      when(it) {
        is AllowAssessmentResult -> { /* `allow` result */ }
        else -> { /* `deny` result */ }
      }
    }
  }
```

## License
This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
