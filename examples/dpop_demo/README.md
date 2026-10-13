# IBM Verify DPoP Sample App for Android

This folder contains an Android sample app used to demonstrate configuring DPoP (Demonstrating Proof-of-Possession) flows with IBM Verify. It requests a DPoP-bound access token from an IBM Verify tenant and sends it, together with a DPoP proof, to a resource server for validation.

They are supporting assets for articles published on [IBM Verify Docs](https://docs.verify.ibm.com/verify) or on IBM Verify community blogs.

See the [DPoP Usage Guide](../../sdk/authentication/DPOP_USAGE.md) for details on the SDK API.

## Getting started

1. Clone this repository and open it in Android Studio.
1. In [`MainActivity.kt`](src/main/java/com/ibm/security/verifysdk/dpop/demoapp/MainActivity.kt), replace the placeholder values for your IBM Verify tenant:
   - `tenant` - the tenant host name, without protocol
   - `clientId` and `clientSecret` - an API client that is allowed to use the `client_credentials` grant
1. Optionally change `resourceServer` and `resourceServerPort`. The defaults (`10.0.2.2:8080`) point at a server running on the host machine of the Android emulator and expose a `/validate-token` endpoint.
1. Create a "Run/Debug configuration" for the `dpop_demo` module and start it.
1. Tap **Request DPoP Token** to request an access token with a DPoP proof.
1. Tap **Validate DPoP Token** to call the resource server with the token and a new DPoP proof.

> **Note:** Do not commit your client secret. This sample keeps it in source code for simplicity only.

## License

This package contains code licensed under the MIT License (the "License"). You may view the License in the [LICENSE](../../LICENSE) file within this package.
