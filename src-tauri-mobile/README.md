# GaugeDesk Mobile

This workspace packages the existing Solid mobile projection client as the
native GaugeDesk application for Android and iOS.

The mobile shell is deliberately separate from `src-tauri/`:

- desktop starts a co-resident control plane;
- mobile never starts one and connects only to an admitted remote Machine;
- mobile owns the native webview, shared Android/iOS QR scanner, and deep-link
  intake, and is the boundary where notification and biometric integrations attach;
- project state, transcripts, commands, and authority remain on the selected
  Machine.

## Android development

Install the Tauri 2 Android prerequisites, then:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cd src-tauri-mobile
npm install
npm run android:init
npm run android:dev
```

`ANDROID_HOME`, `NDK_HOME`, and `JAVA_HOME` must point to the installed Android
SDK, side-by-side NDK, and JDK. The generated `gen/android` project is committed
after initialization so CI and other developers build the same native project.
Installing the SDK packages requires the developer to review and accept Google's
Android SDK licenses; that acceptance is host state and is not automated by this
repository.

The reproducible local smoke build is:

```sh
npm run tauri -- android build --debug --apk --target x86_64 --ci
```

The generated APK is written under
`gen/android/app/build/outputs/apk/universal/debug/`. The API 35 smoke test
installs it with `adb`, cold-launches `com.gaugewright.gaugedesk/.MainActivity`,
and verifies that the webview respects Android system-bar insets.

The full native acceptance gate reuses the same Maestro journey intended for
iOS and drives a real fake-agent Machine through HTTPS:

```sh
GW_MOBILE_E2E_BUILD=1 scripts/android-mobile-machine-e2e.sh
```

It requires a running writable-system Android emulator and the pinned Maestro
CLI. The script creates a throwaway TLS root, installs it only in that emulator,
then verifies invitation, native-key proof, owner approval, shared chat routes,
encrypted-credential restart, and immediate controller revocation. It then
resets only app data and runs the shared account journey: system-browser login,
two exact Homes, wrong-Home rejection, restart/offline cache isolation,
reference-only links, and durable sign-out.

## iOS development

iOS initialization and builds require macOS with Xcode and XcodeGen:

```sh
cd src-tauri-mobile
npm install
npm run ios:init
npm run ios:dev
```

The first-party device plugin uses a non-exportable Secure Enclave P-256 key on
physical iPhones and keeps the opaque Machine credential in a non-synchronizing
`ThisDeviceOnly` Keychain item. The unsigned hosted Simulator cannot obtain the
Keychain entitlement, so only that compilation target uses a test-only CryptoKit
P-256 key and install-local `UserDefaults` credential. That branch is excluded
from physical iPhones. Both targets expose the same six-command adapter as
Android.

The complete Simulator acceptance gate generates the pinned Xcode wrapper when
needed and reuses Android's Machine coordinator and Maestro flow:

```sh
GW_MOBILE_E2E_BUILD=1 scripts/ios-mobile-machine-e2e.sh
```

It creates and deletes a dedicated Simulator, installs a throwaway TLS root,
then verifies invitation, native-key proof, owner approval, shared chat routes,
restart recovery, and immediate controller revocation, followed by the same
account/two-Home/offline/link/sign-out journey as Android.

Native release signing remains separate from source. Certificates,
provisioning profiles, keystore files, and passwords never enter Git.

## Release packaging

`.github/workflows/mobile-release.yml` builds a signed Android App Bundle and a
signed iOS archive from protected CI inputs. Android release signing reads the
ignored `gen/android/keystore.properties`; its upload key is backed up in the
operator secret store and injected only on the ephemeral runner. The workflow
verifies the AAB's signer fingerprint before publishing the artifact.

iOS uses Xcode automatic signing with an App Store Connect API key and the
non-secret Apple development team variable. The release gate extracts the IPA
and verifies its Apple Distribution authority, team identifier, application
identifier, release entitlements, and embedded provisioning profile before
publishing it. It can upload the resulting IPA to TestFlight when explicitly
requested. App Store/Play metadata and each store's first app record remain
account-console operations; no signing material is committed.
