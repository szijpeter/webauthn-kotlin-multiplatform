# sample:compose-passkey-android

Android host app for the shared Compose passkey sample.

Use this sample when you want to run the shared Compose passkey demo on Android with the in-repo backend contract.

The host derives its WebAuthn origin from the installed APK's signing certificate
and passes the resulting `android:apk-key-hash:...` value to the shared sample.
When using the ngrok helper, ensure `ANDROID_SHA256` describes the same signing
certificate so the served Digital Asset Links statement matches the installed app.

Status: sample app, not published.
