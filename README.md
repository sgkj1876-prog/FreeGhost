# Free Ghost
Android APK static-analysis project designed to build from Termux/GitHub.

## Build in Termux
Install Java 17, Gradle and Android SDK command-line tools, set `ANDROID_HOME`, install platform 35 and build-tools 35.x, then:

```bash
git clone https://github.com/YOUR_USER/FreeGhost.git
cd FreeGhost
chmod +x gradlew
./gradlew assembleDebug
```

APK: `app/build/outputs/apk/debug/app-debug.apk`

## Features in this first APK prototype
- Arabic / English switch
- RTL / LTR
- APK picker using Android Storage Access Framework
- local ZIP inventory
- SHA-256
- DEX/native library counts
- Manifest/resources presence
- lightweight URL/text indicators
- explainable experimental confidence

The confidence score is intentionally evidence-based and capped; it is not a claim that an APK is malicious.
