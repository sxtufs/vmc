VMPacker is an Android APK protection tool that virtualizes eligible DEX methods and executes them through a native runtime. It rebuilds and signs processed APKs with runtime integrity and signature verification.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

## Features

- **DEX Virtualization** — Moves eligible DEX method bodies into virtualized containers and replaces their original implementations with native stubs.
- **Native Runtime** — Executes virtualized methods through a native interpreter using JNI and libffi.
- **APK Integrity Verification** — Verifies APK signing data and content digests before initializing the virtual machine.
- **R8/ProGuard Mapping** — Supports mapping files to resolve original class and method names during method selection and preview.
- **Package and Class Preview** — Inspects candidate packages and classes and allows exclusions to be configured before packing.
- **Flexible Signing** — Supports generated signing identities, persistent named identities, and custom JKS signing keys.
- **Multiple ABIs** — Supports `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`.
- **Authenticated Containers** — Uses compression, cryptographic authentication, and other transformations to protect virtualized method data.

## How It Works

1. Select an input APK.
2. VMPacker analyzes the manifest and DEX files to identify eligible methods.
3. Selected methods are replaced with native stubs, while their virtualized implementations are stored in VMC containers.
4. The APK is rebuilt with the modified DEX files, container assets, and required native libraries.
5. The output APK is signed and verified before the operation is reported as successful.

Not every method is eligible for virtualization. Some methods remain ordinary ART/Dalvik code to preserve compatibility.

## Compatibility

| Feature | Support |
| --- | --- |
| APK input | Supported, subject to compatibility requirements |
| Android App Bundle (`.aab`) | Not supported |
| Split APK sets (`.apks`) | Not supported |
| R8/ProGuard mapping | Supported |
| Minimum Android API | 26 |
| Native ABIs | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |

The input APK must contain a binary `AndroidManifest.xml` and contiguous DEX files. Required native runtime libraries must be available for the supported ABIs.

The runtime verifier supports APK v2/v3 signature verification. APK v3.1 signing blocks and proof-of-rotation attributes are not currently supported.

## Usage

1. Open VMPacker and select an APK.
2. Optionally import the corresponding R8/ProGuard mapping file.
3. Scan and preview the candidate packages and classes.
4. Configure exclusions for items you do not want virtualized.
5. Select a generated signing identity or import a custom JKS key if needed.
6. Tap **PACK** to process the APK.
7. Check the application log for the output location.

The original APK signature is not preserved. VMPacker signs the rebuilt APK with the selected signing identity.

## Building from Source

### Requirements

- JDK 17
- Gradle 9.6.1
- Android SDK platform 36
- Android build-tools 36.0.0
- Android NDK `30.0.16248370`
- Python 3 and the required native build tools

The repository does not include a Gradle wrapper. The native runtime must be built separately, and its libraries must be placed in `app/src/main/assets/vmp/` before building the application.

Build the Android application with:

```bash
gradle --no-daemon assembleRelease
```

The resulting APK is unsigned. Refer to the native build scripts and GitHub Actions workflows for the complete build process.

## Limitations

- AAB and split APK processing are not supported.
- Only methods accepted by the current virtualization policy are processed.
- Certain DEX opcode families are intentionally excluded from virtualization.
- Missing native runtime libraries cause packing to fail.
- Backup behavior may remain platform-defined when the input manifest does not explicitly specify `android:allowBackup`.
- Protection does not prevent all static analysis, dynamic instrumentation, memory inspection, or reverse engineering.

## Third-Party Notices

VMPacker uses [miniz](https://github.com/richgel999/miniz), a lightweight compression library licensed under the MIT License.

## License

VMPacker is licensed under the [GNU General Public License v3.0](LICENSE).

VMPacker provides an additional layer of application protection, not a guarantee of complete security. Only process applications you have permission to modify and redistribute.