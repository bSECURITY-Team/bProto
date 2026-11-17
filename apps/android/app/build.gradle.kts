// bProto Android client.
//
// The native side lives in `crates/vpn-ffi` (Rust, `--features jni`). Drop the
// output of `./build_app.sh --android` into `app/src/main/jniLibs` and Gradle
// packages it into the APK.

plugins {
    id("com.android.application") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "2.1.0"
}

// Credentials are supplied only to trusted release jobs. Debug builds need none.
// TODO(3.0 validation): run the trusted signing workflow with the real keystore
// and verify supported-device upgrades. Synthetic gate tests do not cover that.
val releaseStore = providers.environmentVariable("BPROTO_ANDROID_KEYSTORE").orNull
val releaseStorePassword = providers.environmentVariable("BPROTO_ANDROID_STORE_PASSWORD").orNull
val releaseAlias = providers.environmentVariable("BPROTO_ANDROID_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("BPROTO_ANDROID_KEY_PASSWORD").orNull
val releaseSigningAvailable = listOf(releaseStore, releaseStorePassword, releaseAlias, releaseKeyPassword)
    .all { !it.isNullOrBlank() }

gradle.taskGraph.whenReady {
    if (allTasks.any { it.name.contains("Release", ignoreCase = true) } && !releaseSigningAvailable) {
        throw GradleException("Release signing requires all four BPROTO_ANDROID signing environment variables")
    }
}

android {
    namespace = "dev.bproto.client"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.bproto.client"
        minSdk = 26
        targetSdk = 35
        versionCode = 20500
        versionName = "2.5.0"
        ndk {
            // Only the ABIs we build; cargo-ndk maps them in build_app.sh --android.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    signingConfigs {
        if (releaseSigningAvailable) {
            create("release") {
                storeFile = file(requireNotNull(releaseStore))
                storePassword = releaseStorePassword
                keyAlias = releaseAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release")
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        viewBinding = true
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
}
