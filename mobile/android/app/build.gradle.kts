plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.meshgate.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.meshgate.app"
        minSdk = 26
        targetSdk = 35
        // CI passes -PversionName=1.2.3 -PversionCode=N from the git tag.
        versionCode = (project.findProperty("versionCode") as String?)?.toInt() ?: 1
        versionName = (project.findProperty("versionName") as String?) ?: "0.1.0-dev"
    }

    // Release signing comes from environment variables (GitHub secrets):
    // MESHGATE_KEYSTORE (path), MESHGATE_KEYSTORE_PASSWORD, MESHGATE_KEY_ALIAS,
    // MESHGATE_KEY_PASSWORD. Without them release builds use the debug key so
    // the APK still installs.
    val keystore = System.getenv("MESHGATE_KEYSTORE")?.let { file(it) }?.takeIf { it.exists() }
    signingConfigs {
        if (keystore != null) {
            create("release") {
                storeFile = keystore
                storePassword = System.getenv("MESHGATE_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("MESHGATE_KEY_ALIAS")
                keyPassword = System.getenv("MESHGATE_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (keystore != null) signingConfigs.getByName("release") else signingConfigs.getByName("debug")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    // Built by `make android-core` (gomobile bind) from ../../core
    implementation(files("libs/meshcore.aar"))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
