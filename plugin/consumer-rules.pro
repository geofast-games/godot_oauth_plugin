# Keep the Godot plugin entry class and all @UsedByGodot-annotated methods —
# Godot invokes them reflectively at runtime.
-keep class org.godotengine.plugin.android.oauth2.GodotAndroidPlugin {
    @org.godotengine.godot.plugin.UsedByGodot <methods>;
    public <init>(org.godotengine.godot.Godot);
}

# Keep the @UsedByGodot annotation itself so R8 can still recognise it
# in keep rules at consumer-app time.
-keep @interface org.godotengine.godot.plugin.UsedByGodot

# Keep the Credential Manager + Google ID token classes the plugin reflects
# into via CustomCredential.type / GoogleIdTokenCredential.createFrom.
-keep class com.google.android.libraries.identity.googleid.** { *; }
-keep class androidx.credentials.** { *; }
