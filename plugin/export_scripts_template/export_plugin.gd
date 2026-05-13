@tool
extends EditorPlugin

# A class member to hold the editor export plugin during its lifecycle.
var export_plugin: AndroidExportPlugin

func _enter_tree():
	# Initialization of the plugin goes here.
	export_plugin = AndroidExportPlugin.new()
	add_export_plugin(export_plugin)


func _exit_tree():
	# Clean-up of the plugin goes here.
	remove_export_plugin(export_plugin)
	export_plugin = null


class AndroidExportPlugin extends EditorExportPlugin:
	# TODO: Update to your plugin's name.
	var _plugin_name = "GodotAndroidOAuth2"

	func _supports_platform(platform):
		if platform is EditorExportPlatformAndroid:
			return true
		return false

	func _get_android_libraries(platform, debug):
		if debug:
			return PackedStringArray([_plugin_name + "/bin/debug/" + _plugin_name + "-debug.aar"])
		else:
			return PackedStringArray([_plugin_name + "/bin/release/" + _plugin_name + "-release.aar"])

	func _get_android_dependencies(platform, debug):
		# Dependencies matching build.gradle.kts - updated to latest stable versions
		# https://developer.android.com/identity/sign-in/credential-manager-siwg
		return PackedStringArray([
			"androidx.credentials:credentials:1.5.0",
			"androidx.credentials:credentials-play-services-auth:1.5.0",
			"com.google.android.libraries.identity.googleid:googleid:1.1.1",
			"org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3",
			"org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3",
			"androidx.lifecycle:lifecycle-runtime-ktx:2.7.0"
		])

	func _get_name():
		return _plugin_name
