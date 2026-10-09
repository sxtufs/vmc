
-keep class com.vmp.packer.MainActivity { *; }
-keep class * extends android.app.Application { *; }
-keep class * extends android.content.BroadcastReceiver { *; }
-keep class * extends android.content.ContentProvider { *; }
-keep public class * extends android.view.View { *; }
-keep public class * extends androidx.appcompat.widget.SearchView

-keep class androidx.** { *; }
-keep class com.google.android.material.** { *; }
-keep class kotlinx.coroutines.** { *; }
-keep interface kotlinx.coroutines.internal.MainDispatcherFactory { *; }
-keepclassmembers class kotlinx.coroutines.android.** { *; }

-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.**
-dontwarn java.lang.management.**

-keep class com.android.tools.smali.** { *; }

-keep class com.android.apksig.** { *; }
-dontwarn com.android.apksig.**

-keep class kotlin.Metadata { *; }
-keepattributes Signature,InnerClasses,EnclosingMethod,*Annotation*

