package com.vmp.packer

/**
 * The stateless vocabulary of virtualization: which class prefixes are
 * third-party, which names ART calls during attach, and what counts as a
 * Context-wrapper factory.
 *
 * The per-input DECISIONS - whitelist, '!' exclusions, <clinit> closure, size
 * floor - are a value now: PackPolicy, derived per pack and carried by
 * DexParser. Every virtualized body runs through JNI, so interpreting library
 * internals replaces one ART call with dozens of round trips, and a prefix
 * blacklist cannot catch that in an R8-renamed app - hence whitelist-first, and
 * the legacy blacklist here applies only when nothing could be derived.
 */
object VirtualizationPolicy {

    val LIBRARY_PREFIXES = listOf(
        "androidx/",
        "android/",
        "com/android/",
        "java/",
        "javax/",
        "kotlin/",
        "kotlinx/",
        "dalvik/",
        "sun/",
        "org/json/",
        "org/apache/"
    )

    /**
     * SDK roots that survive R8 un-renamed, so [LIBRARY_PREFIXES] misses them.
     * The legacy fallback must never virtualize bundled third-party code.
     */
    val KNOWN_SDK_PREFIXES = listOf(
        "com/google/",
        "com/microsoft/",
        "com/jg/",
        "com/liulishuo/",
        "com/facebook/",
        "com/reactnativecommunity/",
        "com/swmansion/",
        "com/revenuecat/",
        "com/amazon/device/",
        "com/bugsnag/",
        "com/getsentry/",
        "io/invertase/",
        "io/branch/",
        "expo/",
        "org/unimodules/",
        "org/chromium/",
        "com/bytedance/",
        "com/byted/",
        "com/ss/android/",
        "com/qq/e/",
        "com/mbridge/",
        "com/applovin/",
        "com/vungle/",
        "com/tp/adx/",
        "com/tradplus/",
        "com/kwad/",
        "sg/bigo/",
        "com/alipay/",
        "com/journeyapps/",
        "rikka/",
        "com/kuaishou/",
        "com/ironsrc/",
        "com/unity3d/ads/",
        "com/unity/ads/",
        "com/facebook/ads/",
        "com/inmobi/",
        "com/adjoe/",
        "com/chartboost/",
        "com/mopub/",
        "com/adcolony/",
        "com/appodeal/",
        "com/startapp/",
        "com/tapjoy/",
        "com/fyber/",
        "com/ironsource/"
    )

    /**
     * True for library/framework classes that must NOT be virtualized, because
     * ART calls their methods at boot time before our loader initializes the VM
     * (e.g. androidx.core.app.CoreComponentFactory, androidx.startup
     * InitializationProvider). Virtualizing them makes them native with no
     * registered implementation -> UnsatisfiedLinkError at startup.
     */
    fun isLibraryClass(desc: String): Boolean {
        val name = if (desc.length >= 2 && desc[0] == 'L' && desc[desc.length - 1] == ';')
            desc.substring(1, desc.length - 1) else desc
        return LIBRARY_PREFIXES.any { name.startsWith(it) } ||
                KNOWN_SDK_PREFIXES.any { name.startsWith(it) }
    }

    /**
     * True for well-known library/SDK package paths that manifest
     * components may reference (androidx.startup.InitializationProvider,
     * androidx.profileinstaller.ProfileInstallReceiver, ...). Such components
     * must never seed the whitelist: they run as real framework code before
     * (or without) the loader's initVM.
     */
    fun isLibraryPackagePath(path: String): Boolean =
        LIBRARY_PREFIXES.any { path.startsWith(it) } ||
                KNOWN_SDK_PREFIXES.any { path.startsWith(it) }

    /**
     * Names ART calls during Activity/Application attach. attachBaseContext
     * sets ContextWrapper's mBase: virtualize it and the framework NPEs on
     * getApplicationInfo(). It is also where initVM itself is injected.
     */
    private val FRAMEWORK_CRITICAL_METHODS = setOf("attachBaseContext")

    fun isFrameworkCriticalMethod(name: String): Boolean =
        FRAMEWORK_CRITICAL_METHODS.contains(name)

    /**
     * Context factories (Context -> Context). App code calls them from
     * attachBaseContext; interpreting one can return a wrapper whose mBase was
     * never set, and the framework then NPEs on the Activity's base context.
     */
    fun isContextWrapperMethod(paramTypesConcat: String, returnType: String): Boolean =
        paramTypesConcat.contains("Landroid/content/Context;") &&
                returnType.startsWith("Landroid/content/Context")

}
