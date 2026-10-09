package fixt

/**
 * CI fixture used by ci/FormatCheck.kt to build a representative DEX.
 * Covers packed and sparse switches, fill-array-data payloads, typed
 * try/catch/finally handlers, interface/virtual/static invokes, const-string
 * chains, long arithmetic, closures (indy), nested classes, and data classes.
 * It is not packaged with the app or executed; the checks consume it as parsed
 * data.
 */
interface Greeter { fun greet(name: String): String }

open class Base {
    open fun describe(): String = "base"
    var counter: Int = 0
}

class Named(val who: String) : Greeter {
    override fun greet(name: String): String = "hello $name from $who"
}

data class Point(val x: Int, val y: Int) {
    fun manhattan() = x + y
}

class TestSubject : Base(), Greeter {

    companion object Statics {
        @JvmStatic fun add(a: Int, b: Int): Int = a + b
        var shared: Long = 0L
    }

    private val table = intArrayOf(3, 1, 4, 1, 5, 9)
    private val flags = booleanArrayOf(true, false, true)
    private val chars = charArrayOf('a', 'b', 'c')
    private val longs = longArrayOf(1L, 2L, 3L, 4L)

    override fun greet(name: String): String = name + "!"

    fun packedSwitch(k: Int): Int = when (k) {
        1 -> 10
        2 -> 20
        3 -> 30
        4 -> 40
        else -> -1
    }

    fun sparseSwitch(k: Int): String = when (k) {
        100 -> "cent"
        7000 -> "grand"
        13, 17 -> "prime-ish"
        else -> "other"
    }

    fun loopAndMath(n: Int): Long {
        var acc = 0L
        var i = 0
        while (i < n) {
            acc += table[i % table.size] * 1_000_000L
            acc = (acc shl 1) ushr 1
            i++
        }
        shared = acc
        return acc + add(i, flags.size + chars.size)
    }

    fun risky(k: Int): String {
        val sb = StringBuilder()
        try {
            for (j in 0 until k) sb.append(sparseSwitch(j * 100))
            if (k > 4) throw IllegalStateException("too much")
        } catch (e: IllegalStateException) {
            sb.append("ISE:").append(e.message)
        } catch (e: Exception) {
            sb.append("E")
        } finally {
            sb.append('|').append(describe())
        }
        return sb.toString()
    }

    fun objects(names: List<String>): String {
        val g: Greeter = Named("sub")
        val parts = names.map { g.greet(it) + counter }
        counter++
        val p = Point(parts.size, parts.size * 2)
        return parts.joinToString(",") + "|" + p.manhattan() + p.copy(x = p.y).toString()
    }

    fun wide(x: Double): Float {
        var v = x
        v = v * 3.5 - 1.25
        val l = v.toLong()
        val i = l.toInt() xor (l ushr 32).toInt()
        return i.toFloat() / 3f
    }

    fun bytes(): ByteArray {
        val out = ByteArray(longs.size * 8)
        for (i in longs.indices) {
            val w = longs[i]
            for (b in 0 until 8) out[i * 8 + b] = (w ushr (b * 8)).toByte()
        }
        return out
    }

    fun multidimensional(): Array<IntArray> =
        arrayOf(intArrayOf(1, 2), intArrayOf(3, 4))
}
