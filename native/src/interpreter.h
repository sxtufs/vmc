#ifndef INTERPRETER_H
#define INTERPRETER_H

#include <jni.h>
#include <stdint.h>
#include <atomic>
#include "vmp_file.h"

/**
 * Result of a single interpreted method execution: a jvalue plus a flag
 * telling the caller whether an exception is pending (thrown but not caught).
 */
struct VmResult {
    jvalue value;
    bool exception = false;
};

/**
 * Interprets a virtualized method.
 *
 * @param self the `this` object (null for static methods)
 * @param args the argument array (jvalue), length = m->ins (`this` at args[0]
 *             for non-static methods)
 * @return the return value; if VmResult.exception is true, a Java exception is
 *         pending on the thread
 */
VmResult vmInterpret(JNIEnv *env, jobject self, VmpFile *file,
                     const VmMethod *m, const jvalue *args, bool isStatic);

/**
 * Set debug mode from the packer-side flag. It sets the two BUDGETED checks -
 * per-argument and read-side - and, through vmp.cpp, the instruction trace.
 * The WRITE-side checks (iput receiver/value, object return) are permanent and
 * unbudgeted: a miss there corrupts an unrelated live object silently. Called
 * by vmpInitVMImpl(); the anti-instrumentation watcher re-asserts false, which
 * is also why these flags are atomic.
 */
void vmpSetInterpDebug(bool debug);

/** Master debug flag: set at init, read by the diagnostics in interpreter.cpp.
 *  Atomic because the watcher thread can clear it while interpreted code is
 *  reading it. Gated diagnostics (iface-dispatch, null-result trace) skip
 *  entirely when false. */
extern std::atomic<bool> g_vmpDebug;

/**
 * Interpreter nesting guard, owned by vmp.cpp where the depth counter lives.
 * doInvoke() calls vmInterpret() directly for a non-virtual call into another
 * virtualized method; that path never passes through a vmpHandlerCore clone and
 * so bypasses the check there. vmpInterpEnter() returns false once the cap is
 * reached - the caller must then throw a catchable StackOverflowError.
 */
bool vmpInterpEnter(void);
void vmpInterpLeave(void);

#endif