/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_signal_argon2_Argon2Native */

#ifndef _Included_org_signal_argon2_Argon2Native
#define _Included_org_signal_argon2_Argon2Native
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_signal_argon2_Argon2Native
 * Method:    runTests
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_org_signal_argon2_Argon2Native_runTests
  (JNIEnv *, jclass);

/*
 * Class:     org_signal_argon2_Argon2Native
 * Method:    argon2_hash
 * Signature: (III[B[B[BLjava/lang/StringBuffer;II)I
 */
JNIEXPORT jint JNICALL Java_org_signal_argon2_Argon2Native_argon2_1hash
  (JNIEnv *, jclass, jint, jint, jint, jbyteArray, jbyteArray, jbyteArray, jobject, jint, jint);

/*
 * Class:     org_signal_argon2_Argon2Native
 * Method:    argon2_verify
 * Signature: (Ljava/lang/String;[BI)I
 */
JNIEXPORT jint JNICALL Java_org_signal_argon2_Argon2Native_argon2_1verify
  (JNIEnv *, jclass, jstring, jbyteArray, jint);

/*
 * Class:     org_signal_argon2_Argon2Native
 * Method:    argon2_error_string
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_signal_argon2_Argon2Native_argon2_1error_1string
  (JNIEnv *, jclass, jint);

#ifdef __cplusplus
}
#endif
#endif
