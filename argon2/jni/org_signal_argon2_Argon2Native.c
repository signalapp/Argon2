#include <stdio.h>
#include <string.h>
#include "org_signal_argon2_Argon2Native.h"
#include "argon2.h"

#define ENCODED_LEN 512

JNIEXPORT jint JNICALL Java_org_signal_argon2_Argon2Native_hash
  (JNIEnv *env,
   jclass clazz,
   jint t,
   jint m,
   jint parallelism,
   jbyteArray jPwd,
   jbyteArray jSalt,
   jbyteArray jHash,
   jobject jEncoded,
   jint argon_type,
   jint version)
{
  jsize  pwd_size     = (*env)->GetArrayLength(env, jPwd);
  jsize  salt_size    = (*env)->GetArrayLength(env, jSalt);
  jsize  outLen       = (*env)->GetArrayLength(env, jHash);
  jbyte* pwdElements  = (*env)->GetByteArrayElements(env, jPwd, NULL);
  jbyte* saltElements = (*env)->GetByteArrayElements(env, jSalt, NULL);

  unsigned char out[outLen];
           char encoded[ENCODED_LEN];

  int ret = argon2_hash(t, m, parallelism,
                        pwdElements, pwd_size,
                        saltElements, salt_size,
                        out, outLen,
                        encoded, ENCODED_LEN,
                        argon_type,
                        version);

  (*env)->ReleaseByteArrayElements(env, jPwd, pwdElements, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, jSalt, saltElements, JNI_ABORT);

  if (ret == ARGON2_OK) {
    (*env)->SetByteArrayRegion(env, jHash, 0, outLen, (jbyte *)out);

    jclass    stringBufferClass = (*env)->GetObjectClass(env, jEncoded);
    jmethodID appendMethod      = (*env)->GetMethodID(env, stringBufferClass, "append", "(Ljava/lang/String;)Ljava/lang/StringBuffer;");
    (*env)->CallObjectMethod(env, jEncoded, appendMethod, (*env)->NewStringUTF(env, encoded));
  }

  return ret;
}

JNIEXPORT jint JNICALL Java_org_signal_argon2_Argon2Native_verify
  (JNIEnv *env, jclass clazz, jstring jEncoded, jbyteArray jPwd, jint argon_type)
{
  const char  *encoded  = (*env)->GetStringUTFChars(env, jEncoded, NULL);
        jsize  pwd_size = (*env)->GetArrayLength(env, jPwd);
        jbyte *pwd      = (*env)->GetByteArrayElements(env, jPwd, NULL);

  int ret = argon2_verify((char *)encoded, pwd, pwd_size, argon_type);

  (*env)->ReleaseByteArrayElements(env, jPwd, pwd, JNI_ABORT);
  (*env)->ReleaseStringUTFChars(env, jEncoded, encoded);

  return ret;
}

JNIEXPORT jstring JNICALL Java_org_signal_argon2_Argon2Native_resultToString
  (JNIEnv *env, jclass clazz, jint argonResult)
{
  return (*env)->NewStringUTF(env, argon2_error_message(argonResult));
}
