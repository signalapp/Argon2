#include <stdio.h>
#include <string.h>
#include "org_signal_argon2_Argon2Native.h"
#include "argon2.h"

#define ENCODED_LEN 512

#define SIGNAL_ERROR_NULL_INPUT        -100
#define SIGNAL_ERROR_BUFFER_ALLOCATION -101
#define SIGNAL_ERROR_JNI_METHOD        -102

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
  if (jPwd  == NULL) return SIGNAL_ERROR_NULL_INPUT;
  if (jSalt == NULL) return SIGNAL_ERROR_NULL_INPUT;
  if (jHash == NULL) return SIGNAL_ERROR_NULL_INPUT;

  char encoded[ENCODED_LEN];

  jsize  pwd_size     = (*env)->GetArrayLength(env, jPwd);
  jsize  salt_size    = (*env)->GetArrayLength(env, jSalt);
  jsize  hash_size    = (*env)->GetArrayLength(env, jHash);

  jbyte* pwdElements  = NULL;
  jbyte* saltElements = NULL;
  jbyte* hashElements = NULL;

                            pwdElements  = (*env)->GetByteArrayElements(env, jPwd,  NULL);
  if (pwdElements  != NULL) saltElements = (*env)->GetByteArrayElements(env, jSalt, NULL);
  if (saltElements != NULL) hashElements = (*env)->GetByteArrayElements(env, jHash, NULL);

  int result = pwdElements == NULL || saltElements == NULL || hashElements == NULL
               ? SIGNAL_ERROR_BUFFER_ALLOCATION
               : argon2_hash(t, m, parallelism,
                             pwdElements,  pwd_size,
                             saltElements, salt_size,
                             hashElements, hash_size,
                             encoded, ENCODED_LEN,
                             argon_type,
                             version);

  if (result == ARGON2_OK && jEncoded != NULL) {
    jclass    stringBufferClass = (*env)->GetObjectClass(env, jEncoded);
    jmethodID appendMethod      = (*env)->GetMethodID(env, stringBufferClass, "append", "(Ljava/lang/String;)Ljava/lang/StringBuffer;");

    if (appendMethod == NULL) {
      result = SIGNAL_ERROR_JNI_METHOD;
    } else {
      (*env)->CallObjectMethod(env, jEncoded, appendMethod, (*env)->NewStringUTF(env, encoded));
    }
  }

  if (pwdElements  != NULL) (*env)->ReleaseByteArrayElements(env, jPwd,  pwdElements,  JNI_ABORT);
  if (saltElements != NULL) (*env)->ReleaseByteArrayElements(env, jSalt, saltElements, JNI_ABORT);
  if (hashElements != NULL) (*env)->ReleaseByteArrayElements(env, jHash, hashElements, result == ARGON2_OK ? 0 : JNI_ABORT);

  return result;
}

JNIEXPORT jint JNICALL Java_org_signal_argon2_Argon2Native_verify
  (JNIEnv *env, jclass clazz, jstring jEncoded, jbyteArray jPwd, jint argon_type)
{
  if (jEncoded == NULL) return SIGNAL_ERROR_NULL_INPUT;
  if (jPwd     == NULL) return SIGNAL_ERROR_NULL_INPUT;

  const char *encoded = NULL;

  jsize  pwd_size = (*env)->GetArrayLength(env, jPwd);
  jbyte *pwd      = (*env)->GetByteArrayElements(env, jPwd, NULL);

  if (pwd != NULL) encoded = (*env)->GetStringUTFChars(env, jEncoded, NULL);

  int result = pwd == NULL || encoded == NULL
               ? SIGNAL_ERROR_BUFFER_ALLOCATION
               : argon2_verify((char *)encoded, pwd, pwd_size, argon_type);

  if (pwd     != NULL) (*env)->ReleaseByteArrayElements(env, jPwd, pwd, JNI_ABORT);
  if (encoded != NULL) (*env)->ReleaseStringUTFChars(env, jEncoded, encoded);

  return result;
}

JNIEXPORT jstring JNICALL Java_org_signal_argon2_Argon2Native_resultToString
  (JNIEnv *env, jclass clazz, jint argonResult)
{
  const char *message;

  switch (argonResult) {
    case SIGNAL_ERROR_NULL_INPUT:        message = "Input parameter was NULL";         break;
    case SIGNAL_ERROR_BUFFER_ALLOCATION: message = "Failed to allocate input buffers"; break;
    case SIGNAL_ERROR_JNI_METHOD:        message = "Failed to find method";            break;
    default:                             message = argon2_error_message(argonResult);
  }

  return (*env)->NewStringUTF(env, message);
}
