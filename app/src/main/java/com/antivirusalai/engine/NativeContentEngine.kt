package com.antivirusalai.engine
object NativeContentEngine {
 const val RULE_SET_ID="builtin-selftest-only-v1"
 const val SELF_TEST_RULE_ID="ALAI-NATIVE-ENGINE-SELFTEST"
 const val SELF_TEST_MARKER="ALAI_ENGINE_SELFTEST_MARKER_V1"
 private const val MAX_RULES=512
 private val libraryLoaded:Boolean=try{System.loadLibrary("alai_scan_engine");true}catch(_:LinkageError){false}catch(_:SecurityException){false}
 fun openSession(rules:List<ContentSignatureRule> = emptyList()):Session?{
  if(!libraryLoaded||rules.size>=MAX_RULES)return null
  val h=try{nativeCreate()}catch(_:LinkageError){0L};if(h==0L)return null
  val s=Session(h);return try{s.addRule(SELF_TEST_RULE_ID,SELF_TEST_MARKER.toByteArray(Charsets.US_ASCII));rules.forEach{s.addRule(it.id,it.pattern)};s}catch(_:Exception){s.close();null}catch(_:LinkageError){s.close();null}
 }
 class Session internal constructor(private var handle:Long):AutoCloseable{
  fun addRule(id:String,pattern:ByteArray){check(handle!=0L);require(id.matches(Regex("[A-Za-z0-9._-]{1,64}")));require(pattern.size in 4..256);check(NativeContentEngine.nativeAddRule(handle,id,pattern)){"Native scanner rejected a content rule."}}
  fun update(buffer:ByteArray,length:Int){check(handle!=0L);require(length in 0..buffer.size);check(NativeContentEngine.nativeUpdate(handle,buffer,length)){"Native scanner rejected input."}}
  fun finish():Set<String>{check(handle!=0L);return NativeContentEngine.nativeFinish(handle)?.toSet().orEmpty()}
  override fun close(){val h=handle;if(h!=0L){handle=0L;NativeContentEngine.nativeDestroy(h)}}
 }
 private external fun nativeCreate():Long
 private external fun nativeAddRule(handle:Long,id:String,pattern:ByteArray):Boolean
 private external fun nativeUpdate(handle:Long,buffer:ByteArray,length:Int):Boolean
 private external fun nativeFinish(handle:Long):Array<String>?
 private external fun nativeDestroy(handle:Long)
}
