#ifndef _HOHHADYNAMICXOR_C_
#define _HOHHADYNAMICXOR_C_

#define SALT_SIZE 8 //
#define MAX_NUM_JUMPS 64
#define FALSE (0U)
#define TRUE (!(FALSE))
#define VERBOSE

/* Function used to determine if V is unique among the first Pos elements
 * Used by the xorGetKey function to check particle length uniqueness
 */
#define MAX_BODY_SIZE 256 // DO NOT SET THIS LIMIT TO MORE THAN 256 BYTES! Or you must also change encryption&decryption code for key coverage

#define SP_NUM_JUMPS 0
#define SP_BODY_LEN 1
#define SP_SALT_DATA 3
#define SP_BODY (SP_SALT_DATA+SALT_SIZE)
#define GetBodyLen(K) (K[SP_BODY_LEN] + 256 * K[SP_BODY_LEN+1])
#define GetBodyPtr(K) (K + SP_BODY)
#define GetNumJumps(K) (K[SP_NUM_JUMPS])
#define xorComputeKeyBufLen(BodyLen) (SP_BODY+BodyLen)

#define xorComputeKeyCheckSum(K) digital_crc32(K, SP_BODY + GetBodyLen(K))

extern void GetRandomNumbers(uint32_t ByteCount, uint8_t *Buffer);

extern void xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf);
extern unsigned int digital_crc32(uint8_t *buf, size_t len);
extern void xorAnalyzeKey(uint8_t *K);

extern uint64_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
extern uint64_t xorDecrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
extern uint64_t xorEncryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
extern uint64_t xorDecryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
extern uint64_t xorEncryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
extern uint64_t xorDecryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
extern uint64_t xorEncryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
extern uint64_t xorDecryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);


static inline uint64_t BufCheckSum(uint8_t *Buf, uint64_t BufLen)
{
  uint64_t t, CheckSum = 0;

  for (t=0; t<BufLen; t++)
    CheckSum += Buf[t];
  return CheckSum;
}

// Standart C has not ROL or ROR function, but most modern cpus has instructions for circular shift operations
// This is a quick and dirty code for standart C versions and Intel Family cpu assembler optimized versions

#define GCC_INTEL_OPTIMIZED

static inline int ROL32_1(int v)
{
  #if defined(__GNUC__)
    #if defined(GCC_INTEL_OPTIMIZED)
      asm ("rol %0;" :"=r"(v) /* output */ :"0"(v) /* input */ );
      return v;
    #else
      return (((v) << 1) | ((v) >> 31));
    #endif
  #endif
}

static inline int ROR32_1(int v) {
  #if defined(__GNUC__)
    #if defined(GCC_INTEL_OPTIMIZED)
      asm ("ror %0;" :"=r"(v) /* output */ :"0"(v) /* input */ );
      return v;
    #else
      return (((v) >> 1) | ((v) << 31))
    #endif
  #endif
}

#endif // _HOHHADYNAMICXOR_C_
