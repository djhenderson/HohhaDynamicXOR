#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>

#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "HohhaDynamicXOR.h"
#include "cencoder.h"


// ==================================== Start of tests =================

#define TESTSTR1 "TÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!222TÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!frfrTÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!"
#define TESTSTR1_LEN strlen(TESTSTR1)

void CheckOptimizedVersion(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int DLen, OriginalPlainTextCheckSum, CheckSumReturnedFromEncryptor, CheckSumReturnedFromDecryptor;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint8_t PlainTextBuf[132000], Data[132000];
  unsigned long long int KeyCheckSum;
  uint64_t SaltData;

  printf("-------------------- TESTING OPTIMIZED VERSION FOR %u PARTICLES -------------------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  DLen = TESTSTR1_LEN;
  memcpy(Data, TESTSTR1, DLen);
  memcpy(PlainTextBuf, TESTSTR1, DLen);

  for (DLen = 0; DLen < TESTSTR1_LEN; DLen++)
  {
    PlainTextBuf[DLen] = (uint8_t)(DLen & 255);
    Data[DLen] = PlainTextBuf[DLen];
    OriginalPlainTextCheckSum = BufCheckSum(Data, DLen+1);
    SaltData=1234;
    CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data); // We encrypt with non-optimized version
    if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
    {
      printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from xorEncryptDecrypt\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
      exit(-1);
    }
    // Salt data changes with every encrypt decrypt!
    SaltData=1234;
    if (NumJumps == 2)
      CheckSumReturnedFromDecryptor = xorDecryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data);
    else if (NumJumps == 3)
      CheckSumReturnedFromDecryptor = xorDecryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data);
    else if (NumJumps == 4)
      CheckSumReturnedFromDecryptor = xorDecryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data);
    else exit(-1);

    if (OriginalPlainTextCheckSum != CheckSumReturnedFromDecryptor)
    {
      printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from HOP decyptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromDecryptor);
      exit(-1);
    }
    if (memcmp((char *)Data, (char *)PlainTextBuf, DLen+1) != 0)
    {
      printf("String: %s ... optimized version test result: FAILED!!!!\n----------------------------------------\n", Data);
      exit(-1);
    }
  }
  printf("xorEncryptDecryptHOP%u SUCCESSFUL!\n",NumJumps);
}

void Test1(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int DLen, OriginalPlainTextCheckSum, CheckSumReturnedFromEncryptor, CheckSumReturnedFromDecryptor;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint8_t Data[2048],Data2[2048];
  char *Base64EncodedKeyStr, *Base64CipherText;
  uint32_t KeyCheckSum;
  uint64_t OriginalSaltData, SaltData;


  GetRandomNumbers(SALT_SIZE, (uint8_t *)&OriginalSaltData); // Fill salt data with random numbers
  SaltData = OriginalSaltData;

  printf("----------- TEST 1: BASIC FUNCTIONALITY(%u Jumps) --------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  Base64EncodedKeyStr = Base64Encode((const char *)KeyBuf, RawKeyLen);
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);

  xorAnalyzeKey(KeyBuf);
  memset(&Data, 0, sizeof(Data));
  memset(&Data2, 0, sizeof(Data2));
  DLen = TESTSTR1_LEN;
  memcpy(Data, TESTSTR1, DLen);
  memcpy(Data2, TESTSTR1, DLen);
  OriginalPlainTextCheckSum = BufCheckSum(Data, DLen);
  CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data); // We encrypt with non-optimized version
  if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
  {
    printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from non-optimized encryptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
    exit(-1);
  } else printf("OriginalPlainTextCheckSum %llu = CheckSumReturnedFromEncryptor %llu :: SUCCESS!\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
  // Now let's encrypt with the optimized encryptor
  SaltData=OriginalSaltData;

  if (NumJumps == 2)
    CheckSumReturnedFromEncryptor = xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data2);
  else if (NumJumps == 3)
    CheckSumReturnedFromEncryptor = xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data2);
  else if (NumJumps == 4)
    CheckSumReturnedFromEncryptor = xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data2);
  else exit(-1);


  if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
  {
    printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from optimized encryptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
    exit(-1);
  } else printf("OriginalPlainTextCheckSum %llu = CheckSumReturnedFromOptimizedEncryptor %llu :: SUCCESS!\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
  if (memcmp((char *)Data, Data2, DLen) != 0)
  {
    printf("Non-optimized and optimized encryptor functions outputs are different! FAILED! FAILED!\n");
    exit(-1);
  }

  Base64CipherText = Base64Encode((const char *)Data, DLen);
  printf("Base64CipherText: %s\n", Base64CipherText);
  printf("\n\nDecryption process:\n\n");
  SaltData=OriginalSaltData;
  uint8_t *K = (uint8_t *)Base64Decode(Base64EncodedKeyStr);

  if (memcmp((char *)KeyBuf, (char *)K, RawKeyLen) != 0)
  {
    printf("Original key and base64 encoded and decoded keys are different!!!!!\n");
    exit(-1);
  }
  //CheckSumReturnedFromDecryptor = xorDecrypt(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);

  if (NumJumps == 2)
    CheckSumReturnedFromDecryptor = xorDecryptHOP2(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  else if (NumJumps == 3)
    CheckSumReturnedFromDecryptor = xorDecryptHOP3(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  else if (NumJumps == 4)
    CheckSumReturnedFromDecryptor = xorDecryptHOP4(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  else exit(-1);

  if (OriginalPlainTextCheckSum != CheckSumReturnedFromDecryptor)
  {
    printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from HOP decyptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromDecryptor);
    exit(-1);
  } else printf("OriginalPlainTextCheckSum %llu = CheckSumReturnedFromDecryptor %llu :: SUCCESS!\n",OriginalPlainTextCheckSum,CheckSumReturnedFromDecryptor);

  if (memcmp((char *)Data, TESTSTR1, DLen) == 0)
  {
    printf("String: %s ... Test1 result: SUCCESSFUL!!!!\n----------------------------------------\n", Data);
  }
  else {
    printf("String: %s ... Test1 result: FAILED!!!!\n----------------------------------------\n", Data);
    exit(-1);
  }
  //exit(-1);
}

void D1()
{
  int t;
  register uint8_t V=0;
  for (t=0;t<128;t++)
  {
    printf("%u ",V);
    V += t;
  }
}
char *GetBinStr(uint32_t val, char *ResBuf)
{
  char *p;
  unsigned int t;
  p = ResBuf;
  t = 0x80000000; // scan 32 bits
  for ( ; t > 0; t = t >> 1)
  {
    if (val & t)
      *p++ = '1';
    else *p++ = '0';
  }
  *p = 0;
  return ResBuf;
}

void CircularShiftTest()
{
  uint32_t t, Nn = (uint32_t)(0b10000000000000000000000000000010U);
  char Buf[256];
  printf("Circular shift left:\n");
  for (t=0; t<5; t++)
  {
    printf("%s\n", GetBinStr(Nn,Buf));
    Nn = ROL32_1(Nn);
  }
  printf("Circular shift right:\n");
  for (t=0; t<6; t++)
  {
    printf("%s\n", GetBinStr(Nn,Buf));
    Nn = ROR32_1(Nn);
  }
}

// ==================================== End of tests ===================

int main()
{
  uint32_t BodyLen = 128;

  //printf("CRC: %u\n", digital_crc32((uint8_t *)"Ismail", 7));
  //printf("CRC: %u\n", digital_crc32((uint8_t *)"Hasan", 5));
  //printf("CRC: %u\n", digital_crc32((uint8_t *)"Ismail", 7));

  Test1(2, BodyLen);
  //CreateVisualProofs();
//  exit(-1);

  //CircularShiftTest();
  //uint32_t TestSampleLength = 8192;
  //D1();
  Test1(2, BodyLen);
  Test1(3, BodyLen);
  Test1(4, BodyLen);
  //Test1(4, BodyLen);
  //Test1(5, BodyLen);

    //exit(-1);

  CheckOptimizedVersion(2, BodyLen);
  CheckOptimizedVersion(3, BodyLen);
  CheckOptimizedVersion(4, BodyLen);
  //CheckOptimizedVersion(5, BodyLen);

  return 0;
}
