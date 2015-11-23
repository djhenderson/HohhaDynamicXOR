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

/* =============== Start of visualization test code ==================*/

int64_t EncryptFile(const char *InFileName, const char *OutFileName, uint8_t *KeyBuf, uint32_t KeyCheckSum)
{
  int32_t FDesc;
  int64_t Len, RLen;
  uint8_t *Data;
  uint64_t CheckSum=0, SaltData;

  if ((FDesc = open(InFileName, O_RDONLY)) == -1)
  {
    fputs(InFileName, stderr);
    perror(" - Error in opening file!\n");
    return -1;
  }
  Len = lseek(FDesc, 0, SEEK_END);
  lseek(FDesc, 0, SEEK_SET);
  Data = (uint8_t *)malloc(Len);
  RLen = read(FDesc, Data, Len);
  if (RLen != Len)
  {
    fputs(InFileName, stderr);
    perror(" - Error in reading file! %s\n");
    return -1;
  }
  close(FDesc);

  //GetRandomNumbers(8, (uint8_t *)(&SaltData));
  // Copy key's original salt value to salt buffer
  memcpy(&SaltData, KeyBuf+SP_SALT_DATA, SALT_SIZE);
  if (GetNumJumps(KeyBuf) == 2)
    CheckSum = xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data);
  else if (GetNumJumps(KeyBuf) == 3)
    CheckSum = xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data);
  else if (GetNumJumps(KeyBuf) == 4)
    CheckSum = xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data);

  if ((FDesc = creat(OutFileName, 700)) == -1)
  {
    fputs(OutFileName, stderr);
    perror(" - Error in creating output file!\n");
    return -1;
  }
  write(FDesc,Data,Len);
  free(Data);
  close(FDesc);
  return CheckSum;
}

int64_t EncryptBMPFile(const char *InFileName, const char *OutFileName, uint8_t *KeyBuf, uint32_t KeyCheckSum)
{ // Encrypts a bmp file for visual attack
  int32_t FDesc;
  int64_t Len, RLen;
  uint8_t *Data;
  uint8_t OriginalHeader[255];
  uint64_t CheckSum=0, SaltData;

  if ((FDesc = open(InFileName, O_RDONLY)) == -1)
  {
    fputs(InFileName, stderr);
    perror(" - Error in opening file!\n");
    return -1;
  }
  Len = lseek(FDesc, 0, SEEK_END);
  if (lseek(FDesc, 0, SEEK_SET) != 0)
  {
    fputs(InFileName, stderr);
    perror(" - Error seeking to beginning of file!\n");
    return -1;
  }
  Data = (uint8_t *)malloc(Len);
  RLen = read(FDesc, Data, Len);
  if (RLen != Len)
  {
    fputs(InFileName, stderr);
    perror(" - Error in reading file!\n");
    return -1;
  }
  // Copy original header to a buffer
  memcpy(OriginalHeader, Data, 54);
  close(FDesc);

  //GetRandomNumbers(8, (uint8_t *)(&SaltData));
  // Copy key's original salt value to salt buffer
  memcpy(&SaltData, KeyBuf+SP_SALT_DATA, SALT_SIZE);
/*  if (GetNumJumps(KeyBuf) == 2)
    CheckSum = xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data);
  else if (GetNumJumps(KeyBuf) == 3)
    CheckSum = xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data);
  else if (GetNumJumps(KeyBuf) == 4)
    CheckSum = xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data);
  else {
    printf("Invalid number of jumps!\n");
    exit(-1);
  }*/
  CheckSum = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data);
  if ((FDesc = creat(OutFileName, 777)) == -1)
  {
    fputs(OutFileName, stderr);
    perror(" - Error in creating output file!\n");
    return -1;
  }
  // Copy original header to encrypted file in order to see it on a browser
  memcpy(Data, OriginalHeader, 54);
  if (write(FDesc,Data,Len) != Len)
  {
    fputs(OutFileName, stderr);
    perror(" - Error writing file!\n");
    return -1;
  }
  free(Data);
  close(FDesc);
  return CheckSum;
}

#ifndef IMAGE_SRC
#  define IMAGE_SRC /home/ikizir/Downloads
#endif


#define p(a,b) (a b)
#define SAMPLE_FILE_PATH p(IMAGE_SRC,"/panda.bmp")
  #define SAMPLE_OUT_FILE_PATH p(IMAGE_SRC,"/panda_enc.bmp")

void TestEncryptFile(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int ChkSum;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint32_t KeyCheckSum;
  char *Base64EncodedKeyStr;

  printf("----------- FILE ENC TEST(%u Jumps) --------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  Base64EncodedKeyStr = Base64Encode((const char *)KeyBuf, RawKeyLen);
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);
  xorAnalyzeKey(KeyBuf);
  ChkSum = EncryptFile(SAMPLE_FILE_PATH, SAMPLE_OUT_FILE_PATH, KeyBuf, KeyCheckSum);
  printf("Result: %llu\n", ChkSum);
  if( ChkSum == -1 ) exit(1);
}

void TestEncryptBMPFile(const char *InFileName, const char *OutFileName, unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int ChkSum;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint32_t KeyCheckSum;
  char *Base64EncodedKeyStr;

  printf("----------- FILE ENC TEST(%u Jumps) --------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  Base64EncodedKeyStr = Base64Encode((const char *)KeyBuf, RawKeyLen);
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);
  xorAnalyzeKey(KeyBuf);
  ChkSum = EncryptBMPFile(InFileName, OutFileName, KeyBuf, KeyCheckSum);
  printf("Result: %llu\n", ChkSum);
  if( ChkSum == -1 ) exit(1);
}

void CreateVisualProofs()
{
  TestEncryptBMPFile(p(IMAGE_SRC,"/panda.bmp"), p(IMAGE_SRC,"/panda_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(p(IMAGE_SRC,"/panda.bmp"), p(IMAGE_SRC,"/panda_enc_3J_64.bmp"), 3, 64);

  TestEncryptBMPFile(p(IMAGE_SRC,"/panda.bmp"), p(IMAGE_SRC,"/panda_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(p(IMAGE_SRC,"/panda.bmp"), p(IMAGE_SRC,"/panda_enc_3J_128.bmp"), 3, 128);

  TestEncryptBMPFile(p(IMAGE_SRC,"/panda.bmp"), p(IMAGE_SRC,"/panda_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(p(IMAGE_SRC,"/panda.bmp"), p(IMAGE_SRC,"/panda_enc_3J_256.bmp"), 3, 256);

  TestEncryptBMPFile(p(IMAGE_SRC,"/Bitmap1.bmp"), p(IMAGE_SRC,"/Bitmap1_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(p(IMAGE_SRC,"/Bitmap1.bmp"), p(IMAGE_SRC,"/Bitmap1_enc_3J_64.bmp"), 3, 64);

  TestEncryptBMPFile(p(IMAGE_SRC,"/Bitmap1.bmp"), p(IMAGE_SRC,"/Bitmap1_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(p(IMAGE_SRC,"/Bitmap1.bmp"), p(IMAGE_SRC,"/Bitmap1_enc_3J_128.bmp"), 3, 128);

  TestEncryptBMPFile(p(IMAGE_SRC,"/Bitmap1.bmp"), p(IMAGE_SRC,"/Bitmap1_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(p(IMAGE_SRC,"/Bitmap1.bmp"), p(IMAGE_SRC,"/Bitmap1_enc_3J_256.bmp"), 3, 256);

  TestEncryptBMPFile(p(IMAGE_SRC,"/Viking.bmp"), p(IMAGE_SRC,"/Viking_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(p(IMAGE_SRC,"/Viking.bmp"), p(IMAGE_SRC,"/Viking_enc_3J_64.bmp"), 3, 64);

  TestEncryptBMPFile(p(IMAGE_SRC,"/Viking.bmp"), p(IMAGE_SRC,"/Viking_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(p(IMAGE_SRC,"/Viking.bmp"), p(IMAGE_SRC,"/Viking_enc_3J_128.bmp"), 3, 128);

  TestEncryptBMPFile(p(IMAGE_SRC,"/Viking.bmp"), p(IMAGE_SRC,"/Viking_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(p(IMAGE_SRC,"/Viking.bmp"), p(IMAGE_SRC,"/Viking_enc_3J_256.bmp"), 3, 256);

  TestEncryptBMPFile(p(IMAGE_SRC,"/B.bmp"), p(IMAGE_SRC,"/B_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(p(IMAGE_SRC,"/B.bmp"), p(IMAGE_SRC,"/B_enc_3J_64.bmp"), 3, 64);

  TestEncryptBMPFile(p(IMAGE_SRC,"/B.bmp"), p(IMAGE_SRC,"/B_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(p(IMAGE_SRC,"/B.bmp"), p(IMAGE_SRC,"/B_enc_3J_128.bmp"), 3, 128);

  TestEncryptBMPFile(p(IMAGE_SRC,"/B.bmp"), p(IMAGE_SRC,"/B_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(p(IMAGE_SRC,"/B.bmp"), p(IMAGE_SRC,"/B_enc_3J_256.bmp"), 3, 256);




  TestEncryptBMPFile(p(IMAGE_SRC,"/penguen.bmp"), p(IMAGE_SRC,"/penguen_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(p(IMAGE_SRC,"/penguen.bmp"), p(IMAGE_SRC,"/penguen_enc_3J_64.bmp"), 3, 64);

  TestEncryptBMPFile(p(IMAGE_SRC,"/penguen.bmp"), p(IMAGE_SRC,"/penguen_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(p(IMAGE_SRC,"/penguen.bmp"), p(IMAGE_SRC,"/penguen_enc_3J_128.bmp"), 3, 128);

  TestEncryptBMPFile(p(IMAGE_SRC,"/penguen.bmp"), p(IMAGE_SRC,"/penguen_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(p(IMAGE_SRC,"/penguen.bmp"), p(IMAGE_SRC,"/penguen_enc_3J_256.bmp"), 3, 256);

}

/* ================= End of visualization test code ==================*/

int main()
{
  puts(IMAGE_SRC);
  puts(SAMPLE_FILE_PATH);
  CreateVisualProofs();
  return 0;
}
