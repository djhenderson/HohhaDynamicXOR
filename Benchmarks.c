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

// =================================== Start of Benchmark code =========

uint8_t *CreateDataBuf(size_t Size)
{
  return (uint8_t *)calloc(1, Size);
}

uint32_t GetElapsedTimeInMilliSeconds(struct timeval *StartTime)
{
  struct timeval Now;

  gettimeofday (&Now, NULL);
  return (Now.tv_sec - StartTime->tv_sec) * 1000 + (Now.tv_usec - StartTime->tv_usec) / 1000;
}

double PrintElapsedTime(struct timeval *StartTime, unsigned long long int TotalProcessedBytes)
{
  double TotalMBytes = ((double)TotalProcessedBytes/(1024.0*1024));
  unsigned EInMs = GetElapsedTimeInMilliSeconds(StartTime);
  double Average = TotalMBytes / (1.0 * EInMs) * 1000.0;
  printf("\n\tTotal data processed: %6.2f MBytes\n\tElapsed Time: %u ms.\n\tAverage: %10.4f MBytes/secs \n",TotalMBytes, EInMs, Average);
  return Average;
}

void IncByOne(uint8_t *Buf, uint32_t BufLen)
{
  unsigned t;
  for (t=0; t<BufLen; t++)
    Buf[t]++;
}

//#define xorEncryptDecrypt xorEncryptDecryptHOP5
/* Memcpy Benchmark1 :
 * This function
 *   Creates a N bytes random data buffer
 *   Creates another N bytes zero filled buffer (DestBuf)
 *   Starts an iteration
 *   For each iteration, increases every byte of the data by 1
 *   Copies the data buffer to DestBuf
 *   Prints the elapsed time
 */
double MemCpyBenchmark1(uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  uint8_t *DestBuf = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  unsigned t;

  /*printf("-------------------- MemCpyBenchmark1 1: BASIC FUNCTIONALITY -------------------------\n"
        "This function\n 1.Creates a %u bytes random data buffer\nCreates another buffer(DestBuf) with the same size\nMakes %u iteration\n"
         "For each iteration, increases every byte of the data by 1\nCopies the data buffer to DestBuf\nPrints the elapsed time",TestSampleLength,NumIterations);*/
  printf("MemCpyBenchmark1\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",TestSampleLength,NumIterations);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL);

  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    memcpy(DestBuf, Data, TestSampleLength);
    TotalProcessedBytes += TestSampleLength;
  }
  PrintElapsedTime(&StartTime,TotalProcessedBytes);
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(DestBuf);
  return Average;
}

/* Benchmark1 :
 * This function
 *   Creates a key with NumJumps particles and with a body length of BodyLen
 *   Creates a N bytes random zero filled buffer
 *   Starts an iteration of NumIterations times
 *   For each iteration, increases every byte of the data by 1
 *   Encrypts the data
 *   Prints the elapsed time
 */
double Benchmark1(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t,Salt;
  uint32_t KeyCheckSum;

  printf("Benchmark1\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);

  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL);

  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    Salt=1234;
    xorEncrypt(KeyBuf, (uint8_t *)(&Salt), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

double BenchmarkHOP2(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint32_t KeyCheckSum;
  uint32_t  SaltData=1245;

  printf("BenchmarkHop2\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);

  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL);

  BufCheckSum(Data, TestSampleLength);
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

double BenchmarkHOP3(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint32_t KeyCheckSum;
  uint64_t SaltData;

  printf("BenchmarkHop3\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);

  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL);

  BufCheckSum(Data, TestSampleLength);
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

double BenchmarkHOP4(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint32_t KeyCheckSum;
  uint64_t SaltData;

  printf("BenchmarkHop4\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);

  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL);

  BufCheckSum(Data, TestSampleLength);
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

// ===================================== End of Benchmark code =========

int main()
{
  uint32_t BodyLen = 128;
  uint32_t NumIterations = 1000000;
  double Average16M,Average64M,Average256M,Average1024M,Average8192M;
  double Average16H2,Average64H2,Average256H2,Average1024H2,Average8192H2;
  double Average16H3,Average64H3,Average256H3,Average1024H3,Average8192H3;
  double Average16H4,Average64H4,Average256H4,Average1024H4,Average8192H4;


  Average16M = MemCpyBenchmark1(16, NumIterations);
  Average64M = MemCpyBenchmark1(64, NumIterations);
  Average256M = MemCpyBenchmark1(256, NumIterations);
  Average1024M = MemCpyBenchmark1(1024, NumIterations);
  Average8192M = MemCpyBenchmark1(8192, NumIterations);
  /*
  double Average16,Average64,Average256,Average1024,Average8192;
  Average16 = Benchmark1(NumJumps, BodyLen, 16, NumIterations);
  Average64 = Benchmark1(NumJumps, BodyLen, 64, NumIterations);
  Average256 = Benchmark1(NumJumps, BodyLen, 256, NumIterations);
  Average1024 = Benchmark1(NumJumps, BodyLen, 1024, NumIterations);
  Average8192 = Benchmark1(NumJumps, BodyLen, 8192, NumIterations);
  printf("\n\nNON-HAND-OPTIMIZED VERSION BENCHMARKS:\n"
         "16                  64                  256                 1024                 8192\n"
         "------------------- ------------------- ------------------- -------------------- --------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16, Average64, Average256, Average1024, Average8192);
  */
  Average16H2 = BenchmarkHOP2(2, BodyLen, 16, NumIterations);
  Average64H2 = BenchmarkHOP2(2, BodyLen, 64, NumIterations);
  Average256H2 = BenchmarkHOP2(2, BodyLen, 256, NumIterations);
  Average1024H2 = BenchmarkHOP2(2, BodyLen, 1024, NumIterations);
  Average8192H2 = BenchmarkHOP2(2, BodyLen, 8192, NumIterations);

  Average16H3 = BenchmarkHOP3(3, BodyLen, 16, NumIterations);
  Average64H3 = BenchmarkHOP3(3, BodyLen, 64, NumIterations);
  Average256H3 = BenchmarkHOP3(3, BodyLen, 256, NumIterations);
  Average1024H3 = BenchmarkHOP3(3, BodyLen, 1024, NumIterations);
  Average8192H3 = BenchmarkHOP3(3, BodyLen, 8192, NumIterations);

  Average16H4 = BenchmarkHOP4(4, BodyLen, 16, NumIterations);
  Average64H4 = BenchmarkHOP4(4, BodyLen, 64, NumIterations);
  Average256H4 = BenchmarkHOP4(4, BodyLen, 256, NumIterations);
  Average1024H4 = BenchmarkHOP4(4, BodyLen, 1024, NumIterations);
  Average8192H4 = BenchmarkHOP4(4, BodyLen, 8192, NumIterations);

  printf("\n\nMemcpy BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16M, Average64M, Average256M, Average1024M, Average8192M);
  printf("\n\n2-Jumps BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H2, Average64H2, Average256H2, Average1024H2, Average8192H2);
  printf("\n\n3-Jumps BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H3, Average64H3, Average256H3, Average1024H3, Average8192H3);
  printf("\n\n4-Jumps BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H4, Average64H4, Average256H4, Average1024H4, Average8192H4);

  return 0;
}
