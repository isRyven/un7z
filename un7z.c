/* Igor Pavlov : Public domain */

#include "un7z.h"

/* ^^^^^^^^^^^^^^ HEADERS ^^^^^^^^^^^^^^ */

#ifndef _WIN32
#ifdef __linux
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* For futimesat() */
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE  /* For utimes() in diet libc. */
#endif
#include <sys/time.h>
#endif
#endif

/* for mkdir */
#ifdef _WIN32
#include <direct.h>
#else
#include <fcntl.h>  /* open() */
#include <sys/stat.h>
#include <errno.h>
#include <utime.h>
#include <unistd.h>  /* symlink() */
#include <sys/time.h>  /* futimes() for uClibc */
#endif

#include <stdlib.h>
#include <string.h>

#if defined(_SZ_ALLOC_DEBUG) || defined(_SZ_SEEK_DEBUG) || defined(_SZ_HEADER_DEBUG) || defined(_SZ_READ_DEBUG) || defined(_SZ_CODER_DEBUG) || defined(_SZ_CHMODW_DEBUG)
#include <stdio.h>
#endif

#ifndef UNDER_CE
#include <errno.h>
#endif

/*
Conditions:
  outSize <= FullOutputSize,
  where FullOutputSize is full size of output stream of x86_2 filter.

If buf0 overlaps outBuf, there are two required conditions:
  1) (buf0 >= outBuf)
  2) (buf0 + size0 >= outBuf + FullOutputSize).

Returns:
  SZ_OK
  SZ_ERROR_DATA - Data error
*/

STATIC int Bcj2_Decode(
    const Byte *buf0, size_t size0,
    const Byte *buf1, size_t size1,
    const Byte *buf2, size_t size2,
    const Byte *buf3, size_t size3,
    Byte *outBuf, size_t outSize);

/*
These functions convert relative addresses to absolute addresses
in CALL instructions to increase the compression ratio.

  In:
    data     - data buffer
    size     - size of data
    ip       - current virtual Instruction Pinter (IP) value
    state    - state variable for x86 converter
    encoding - 0 (for decoding), 1 (for encoding)

  Out:
    state    - state variable for x86 converter

  Returns:
    The number of processed bytes. If you call these functions with multiple calls,
    you must start next call with first byte after block of processed bytes.

  Type   Endian  Alignment  LookAhead

  x86    little      1          4
  ARMT   little      2          2
  ARM    little      4          0
  PPC     big        4          0
  SPARC   big        4          0
  IA64   little     16          0

  size must be >= Alignment + LookAhead, if it's not last block.
  If (size < Alignment + LookAhead), converter returns 0.

  Example:

    UInt32 ip = 0;
    for ()
    {
      ; size must be >= Alignment + LookAhead, if it's not last block
      size_t processed = Convert(data, size, ip, 1);
      data += processed;
      size -= processed;
      ip += processed;
    }
*/

#define x86_Convert_Init(state) { state = 0; }
STATIC size_t x86_Convert(Byte *data, size_t size, UInt32 ip, UInt32 *state, int encoding);
STATIC size_t ARM_Convert(Byte *data, size_t size, UInt32 ip, int encoding);

/* ---------- LZMA Decoder state ---------- */

/* #define _LZMA_PROB32 */
/* _LZMA_PROB32 can increase the speed on some CPUs,
   but memory usage for CLzmaDec::probs will be doubled in that case */

#ifdef _LZMA_PROB32
#define CLzmaProb UInt32
#else
#define CLzmaProb UInt16
#endif


/* ---------- LZMA Properties ---------- */

#define LZMA_PROPS_SIZE 5

typedef struct _CLzmaProps
{
  unsigned lc, lp, pb;
  UInt32 dicSize;
} CLzmaProps;

/* LzmaProps_Decode - decodes properties
Returns:
  SZ_OK
  SZ_ERROR_UNSUPPORTED - Unsupported properties
*/

STATIC SRes LzmaProps_Decode(CLzmaProps *p, const Byte *data, unsigned size);

/* LZMA_REQUIRED_INPUT_MAX = number of required input bytes for worst case.
   Num bits = log2((2^11 / 31) ^ 22) + 26 < 134 + 26 = 160; */

#define LZMA_REQUIRED_INPUT_MAX 20

typedef struct
{
  CLzmaProps prop;
  CLzmaProb *probs;
  Byte *dic;
  const Byte *buf;
  UInt32 range, code;
  size_t dicPos;
  size_t dicBufSize;
  UInt32 processedPos;
  UInt32 checkDicSize;
  unsigned state;
  UInt32 reps[4];
  unsigned remainLen;
  int needFlush;
  int needInitState;
  UInt32 numProbs;
  unsigned tempBufSize;
  Byte tempBuf[LZMA_REQUIRED_INPUT_MAX];
} CLzmaDec;

#define LzmaDec_Construct(p) { (p)->dic = 0; (p)->probs = 0; }

STATIC void LzmaDec_Init(CLzmaDec *p);

/* There are two types of LZMA streams:
     0) Stream with end mark. That end mark adds about 6 bytes to compressed size.
     1) Stream without end mark. You must know exact uncompressed size to decompress such stream. */

typedef enum
{
  LZMA_FINISH_ANY,   /* finish at any point */
  LZMA_FINISH_END    /* block must be finished at the end */
} ELzmaFinishMode;

/* ELzmaFinishMode has meaning only if the decoding reaches output limit

   You must use LZMA_FINISH_END, when you know that current output buffer
   covers last bytes of block. In other cases you must use LZMA_FINISH_ANY.

   If LZMA decoder sees end marker before reaching output limit, it returns SZ_OK,
   and output value of destLen will be less than output buffer size limit.
   You can check status result also.

   You can use multiple checks to test data integrity after full decompression:
     1) Check Result and "status" variable.
     2) Check that output(destLen) = uncompressedSize, if you know real uncompressedSize.
     3) Check that output(srcLen) = compressedSize, if you know real compressedSize.
        You must use correct finish mode in that case. */

typedef enum
{
  LZMA_STATUS_NOT_SPECIFIED,               /* use main error code instead */
  LZMA_STATUS_FINISHED_WITH_MARK,          /* stream was finished with end mark. */
  LZMA_STATUS_NOT_FINISHED,                /* stream was not finished */
  LZMA_STATUS_NEEDS_MORE_INPUT,            /* you must provide more input bytes */
  LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK  /* there is probability that stream was finished without end mark */
} ELzmaStatus;

/* ELzmaStatus is used only as output value for function call */


/* ---------- Interfaces ---------- */

/* There are 3 levels of interfaces:
     1) Dictionary Interface
     2) Buffer Interface
     3) One Call Interface
   You can select any of these interfaces, but don't mix functions from different
   groups for same object. */


/* There are two variants to allocate state for Dictionary Interface:
     1) LzmaDec_Allocate / LzmaDec_Free
     2) LzmaDec_AllocateProbs / LzmaDec_FreeProbs
   You can use variant 2, if you set dictionary buffer manually.
   For Buffer Interface you must always use variant 1.

LzmaDec_Allocate* can return:
  SZ_OK
  SZ_ERROR_MEM         - Memory allocation error
  SZ_ERROR_UNSUPPORTED - Unsupported properties
*/

STATIC SRes LzmaDec_AllocateProbs(CLzmaDec *p, const Byte *props, unsigned propsSize);
STATIC void LzmaDec_FreeProbs(CLzmaDec *p);

/* ---------- Dictionary Interface ---------- */

/* You can use it, if you want to eliminate the overhead for data copying from
   dictionary to some other external buffer.
   You must work with CLzmaDec variables directly in this interface.

   STEPS:
     LzmaDec_Constr()
     LzmaDec_Allocate()
     for (each new stream)
     {
       LzmaDec_Init()
       while (it needs more decompression)
       {
         LzmaDec_DecodeToDic()
         use data from CLzmaDec::dic and update CLzmaDec::dicPos
       }
     }
     LzmaDec_Free()
*/

/* LzmaDec_DecodeToDic

   The decoding to internal dictionary buffer (CLzmaDec::dic).
   You must manually update CLzmaDec::dicPos, if it reaches CLzmaDec::dicBufSize

finishMode:
  It has meaning only if the decoding reaches output limit (dicLimit).
  LZMA_FINISH_ANY - Decode just dicLimit bytes.
  LZMA_FINISH_END - Stream must be finished after dicLimit.

Returns:
  SZ_OK
    status:
      LZMA_STATUS_FINISHED_WITH_MARK
      LZMA_STATUS_NOT_FINISHED
      LZMA_STATUS_NEEDS_MORE_INPUT
      LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK
  SZ_ERROR_DATA - Data error
*/

STATIC SRes LzmaDec_DecodeToDic(CLzmaDec *p, size_t dicLimit,
    const Byte *src, size_t *srcLen, ELzmaFinishMode finishMode, ELzmaStatus *status);


/* ---------- Buffer Interface ---------- */

/* It's zlib-like interface.
   See LzmaDec_DecodeToDic description for information about STEPS and return results,
   but you must use LzmaDec_DecodeToBuf instead of LzmaDec_DecodeToDic and you don't need
   to work with CLzmaDec variables manually.

finishMode:
  It has meaning only if the decoding reaches output limit (*destLen).
  LZMA_FINISH_ANY - Decode just destLen bytes.
  LZMA_FINISH_END - Stream must be finished after (*destLen).
*/

/* ---------- One Call Interface ---------- */

/* LzmaDecode

finishMode:
  It has meaning only if the decoding reaches output limit (*destLen).
  LZMA_FINISH_ANY - Decode just destLen bytes.
  LZMA_FINISH_END - Stream must be finished after (*destLen).

Returns:
  SZ_OK
    status:
      LZMA_STATUS_FINISHED_WITH_MARK
      LZMA_STATUS_NOT_FINISHED
      LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK
  SZ_ERROR_DATA - Data error
  SZ_ERROR_MEM  - Memory allocation error
  SZ_ERROR_UNSUPPORTED - Unsupported properties
  SZ_ERROR_INPUT_EOF - It needs more bytes in input buffer (src).
*/

/* ---------- LZMA2 State Interface ---------- */

typedef struct
{
  CLzmaDec decoder;
  UInt32 packSize;
  UInt32 unpackSize;
  int state;
  Byte control;
  Bool needInitDic;
  Bool needInitState;
  Bool needInitProp;
} CLzma2Dec;

#define Lzma2Dec_Construct(p) LzmaDec_Construct(&(p)->decoder)
#define Lzma2Dec_FreeProbs(p) LzmaDec_FreeProbs(&(p)->decoder);
#define Lzma2Dec_Free(p) LzmaDec_Free(&(p)->decoder);

STATIC SRes Lzma2Dec_AllocateProbs(CLzma2Dec *p, Byte prop);
STATIC void Lzma2Dec_Init(CLzma2Dec *p);


/*
finishMode:
  It has meaning only if the decoding reaches output limit (*destLen or dicLimit).
  LZMA_FINISH_ANY - use smallest number of input bytes
  LZMA_FINISH_END - read EndOfStream marker after decoding

Returns:
  SZ_OK
    status:
      LZMA_STATUS_FINISHED_WITH_MARK
      LZMA_STATUS_NOT_FINISHED
      LZMA_STATUS_NEEDS_MORE_INPUT
  SZ_ERROR_DATA - Data error
*/

STATIC SRes Lzma2Dec_DecodeToDic(CLzma2Dec *p, size_t dicLimit,
    const Byte *src, size_t *srcLen, ELzmaFinishMode finishMode, ELzmaStatus *status);

/* ---------- One Call Interface ---------- */

/*
finishMode:
  It has meaning only if the decoding reaches output limit (*destLen).
  LZMA_FINISH_ANY - use smallest number of input bytes
  LZMA_FINISH_END - read EndOfStream marker after decoding

Returns:
  SZ_OK
    status:
      LZMA_STATUS_FINISHED_WITH_MARK
      LZMA_STATUS_NOT_FINISHED
  SZ_ERROR_DATA - Data error
  SZ_ERROR_MEM  - Memory allocation error
  SZ_ERROR_UNSUPPORTED - Unsupported properties
  SZ_ERROR_INPUT_EOF - It needs more bytes in input buffer (src).
*/



/* ^^^^^^^^^^^^^^ MAIN IMPLEMENTATION ^^^^^^^^^^^^^^ */



/* 7zDec.c */

#define k_Copy 0
#define k_LZMA2 0x21
#define k_LZMA  0x30101
#define k_BCJ   0x03030103
#define k_PPC   0x03030205
#define k_ARM   0x03030501
#define k_ARMT  0x03030701
#define k_SPARC 0x03030805
#define k_BCJ2  0x0303011B

static SRes SzDecodeLzma(CSzCoderInfo *coder, UInt64 inSize, CLookToRead *inStream,
    Byte *outBuffer, size_t outSize)
{
  CLzmaDec state;
  SRes res = SZ_OK;

  LzmaDec_Construct(&state);
  RINOK(LzmaDec_AllocateProbs(&state, coder->Props, (unsigned)coder->PropsSize));
  state.dic = outBuffer;
  state.dicBufSize = outSize;
  LzmaDec_Init(&state);

  for (;;)
  {
    Byte *inBuf = NULL;
    size_t inProcessed = inSize > LookToRead_BUF_SIZE ?
        LookToRead_BUF_SIZE : inSize;
    res = LookToRead_Look(inStream, (const void **)&inBuf, &inProcessed);
    if (res != SZ_OK)
      break;

    {
      size_t dicPos = state.dicPos;
      ELzmaStatus status;
      res = LzmaDec_DecodeToDic(&state, outSize, inBuf, &inProcessed, LZMA_FINISH_END, &status);
      inSize -= inProcessed;
      if (res != SZ_OK)
        break;
      if (state.dicPos == state.dicBufSize || (inProcessed == 0 && dicPos == state.dicPos))
      {
        if (state.dicBufSize != outSize || inSize != 0 ||
            (status != LZMA_STATUS_FINISHED_WITH_MARK &&
             status != LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK))
          res = SZ_ERROR_DATA;
        break;
      }
      LOOKTOREAD_SKIP(inStream, inProcessed);
    }
  }

  LzmaDec_FreeProbs(&state);
  return res;
}

static SRes SzDecodeLzma2(CSzCoderInfo *coder, UInt64 inSize, CLookToRead *inStream,
    Byte *outBuffer, size_t outSize)
{
  CLzma2Dec state;
  SRes res = SZ_OK;

  Lzma2Dec_Construct(&state);
  if (coder->PropsSize != 1)
    return SZ_ERROR_DATA;
  RINOK(Lzma2Dec_AllocateProbs(&state, coder->Props[0]));
  state.decoder.dic = outBuffer;
  state.decoder.dicBufSize = outSize;
  Lzma2Dec_Init(&state);

  for (;;)
  {
    Byte *inBuf = NULL;
    size_t inProcessed = inSize > LookToRead_BUF_SIZE ?
        LookToRead_BUF_SIZE : inSize;
    res = LookToRead_Look(inStream, (const void **)&inBuf, &inProcessed);
    if (res != SZ_OK)
      break;

    {
      size_t dicPos = state.decoder.dicPos;
      ELzmaStatus status;
      res = Lzma2Dec_DecodeToDic(&state, outSize, inBuf, &inProcessed, LZMA_FINISH_END, &status);
      inSize -= inProcessed;
      if (res != SZ_OK)
        break;
      if (state.decoder.dicPos == state.decoder.dicBufSize || (inProcessed == 0 && dicPos == state.decoder.dicPos))
      {
        if (state.decoder.dicBufSize != outSize || inSize != 0 ||
            (status != LZMA_STATUS_FINISHED_WITH_MARK))
          res = SZ_ERROR_DATA;
        break;
      }
      LOOKTOREAD_SKIP(inStream, inProcessed);
    }
  }

  Lzma2Dec_FreeProbs(&state);
  return res;
}

static Bool IS_MAIN_METHOD(UInt32 m)
{
  switch(m)
  {
    case k_Copy:
    case k_LZMA:
    case k_LZMA2:
      return True;
  }
  return False;
}

static Bool IS_SUPPORTED_CODER(const CSzCoderInfo *c)
{
  return
      c->NumInStreams == 1 &&
      c->NumOutStreams == 1 &&
      c->MethodID <= (UInt32)0xFFFFFFFF &&
      IS_MAIN_METHOD((UInt32)c->MethodID);
}

#define IS_BCJ2(c) ((c)->MethodID == k_BCJ2 && (c)->NumInStreams == 4 && (c)->NumOutStreams == 1)

static SRes CheckSupportedFolder(const CSzFolder *f)
{
  if (f->NumCoders < 1 || f->NumCoders > 4)
    return SZ_ERROR_UNSUPPORTED;
  if (!IS_SUPPORTED_CODER(&f->Coders[0]))
    return SZ_ERROR_UNSUPPORTED;
  if (f->NumCoders == 1)
  {
    if (f->NumPackStreams != 1 || f->PackStreams[0] != 0 || f->NumBindPairs != 0)
      return SZ_ERROR_UNSUPPORTED;
    return SZ_OK;
  }
  if (f->NumCoders == 2)
  {
    CSzCoderInfo *c = &f->Coders[1];
    if (c->MethodID > (UInt32)0xFFFFFFFF ||
        c->NumInStreams != 1 ||
        c->NumOutStreams != 1 ||
        f->NumPackStreams != 1 ||
        f->PackStreams[0] != 0 ||
        f->NumBindPairs != 1 ||
        f->BindPairs[0].InIndex != 1 ||
        f->BindPairs[0].OutIndex != 0)
      return SZ_ERROR_UNSUPPORTED;
    switch ((UInt32)c->MethodID)
    {
      case k_BCJ:
      case k_ARM:
        break;
      default:
        return SZ_ERROR_UNSUPPORTED;
    }
    return SZ_OK;
  }
  if (f->NumCoders == 4)
  {
    if (!IS_SUPPORTED_CODER(&f->Coders[1]) ||
        !IS_SUPPORTED_CODER(&f->Coders[2]) ||
        !IS_BCJ2(&f->Coders[3]))
      return SZ_ERROR_UNSUPPORTED;
    if (f->NumPackStreams != 4 ||
        f->PackStreams[0] != 2 ||
        f->PackStreams[1] != 6 ||
        f->PackStreams[2] != 1 ||
        f->PackStreams[3] != 0 ||
        f->NumBindPairs != 3 ||
        f->BindPairs[0].InIndex != 5 || f->BindPairs[0].OutIndex != 0 ||
        f->BindPairs[1].InIndex != 4 || f->BindPairs[1].OutIndex != 1 ||
        f->BindPairs[2].InIndex != 3 || f->BindPairs[2].OutIndex != 2)
      return SZ_ERROR_UNSUPPORTED;
    return SZ_OK;
  }
  return SZ_ERROR_UNSUPPORTED;
}

static UInt64 GetSum(const UInt64 *values, UInt32 index)
{
  UInt64 sum = 0;
  UInt32 i;
  for (i = 0; i < index; i++)
    sum += values[i];
  return sum;
}

static SRes SzFolder_Decode2(const CSzFolder *folder, const UInt64 *packSizes,
    CLookToRead *inStream, UInt64 startPos,
    Byte *outBuffer, size_t outSize,
    Byte *tempBuf[])
{
  UInt32 ci;
  size_t tempSizes[3] = { 0, 0, 0};
  size_t tempSize3 = 0;
  Byte *tempBuf3 = 0;

  RINOK(CheckSupportedFolder(folder));

  for (ci = 0; ci < folder->NumCoders; ci++)
  {
    CSzCoderInfo *coder = &folder->Coders[ci];

    if (IS_MAIN_METHOD((UInt32)coder->MethodID))
    {
      UInt32 si = 0;
      UInt64 offset;
      UInt64 inSize;
      Byte *outBufCur = outBuffer;
      size_t outSizeCur = outSize;
      if (folder->NumCoders == 4)
      {
        UInt32 indices[] = { 3, 2, 0 };
        UInt64 unpackSize = folder->UnpackSizes[ci];
        si = indices[ci];
        if (ci < 2)
        {
          Byte *temp;
          outSizeCur = (size_t)unpackSize;
          if (outSizeCur != unpackSize)
            return SZ_ERROR_MEM;
          temp = (Byte *)SzAlloc(outSizeCur);
          if (temp == 0 && outSizeCur != 0)
            return SZ_ERROR_MEM;
          outBufCur = tempBuf[1 - ci] = temp;
          tempSizes[1 - ci] = outSizeCur;
        }
        else if (ci == 2)
        {
          if (unpackSize > outSize) /* check it */
            return SZ_ERROR_PARAM;
          tempBuf3 = outBufCur = outBuffer + (outSize - (size_t)unpackSize);
          tempSize3 = outSizeCur = (size_t)unpackSize;
        }
        else
          return SZ_ERROR_UNSUPPORTED;
      }
      offset = GetSum(packSizes, si);
      inSize = packSizes[si];
#ifdef _SZ_SEEK_DEBUG
      fprintf(stderr, "SEEKN 2\n");
#endif
      RINOK(LookInStream_SeekTo(inStream, startPos + offset));

      if (coder->MethodID == k_Copy)
      {
        size_t size = inSize;
#ifdef _SZ_CODER_DEBUG
      fprintf(stderr, "CODER Copy\n");
#endif
        if (inSize != outSizeCur) /* check it */
          return SZ_ERROR_DATA;
        if (inSize != size)
          return SZ_ERROR_MEM;
        RINOK(LookToRead_ReadAll(inStream, outBufCur, size));
      }
      else if (coder->MethodID == k_LZMA)
      {
#ifdef _SZ_CODER_DEBUG
      fprintf(stderr, "CODER LZMA\n");
#endif
        RINOK(SzDecodeLzma(coder, inSize, inStream, outBufCur, outSizeCur));
      }
      else if (coder->MethodID == k_LZMA2)
      {
#ifdef _SZ_CODER_DEBUG
      fprintf(stderr, "CODER LZMA2\n");
#endif
        RINOK(SzDecodeLzma2(coder, inSize, inStream, outBufCur, outSizeCur));
      }
      else
      {
        return SZ_ERROR_UNSUPPORTED;
      }
    }
    else if (coder->MethodID == k_BCJ2)
    {
      UInt64 offset = GetSum(packSizes, 1);
      UInt64 s3Size = packSizes[1];
      size_t size;
#ifdef _SZ_CODER_DEBUG
      fprintf(stderr, "CODER BCJ2\n");
#endif
      if (ci != 3)
        return SZ_ERROR_UNSUPPORTED;
#ifdef _SZ_SEEK_DEBUG
      fprintf(stderr, "SEEKN 3\n");
#endif
      RINOK(LookInStream_SeekTo(inStream, startPos + offset));
      tempSizes[2] = size = (size_t)s3Size;
      if (size != s3Size)
        return SZ_ERROR_MEM;
      tempBuf[2] = (Byte *)SzAlloc(tempSizes[2]);
      if (tempBuf[2] == 0 && tempSizes[2] != 0)
        return SZ_ERROR_MEM;
      RINOK(LookToRead_ReadAll(inStream, tempBuf[2], size));
      RINOK(Bcj2_Decode(
          tempBuf3, tempSize3,
          tempBuf[0], tempSizes[0],
          tempBuf[1], tempSizes[1],
          tempBuf[2], tempSizes[2],
          outBuffer, outSize));
    }
    else
    {
      if (ci != 1)
        return SZ_ERROR_UNSUPPORTED;
      switch(coder->MethodID)
      {
        case k_BCJ:
        {
          UInt32 state;
#ifdef _SZ_CODER_DEBUG
          fprintf(stderr, "CODER BCJ\n");
#endif
          x86_Convert_Init(state);
          x86_Convert(outBuffer, outSize, 0, &state, 0);
          break;
        }
        case k_ARM:
#ifdef _SZ_CODER_DEBUG
          fprintf(stderr, "CODER ARM\n");
#endif
          ARM_Convert(outBuffer, outSize, 0, 0);
          break;
        default:
          return SZ_ERROR_UNSUPPORTED;
      }
    }
  }
  return SZ_OK;
}

STATIC SRes SzFolder_Decode(const CSzFolder *folder, const UInt64 *packSizes,
    CLookToRead *inStream, UInt64 startPos,
    Byte *outBuffer, size_t outSize)
{
  Byte *tempBuf[3] = { 0, 0, 0};
  int i;
  SRes res = SzFolder_Decode2(folder, packSizes, inStream, startPos,
      outBuffer, (size_t)outSize, tempBuf);
  for (i = 0; i < 3; i++)
    SzFree(tempBuf[i]);
  return res;
}

/* 7zCrc.c */

#define kCrcPoly 0xEDB88320

/* Based on crc32h in: http://www.hackersdelight.org/hdcodetxt/crc.c.txt */
STATIC UInt32 MY_FAST_CALL CrcCalc(const void *data, size_t size) {
  const UInt32 g0 = kCrcPoly, g1 = g0>>1,
      g2 = g0>>2, g3 = g0>>3, g4 = g0>>4, g5 = g0>>5,
      g6 = (g0>>6)^g0, g7 = ((g0>>6)^g0)>>1;
  register const Byte *p = (const Byte*)data;
  register const Byte *pend = p + size;
  register Int32 crc = -1;
  if (p != pend) {
    do {
      crc ^= *p++;
      crc = ((UInt32)crc >> 8) ^
         ((crc<<31>>31) & g7) ^ ((crc<<30>>31) & g6) ^
         ((crc<<29>>31) & g5) ^ ((crc<<28>>31) & g4) ^
         ((crc<<27>>31) & g3) ^ ((crc<<26>>31) & g2) ^
         ((crc<<25>>31) & g1) ^ ((crc<<24>>31) & g0);
    } while (p != pend);
  }
  return ~crc;
}

/* 7zAlloc.c */

STATIC void *SzAlloc(size_t size) {
  if (size == 0)
    return 0;
#ifdef _SZ_ALLOC_DEBUG
  void *r = malloc(size);
  fprintf(stderr, "DYNAMIC ALLOC %lld = %p\n", (long long)size, r);
  return r;
#else
  return malloc(size);
#endif
}

STATIC void SzFree(void *address) {
  #ifdef _SZ_ALLOC_DEBUG
  fprintf(stderr, "DYNAMIC FREE %p\n", address);
  #endif
  free(address);
}

/* 7zStream.c */

STATIC SRes LookInStream_SeekTo(CLookToRead *p, UInt64 offset)
{
  p->pos = p->size = 0;
  if (offset >= p->data_len) {
    errno = EINVAL;
    return SZ_ERROR_READ;
  }
  p->data_pos = offset;
  return SZ_OK;
}

STATIC SRes LookToRead_Look(CLookToRead *p, const void **buf, size_t *size) {
  SRes res = SZ_OK;
  size_t size_in_buf = p->size - p->pos;
  size_t rsize;

  /* Checking size_in_buf <= p->pos is needed to avoid overlap in memcpy. */
  if (*size > size_in_buf && size_in_buf <= p->pos) {  /* TODO(pts): Do we need memmove instead? */
    memcpy(p->buf, p->buf + p->pos, size_in_buf);
    p->pos = 0;
    /* True but we can do it later: p->size = size_in_buf; */
    /* : res = FileInStream_Read(p->realStream, p->buf + size_in_buf, size); */
    /* We fill the buffer, we read more than: *size - size_in_buf; */
    rsize = LookToRead_BUF_SIZE - size_in_buf;
    if ((p->data_pos + rsize) > p->data_len) {
      rsize = p->data_len - p->data_pos;
    }
    if (rsize > 0) {
      memcpy(p->buf + size_in_buf, (char*)p->data + p->data_pos, rsize);
      p->data_pos += rsize;
    } 
    p->size = *size = size_in_buf += rsize;
  } else {
    *size = size_in_buf;
  }
  *buf = p->buf + p->pos;
  return res;
}

STATIC SRes LookToRead_ReadAll(CLookToRead *p, void *buf, size_t size) {
  Byte *lbuf;
  SRes res = SZ_OK;
  size_t got;
  while (size > 0) {
    got = size;
    res = LookToRead_Look(p, (const void**)&lbuf, &got);
    if (res != SZ_OK) break;
    if (got == 0) { res = SZ_ERROR_INPUT_EOF; break; }
    LOOKTOREAD_SKIP(p, got);
    memcpy(buf, lbuf, got);
    size -= got;
    buf = (Byte*)buf + got;
  }
  return res;
}

/* Bcj2.c -- Converter for x86 code (BCJ2) */

#ifdef _LZMA_PROB32
#define CProb UInt32
#else
#define CProb UInt16
#endif

#define IsJcc(b0, b1) ((b0) == 0x0F && ((b1) & 0xF0) == 0x80)
#define IsJ(b0, b1) ((b1 & 0xFE) == 0xE8 || IsJcc(b0, b1))

#define kNumTopBits 24
#define kTopValue ((UInt32)1 << kNumTopBits)

#define kNumBitModelTotalBits 11
#define kBitModelTotal (1 << kNumBitModelTotalBits)
#define kNumMoveBits 5

#define RC_READ_BYTE (*buffer++)
#define RC_TEST { if (buffer == bufferLim) return SZ_ERROR_DATA; }
#define RC_INIT2 code = 0; range = 0xFFFFFFFF; \
  { int i; for (i = 0; i < 5; i++) { RC_TEST; code = (code << 8) | RC_READ_BYTE; }}

#define NORMALIZE_BCJ2 if (range < kTopValue) { RC_TEST; range <<= 8; code = (code << 8) | RC_READ_BYTE; }

#define IF_BIT_0_BCJ2(p) ttt = *(p); bound = (range >> kNumBitModelTotalBits) * ttt; if (code < bound)
#define UPDATE_0_BCJ2(p) range = bound; *(p) = (CProb)(ttt + ((kBitModelTotal - ttt) >> kNumMoveBits)); NORMALIZE_BCJ2;
#define UPDATE_1_BCJ2(p) range -= bound; code -= bound; *(p) = (CProb)(ttt - (ttt >> kNumMoveBits)); NORMALIZE_BCJ2;

STATIC int Bcj2_Decode(
    const Byte *buf0, size_t size0,
    const Byte *buf1, size_t size1,
    const Byte *buf2, size_t size2,
    const Byte *buf3, size_t size3,
    Byte *outBuf, size_t outSize)
{
  CProb p[256 + 2];
  size_t inPos = 0, outPos = 0;

  const Byte *buffer, *bufferLim;
  UInt32 range, code;
  Byte prevByte = 0;

  unsigned int i;
  for (i = 0; i < sizeof(p) / sizeof(p[0]); i++)
    p[i] = kBitModelTotal >> 1;

  buffer = buf3;
  bufferLim = buffer + size3;
  RC_INIT2

  if (outSize == 0)
    return SZ_OK;

  for (;;)
  {
    Byte b;
    CProb *prob;
    UInt32 bound;
    UInt32 ttt;

    size_t limit = size0 - inPos;
    if (outSize - outPos < limit)
      limit = outSize - outPos;
    while (limit != 0)
    {
      Byte b = buf0[inPos];
      outBuf[outPos++] = b;
      if (IsJ(prevByte, b))
        break;
      inPos++;
      prevByte = b;
      limit--;
    }

    if (limit == 0 || outPos == outSize)
      break;

    b = buf0[inPos++];

    if (b == 0xE8)
      prob = p + prevByte;
    else if (b == 0xE9)
      prob = p + 256;
    else
      prob = p + 257;

    IF_BIT_0_BCJ2(prob)
    {
      UPDATE_0_BCJ2(prob)
      prevByte = b;
    }
    else
    {
      UInt32 dest;
      const Byte *v;
      UPDATE_1_BCJ2(prob)
      if (b == 0xE8)
      {
        v = buf1;
        if (size1 < 4)
          return SZ_ERROR_DATA;
        buf1 += 4;
        size1 -= 4;
      }
      else
      {
        v = buf2;
        if (size2 < 4)
          return SZ_ERROR_DATA;
        buf2 += 4;
        size2 -= 4;
      }
      dest = (((UInt32)v[0] << 24) | ((UInt32)v[1] << 16) |
          ((UInt32)v[2] << 8) | ((UInt32)v[3])) - ((UInt32)outPos + 4);
      outBuf[outPos++] = (Byte)dest;
      if (outPos == outSize)
        break;
      outBuf[outPos++] = (Byte)(dest >> 8);
      if (outPos == outSize)
        break;
      outBuf[outPos++] = (Byte)(dest >> 16);
      if (outPos == outSize)
        break;
      outBuf[outPos++] = prevByte = (Byte)(dest >> 24);
    }
  }
  return (outPos == outSize) ? SZ_OK : SZ_ERROR_DATA;
}

/* Bra.c -- Converters for RISC code */

STATIC size_t ARM_Convert(Byte *data, size_t size, UInt32 ip, int encoding)
{
  size_t i;
  if (size < 4)
    return 0;
  size -= 4;
  ip += 8;
  for (i = 0; i <= size; i += 4)
  {
    if (data[i + 3] == 0xEB)
    {
      UInt32 dest;
      UInt32 src = ((UInt32)data[i + 2] << 16) | ((UInt32)data[i + 1] << 8) | (data[i + 0]);
      src <<= 2;
      if (encoding)
        dest = ip + (UInt32)i + src;
      else
        dest = src - (ip + (UInt32)i);
      dest >>= 2;
      data[i + 2] = (Byte)(dest >> 16);
      data[i + 1] = (Byte)(dest >> 8);
      data[i + 0] = (Byte)dest;
    }
  }
  return i;
}

/* Bra86.c -- Converter for x86 code (BCJ) */

#define Test86MSByte(b) ((b) == 0 || (b) == 0xFF)

/*static const Byte kMaskToAllowedStatus[8] = {1, 1, 1, 0, 1, 0, 0, 0};*/
static const Byte kMaskToAllowedStatus = 0x17;
/*static const Byte kMaskToBitNumber[8] = {0, 1, 2, 2, 3, 3, 3, 3};*/
static const UInt16 kMaskToBitNumber = 0xffa4;

STATIC size_t x86_Convert(Byte *data, size_t size, UInt32 ip, UInt32 *state, int encoding)
{
  size_t bufferPos = 0, prevPosT;
  UInt32 prevMask = *state & 0x7;
  if (size < 5)
    return 0;
  ip += 5;
  prevPosT = (size_t)0 - 1;

  for (;;)
  {
    Byte *p = data + bufferPos;
    Byte *limit = data + size - 4;
    for (; p < limit; p++)
      if ((*p & 0xFE) == 0xE8)
        break;
    bufferPos = (size_t)(p - data);
    if (p >= limit)
      break;
    prevPosT = bufferPos - prevPosT;
    if (prevPosT > 3)
      prevMask = 0;
    else
    {
      prevMask = (prevMask << ((int)prevPosT - 1)) & 0x7;
      if (prevMask != 0)
      {
        Byte b = p[4 - ((kMaskToBitNumber >> (prevMask * 2)) & 3)];
        if (!((kMaskToAllowedStatus >> prevMask) & 1) || Test86MSByte(b))
        {
          prevPosT = bufferPos;
          prevMask = ((prevMask << 1) & 0x7) | 1;
          bufferPos++;
          continue;
        }
      }
    }
    prevPosT = bufferPos;

    if (Test86MSByte(p[4]))
    {
      UInt32 src = ((UInt32)p[4] << 24) | ((UInt32)p[3] << 16) | ((UInt32)p[2] << 8) | ((UInt32)p[1]);
      UInt32 dest;
      for (;;)
      {
        Byte b;
        int index;
        if (encoding)
          dest = (ip + (UInt32)bufferPos) + src;
        else
          dest = src - (ip + (UInt32)bufferPos);
        if (prevMask == 0)
          break;
        index = ((kMaskToBitNumber >> (prevMask * 2)) & 3) * 8;
        b = (Byte)(dest >> (24 - index));
        if (!Test86MSByte(b))
          break;
        src = dest ^ ((1 << (32 - index)) - 1);
      }
      p[4] = (Byte)(~(((dest >> 24) & 1) - 1));
      p[3] = (Byte)(dest >> 16);
      p[2] = (Byte)(dest >> 8);
      p[1] = (Byte)dest;
      bufferPos += 5;
    }
    else
    {
      prevMask = ((prevMask << 1) & 0x7) | 1;
      bufferPos++;
    }
  }
  prevPosT = bufferPos - prevPosT;
  *state = ((prevPosT > 3) ? 0 : ((prevMask << ((int)prevPosT - 1)) & 0x7));
  return bufferPos;
}

/* Lzma2Dec.c -- LZMA2 Decoder
2010-12-15 : Igor Pavlov : Public domain */

/* #define SHOW_DEBUG_INFO */


/*
00000000  -  EOS
00000001 U U  -  Uncompressed Reset Dic
00000010 U U  -  Uncompressed No Reset
100uuuuu U U P P  -  LZMA no reset
101uuuuu U U P P  -  LZMA reset state
110uuuuu U U P P S  -  LZMA reset state + new prop
111uuuuu U U P P S  -  LZMA reset state + new prop + reset dic

  u, U - Unpack Size
  P - Pack Size
  S - Props
*/

#define LZMA2_CONTROL_LZMA (1 << 7)
#define LZMA2_CONTROL_COPY_NO_RESET 2
#define LZMA2_CONTROL_COPY_RESET_DIC 1
#define LZMA2_CONTROL_EOF 0

#define LZMA2_IS_UNCOMPRESSED_STATE(p) (((p)->control & LZMA2_CONTROL_LZMA) == 0)

#define LZMA2_GET_LZMA_MODE(p) (((p)->control >> 5) & 3)
#define LZMA2_IS_THERE_PROP(mode) ((mode) >= 2)

#define LZMA2_LCLP_MAX 4
#define LZMA2_DIC_SIZE_FROM_PROP(p) (((UInt32)2 | ((p) & 1)) << ((p) / 2 + 11))

#ifdef SHOW_DEBUG_INFO
#define PRF(x) x
#else
#define PRF(x)
#endif

typedef enum
{
  LZMA2_STATE_CONTROL,
  LZMA2_STATE_UNPACK0,
  LZMA2_STATE_UNPACK1,
  LZMA2_STATE_PACK0,
  LZMA2_STATE_PACK1,
  LZMA2_STATE_PROP,
  LZMA2_STATE_DATA,
  LZMA2_STATE_DATA_CONT,
  LZMA2_STATE_FINISHED,
  LZMA2_STATE_ERROR
} ELzma2State;

static SRes Lzma2Dec_GetOldProps(Byte prop, Byte *props)
{
  UInt32 dicSize;
  if (prop > 40)
    return SZ_ERROR_UNSUPPORTED;
  dicSize = (prop == 40) ? 0xFFFFFFFF : LZMA2_DIC_SIZE_FROM_PROP(prop);
  props[0] = (Byte)LZMA2_LCLP_MAX;
  props[1] = (Byte)(dicSize);
  props[2] = (Byte)(dicSize >> 8);
  props[3] = (Byte)(dicSize >> 16);
  props[4] = (Byte)(dicSize >> 24);
  return SZ_OK;
}

STATIC SRes Lzma2Dec_AllocateProbs(CLzma2Dec *p, Byte prop)
{
  Byte props[LZMA_PROPS_SIZE];
  RINOK(Lzma2Dec_GetOldProps(prop, props));
  return LzmaDec_AllocateProbs(&p->decoder, props, LZMA_PROPS_SIZE);
}

STATIC void Lzma2Dec_Init(CLzma2Dec *p)
{
  p->state = LZMA2_STATE_CONTROL;
  p->needInitDic = True;
  p->needInitState = True;
  p->needInitProp = True;
  LzmaDec_Init(&p->decoder);
}

static ELzma2State Lzma2Dec_UpdateState(CLzma2Dec *p, Byte b)
{
  switch(p->state)
  {
    case LZMA2_STATE_CONTROL:
      p->control = b;
      PRF(printf("\n %4X ", p->decoder.dicPos));
      PRF(printf(" %2X", b));
      if (p->control == 0)
        return LZMA2_STATE_FINISHED;
      if (LZMA2_IS_UNCOMPRESSED_STATE(p))
      {
        if ((p->control & 0x7F) > 2)
          return LZMA2_STATE_ERROR;
        p->unpackSize = 0;
      }
      else
        p->unpackSize = (UInt32)(p->control & 0x1F) << 16;
      return LZMA2_STATE_UNPACK0;

    case LZMA2_STATE_UNPACK0:
      p->unpackSize |= (UInt32)b << 8;
      return LZMA2_STATE_UNPACK1;

    case LZMA2_STATE_UNPACK1:
      p->unpackSize |= (UInt32)b;
      p->unpackSize++;
      PRF(printf(" %8d", p->unpackSize));
      return (LZMA2_IS_UNCOMPRESSED_STATE(p)) ? LZMA2_STATE_DATA : LZMA2_STATE_PACK0;

    case LZMA2_STATE_PACK0:
      p->packSize = (UInt32)b << 8;
      return LZMA2_STATE_PACK1;

    case LZMA2_STATE_PACK1:
      p->packSize |= (UInt32)b;
      p->packSize++;
      PRF(printf(" %8d", p->packSize));
      return LZMA2_IS_THERE_PROP(LZMA2_GET_LZMA_MODE(p)) ? LZMA2_STATE_PROP:
        (p->needInitProp ? LZMA2_STATE_ERROR : LZMA2_STATE_DATA);

    case LZMA2_STATE_PROP:
    {
      int lc, lp;
      if (b >= (9 * 5 * 5))
        return LZMA2_STATE_ERROR;
      lc = b % 9;
      b /= 9;
      p->decoder.prop.pb = b / 5;
      lp = b % 5;
      if (lc + lp > LZMA2_LCLP_MAX)
        return LZMA2_STATE_ERROR;
      p->decoder.prop.lc = lc;
      p->decoder.prop.lp = lp;
      p->needInitProp = False;
      return LZMA2_STATE_DATA;
    }
  }
  return LZMA2_STATE_ERROR;
}

static void LzmaDec_UpdateWithUncompressed(CLzmaDec *p, const Byte *src, size_t size)
{
  memcpy(p->dic + p->dicPos, src, size);
  p->dicPos += size;
  if (p->checkDicSize == 0 && p->prop.dicSize - p->processedPos <= size)
    p->checkDicSize = p->prop.dicSize;
  p->processedPos += (UInt32)size;
}

STATIC void LzmaDec_InitDicAndState(CLzmaDec *p, Bool initDic, Bool initState);

STATIC SRes Lzma2Dec_DecodeToDic(CLzma2Dec *p, size_t dicLimit,
    const Byte *src, size_t *srcLen, ELzmaFinishMode finishMode, ELzmaStatus *status)
{
  size_t inSize = *srcLen;
  *srcLen = 0;
  *status = LZMA_STATUS_NOT_SPECIFIED;

  while (p->state != LZMA2_STATE_FINISHED)
  {
    size_t dicPos = p->decoder.dicPos;
    if (p->state == LZMA2_STATE_ERROR)
      return SZ_ERROR_DATA;
    if (dicPos == dicLimit && finishMode == LZMA_FINISH_ANY)
    {
      *status = LZMA_STATUS_NOT_FINISHED;
      return SZ_OK;
    }
    if (p->state != LZMA2_STATE_DATA && p->state != LZMA2_STATE_DATA_CONT)
    {
      if (*srcLen == inSize)
      {
        *status = LZMA_STATUS_NEEDS_MORE_INPUT;
        return SZ_OK;
      }
      (*srcLen)++;
      p->state = Lzma2Dec_UpdateState(p, *src++);
      continue;
    }
    {
      size_t destSizeCur = dicLimit - dicPos;
      size_t srcSizeCur = inSize - *srcLen;
      ELzmaFinishMode curFinishMode = LZMA_FINISH_ANY;

      if (p->unpackSize <= destSizeCur)
      {
        destSizeCur = (size_t)p->unpackSize;
        curFinishMode = LZMA_FINISH_END;
      }

      if (LZMA2_IS_UNCOMPRESSED_STATE(p))
      {
        if (*srcLen == inSize)
        {
          *status = LZMA_STATUS_NEEDS_MORE_INPUT;
          return SZ_OK;
        }

        if (p->state == LZMA2_STATE_DATA)
        {
          Bool initDic = (p->control == LZMA2_CONTROL_COPY_RESET_DIC);
          if (initDic)
            p->needInitProp = p->needInitState = True;
          else if (p->needInitDic)
            return SZ_ERROR_DATA;
          p->needInitDic = False;
          LzmaDec_InitDicAndState(&p->decoder, initDic, False);
        }

        if (srcSizeCur > destSizeCur)
          srcSizeCur = destSizeCur;

        if (srcSizeCur == 0)
          return SZ_ERROR_DATA;

        LzmaDec_UpdateWithUncompressed(&p->decoder, src, srcSizeCur);

        src += srcSizeCur;
        *srcLen += srcSizeCur;
        p->unpackSize -= (UInt32)srcSizeCur;
        p->state = (p->unpackSize == 0) ? LZMA2_STATE_CONTROL : LZMA2_STATE_DATA_CONT;
      }
      else
      {
        size_t outSizeProcessed;
        SRes res;

        if (p->state == LZMA2_STATE_DATA)
        {
          int mode = LZMA2_GET_LZMA_MODE(p);
          Bool initDic = (mode == 3);
          Bool initState = (mode > 0);
          if ((!initDic && p->needInitDic) || (!initState && p->needInitState))
            return SZ_ERROR_DATA;

          LzmaDec_InitDicAndState(&p->decoder, initDic, initState);
          p->needInitDic = False;
          p->needInitState = False;
          p->state = LZMA2_STATE_DATA_CONT;
        }
        if (srcSizeCur > p->packSize)
          srcSizeCur = (size_t)p->packSize;

        res = LzmaDec_DecodeToDic(&p->decoder, dicPos + destSizeCur, src, &srcSizeCur, curFinishMode, status);

        src += srcSizeCur;
        *srcLen += srcSizeCur;
        p->packSize -= (UInt32)srcSizeCur;

        outSizeProcessed = p->decoder.dicPos - dicPos;
        p->unpackSize -= (UInt32)outSizeProcessed;

        RINOK(res);
        if (*status == LZMA_STATUS_NEEDS_MORE_INPUT)
          return res;

        if (srcSizeCur == 0 && outSizeProcessed == 0)
        {
          if (*status != LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK ||
              p->unpackSize != 0 || p->packSize != 0)
            return SZ_ERROR_DATA;
          p->state = LZMA2_STATE_CONTROL;
        }
        if (*status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK)
          *status = LZMA_STATUS_NOT_FINISHED;
      }
    }
  }
  *status = LZMA_STATUS_FINISHED_WITH_MARK;
  return SZ_OK;
}

/* LzmaDec.c -- LZMA Decoder */

#define kNumTopBits 24
#define kTopValue ((UInt32)1 << kNumTopBits)

#define kNumBitModelTotalBits 11
#define kBitModelTotal (1 << kNumBitModelTotalBits)
#define kNumMoveBits 5

#define RC_INIT_SIZE 5

#define NORMALIZE if (range < kTopValue) { range <<= 8; code = (code << 8) | (*buf++); }

#define IF_BIT_0(p) ttt = *(p); NORMALIZE; bound = (range >> kNumBitModelTotalBits) * ttt; if (code < bound)
#define UPDATE_0(p) range = bound; *(p) = (CLzmaProb)(ttt + ((kBitModelTotal - ttt) >> kNumMoveBits));
#define UPDATE_1(p) range -= bound; code -= bound; *(p) = (CLzmaProb)(ttt - (ttt >> kNumMoveBits));
#define GET_BIT2(p, i, A0, A1) IF_BIT_0(p) \
  { UPDATE_0(p); i = (i + i); A0; } else \
  { UPDATE_1(p); i = (i + i) + 1; A1; }
#define GET_BIT(p, i) GET_BIT2(p, i, ; , ;)

#define TREE_GET_BIT(probs, i) { GET_BIT((probs + i), i); }
#define TREE_DECODE(probs, limit, i) \
  { i = 1; do { TREE_GET_BIT(probs, i); } while (i < limit); i -= limit; }

/* #define _LZMA_SIZE_OPT */

#ifdef _LZMA_SIZE_OPT
#define TREE_6_DECODE(probs, i) TREE_DECODE(probs, (1 << 6), i)
#else
#define TREE_6_DECODE(probs, i) \
  { i = 1; \
  TREE_GET_BIT(probs, i); \
  TREE_GET_BIT(probs, i); \
  TREE_GET_BIT(probs, i); \
  TREE_GET_BIT(probs, i); \
  TREE_GET_BIT(probs, i); \
  TREE_GET_BIT(probs, i); \
  i -= 0x40; }
#endif

#define NORMALIZE_CHECK if (range < kTopValue) { if (buf >= bufLimit) return DUMMY_ERROR; range <<= 8; code = (code << 8) | (*buf++); }

#define IF_BIT_0_CHECK(p) ttt = *(p); NORMALIZE_CHECK; bound = (range >> kNumBitModelTotalBits) * ttt; if (code < bound)
#define UPDATE_0_CHECK range = bound;
#define UPDATE_1_CHECK range -= bound; code -= bound;
#define GET_BIT2_CHECK(p, i, A0, A1) IF_BIT_0_CHECK(p) \
  { UPDATE_0_CHECK; i = (i + i); A0; } else \
  { UPDATE_1_CHECK; i = (i + i) + 1; A1; }
#define GET_BIT_CHECK(p, i) GET_BIT2_CHECK(p, i, ; , ;)
#define TREE_DECODE_CHECK(probs, limit, i) \
  { i = 1; do { GET_BIT_CHECK(probs + i, i) } while (i < limit); i -= limit; }


#define kNumPosBitsMax 4
#define kNumPosStatesMax (1 << kNumPosBitsMax)

#define kLenNumLowBits 3
#define kLenNumLowSymbols (1 << kLenNumLowBits)
#define kLenNumMidBits 3
#define kLenNumMidSymbols (1 << kLenNumMidBits)
#define kLenNumHighBits 8
#define kLenNumHighSymbols (1 << kLenNumHighBits)

#define LenChoice 0
#define LenChoice2 (LenChoice + 1)
#define LenLow (LenChoice2 + 1)
#define LenMid (LenLow + (kNumPosStatesMax << kLenNumLowBits))
#define LenHigh (LenMid + (kNumPosStatesMax << kLenNumMidBits))
#define kNumLenProbs (LenHigh + kLenNumHighSymbols)


#define kNumStates 12
#define kNumLitStates 7

#define kStartPosModelIndex 4
#define kEndPosModelIndex 14
#define kNumFullDistances (1 << (kEndPosModelIndex >> 1))

#define kNumPosSlotBits 6
#define kNumLenToPosStates 4

#define kNumAlignBits 4
#define kAlignTableSize (1 << kNumAlignBits)

#define kMatchMinLen 2
#define kMatchSpecLenStart (kMatchMinLen + kLenNumLowSymbols + kLenNumMidSymbols + kLenNumHighSymbols)

#define IsMatch 0
#define IsRep (IsMatch + (kNumStates << kNumPosBitsMax))
#define IsRepG0 (IsRep + kNumStates)
#define IsRepG1 (IsRepG0 + kNumStates)
#define IsRepG2 (IsRepG1 + kNumStates)
#define IsRep0Long (IsRepG2 + kNumStates)
#define PosSlot (IsRep0Long + (kNumStates << kNumPosBitsMax))
#define SpecPos (PosSlot + (kNumLenToPosStates << kNumPosSlotBits))
#define Align (SpecPos + kNumFullDistances - kEndPosModelIndex)
#define LenCoder (Align + kAlignTableSize)
#define RepLenCoder (LenCoder + kNumLenProbs)
#define Literal (RepLenCoder + kNumLenProbs)

#define LZMA_BASE_SIZE 1846
#define LZMA_LIT_SIZE 768

#define LzmaProps_GetNumProbs(p) ((UInt32)LZMA_BASE_SIZE + (LZMA_LIT_SIZE << ((p)->lc + (p)->lp)))

#if Literal != LZMA_BASE_SIZE
StopCompilingDueBUG
#endif

#define LZMA_DIC_MIN (1 << 12)

/* First LZMA-symbol is always decoded.
And it decodes new LZMA-symbols while (buf < bufLimit), but "buf" is without last normalization
Out:
  Result:
    SZ_OK - OK
    SZ_ERROR_DATA - Error
  p->remainLen:
    < kMatchSpecLenStart : normal remain
    = kMatchSpecLenStart : finished
    = kMatchSpecLenStart + 1 : Flush marker
    = kMatchSpecLenStart + 2 : State Init Marker
*/

static int MY_FAST_CALL LzmaDec_DecodeReal(CLzmaDec *p, size_t limit, const Byte *bufLimit)
{
  CLzmaProb *probs = p->probs;

  unsigned state = p->state;
  UInt32 rep0 = p->reps[0], rep1 = p->reps[1], rep2 = p->reps[2], rep3 = p->reps[3];
  unsigned pbMask = ((unsigned)1 << (p->prop.pb)) - 1;
  unsigned lpMask = ((unsigned)1 << (p->prop.lp)) - 1;
  unsigned lc = p->prop.lc;

  Byte *dic = p->dic;
  size_t dicBufSize = p->dicBufSize;
  size_t dicPos = p->dicPos;

  UInt32 processedPos = p->processedPos;
  UInt32 checkDicSize = p->checkDicSize;
  unsigned len = 0;

  const Byte *buf = p->buf;
  UInt32 range = p->range;
  UInt32 code = p->code;

  do
  {
    CLzmaProb *prob;
    UInt32 bound;
    unsigned ttt;
    unsigned posState = processedPos & pbMask;

    prob = probs + IsMatch + (state << kNumPosBitsMax) + posState;
    IF_BIT_0(prob)
    {
      unsigned symbol;
      UPDATE_0(prob);
      prob = probs + Literal;
      if (checkDicSize != 0 || processedPos != 0)
        prob += (LZMA_LIT_SIZE * (((processedPos & lpMask) << lc) +
        (dic[(dicPos == 0 ? dicBufSize : dicPos) - 1] >> (8 - lc))));

      if (state < kNumLitStates)
      {
        state -= (state < 4) ? state : 3;
        symbol = 1;
        do { GET_BIT(prob + symbol, symbol) } while (symbol < 0x100);
      }
      else
      {
        unsigned matchByte = p->dic[(dicPos - rep0) + ((dicPos < rep0) ? dicBufSize : 0)];
        unsigned offs = 0x100;
        state -= (state < 10) ? 3 : 6;
        symbol = 1;
        do
        {
          unsigned bit;
          CLzmaProb *probLit;
          matchByte <<= 1;
          bit = (matchByte & offs);
          probLit = prob + offs + bit + symbol;
          GET_BIT2(probLit, symbol, offs &= ~bit, offs &= bit)
        }
        while (symbol < 0x100);
      }
      dic[dicPos++] = (Byte)symbol;
      processedPos++;
      continue;
    }
    else
    {
      UPDATE_1(prob);
      prob = probs + IsRep + state;
      IF_BIT_0(prob)
      {
        UPDATE_0(prob);
        state += kNumStates;
        prob = probs + LenCoder;
      }
      else
      {
        UPDATE_1(prob);
        if (checkDicSize == 0 && processedPos == 0)
          return SZ_ERROR_DATA;
        prob = probs + IsRepG0 + state;
        IF_BIT_0(prob)
        {
          UPDATE_0(prob);
          prob = probs + IsRep0Long + (state << kNumPosBitsMax) + posState;
          IF_BIT_0(prob)
          {
            UPDATE_0(prob);
            dic[dicPos] = dic[(dicPos - rep0) + ((dicPos < rep0) ? dicBufSize : 0)];
            dicPos++;
            processedPos++;
            state = state < kNumLitStates ? 9 : 11;
            continue;
          }
          UPDATE_1(prob);
        }
        else
        {
          UInt32 distance;
          UPDATE_1(prob);
          prob = probs + IsRepG1 + state;
          IF_BIT_0(prob)
          {
            UPDATE_0(prob);
            distance = rep1;
          }
          else
          {
            UPDATE_1(prob);
            prob = probs + IsRepG2 + state;
            IF_BIT_0(prob)
            {
              UPDATE_0(prob);
              distance = rep2;
            }
            else
            {
              UPDATE_1(prob);
              distance = rep3;
              rep3 = rep2;
            }
            rep2 = rep1;
          }
          rep1 = rep0;
          rep0 = distance;
        }
        state = state < kNumLitStates ? 8 : 11;
        prob = probs + RepLenCoder;
      }
      {
        unsigned limit, offset;
        CLzmaProb *probLen = prob + LenChoice;
        IF_BIT_0(probLen)
        {
          UPDATE_0(probLen);
          probLen = prob + LenLow + (posState << kLenNumLowBits);
          offset = 0;
          limit = (1 << kLenNumLowBits);
        }
        else
        {
          UPDATE_1(probLen);
          probLen = prob + LenChoice2;
          IF_BIT_0(probLen)
          {
            UPDATE_0(probLen);
            probLen = prob + LenMid + (posState << kLenNumMidBits);
            offset = kLenNumLowSymbols;
            limit = (1 << kLenNumMidBits);
          }
          else
          {
            UPDATE_1(probLen);
            probLen = prob + LenHigh;
            offset = kLenNumLowSymbols + kLenNumMidSymbols;
            limit = (1 << kLenNumHighBits);
          }
        }
        TREE_DECODE(probLen, limit, len);
        len += offset;
      }

      if (state >= kNumStates)
      {
        UInt32 distance;
        prob = probs + PosSlot +
            ((len < kNumLenToPosStates ? len : kNumLenToPosStates - 1) << kNumPosSlotBits);
        TREE_6_DECODE(prob, distance);
        if (distance >= kStartPosModelIndex)
        {
          unsigned posSlot = (unsigned)distance;
          int numDirectBits = (int)(((distance >> 1) - 1));
          distance = (2 | (distance & 1));
          if (posSlot < kEndPosModelIndex)
          {
            distance <<= numDirectBits;
            prob = probs + SpecPos + distance - posSlot - 1;
            {
              UInt32 mask = 1;
              unsigned i = 1;
              do
              {
                GET_BIT2(prob + i, i, ; , distance |= mask);
                mask <<= 1;
              }
              while (--numDirectBits != 0);
            }
          }
          else
          {
            numDirectBits -= kNumAlignBits;
            do
            {
              NORMALIZE
              range >>= 1;

              {
                UInt32 t;
                code -= range;
                t = (0 - ((UInt32)code >> 31)); /* (UInt32)((Int32)code >> 31) */
                distance = (distance << 1) + (t + 1);
                code += range & t;
              }
              /*
              distance <<= 1;
              if (code >= range)
              {
                code -= range;
                distance |= 1;
              }
              */
            }
            while (--numDirectBits != 0);
            prob = probs + Align;
            distance <<= kNumAlignBits;
            {
              unsigned i = 1;
              GET_BIT2(prob + i, i, ; , distance |= 1);
              GET_BIT2(prob + i, i, ; , distance |= 2);
              GET_BIT2(prob + i, i, ; , distance |= 4);
              GET_BIT2(prob + i, i, ; , distance |= 8);
            }
            if (distance == (UInt32)0xFFFFFFFF)
            {
              len += kMatchSpecLenStart;
              state -= kNumStates;
              break;
            }
          }
        }
        rep3 = rep2;
        rep2 = rep1;
        rep1 = rep0;
        rep0 = distance + 1;
        if (checkDicSize == 0)
        {
          if (distance >= processedPos)
            return SZ_ERROR_DATA;
        }
        else if (distance >= checkDicSize)
          return SZ_ERROR_DATA;
        state = (state < kNumStates + kNumLitStates) ? kNumLitStates : kNumLitStates + 3;
      }

      len += kMatchMinLen;

      if (limit == dicPos)
        return SZ_ERROR_DATA;
      {
        size_t rem = limit - dicPos;
        unsigned curLen = ((rem < len) ? (unsigned)rem : len);
        size_t pos = (dicPos - rep0) + ((dicPos < rep0) ? dicBufSize : 0);

        processedPos += curLen;

        len -= curLen;
        if (pos + curLen <= dicBufSize)
        {
          Byte *dest = dic + dicPos;
          ptrdiff_t src = (ptrdiff_t)pos - (ptrdiff_t)dicPos;
          const Byte *lim = dest + curLen;
          dicPos += curLen;
          do
            *(dest) = (Byte)*(dest + src);
          while (++dest != lim);
        }
        else
        {
          do
          {
            dic[dicPos++] = dic[pos];
            if (++pos == dicBufSize)
              pos = 0;
          }
          while (--curLen != 0);
        }
      }
    }
  }
  while (dicPos < limit && buf < bufLimit);
  NORMALIZE;
  p->buf = buf;
  p->range = range;
  p->code = code;
  p->remainLen = len;
  p->dicPos = dicPos;
  p->processedPos = processedPos;
  p->reps[0] = rep0;
  p->reps[1] = rep1;
  p->reps[2] = rep2;
  p->reps[3] = rep3;
  p->state = state;

  return SZ_OK;
}

static void MY_FAST_CALL LzmaDec_WriteRem(CLzmaDec *p, size_t limit)
{
  if (p->remainLen != 0 && p->remainLen < kMatchSpecLenStart)
  {
    Byte *dic = p->dic;
    size_t dicPos = p->dicPos;
    size_t dicBufSize = p->dicBufSize;
    unsigned len = p->remainLen;
    UInt32 rep0 = p->reps[0];
    if (limit - dicPos < len)
      len = (unsigned)(limit - dicPos);

    if (p->checkDicSize == 0 && p->prop.dicSize - p->processedPos <= len)
      p->checkDicSize = p->prop.dicSize;

    p->processedPos += len;
    p->remainLen -= len;
    while (len != 0)
    {
      len--;
      dic[dicPos] = dic[(dicPos - rep0) + ((dicPos < rep0) ? dicBufSize : 0)];
      dicPos++;
    }
    p->dicPos = dicPos;
  }
}

static int MY_FAST_CALL LzmaDec_DecodeReal2(CLzmaDec *p, size_t limit, const Byte *bufLimit)
{
  do
  {
    size_t limit2 = limit;
    if (p->checkDicSize == 0)
    {
      UInt32 rem = p->prop.dicSize - p->processedPos;
      if (limit - p->dicPos > rem)
        limit2 = p->dicPos + rem;
    }
    RINOK(LzmaDec_DecodeReal(p, limit2, bufLimit));
    if (p->processedPos >= p->prop.dicSize)
      p->checkDicSize = p->prop.dicSize;
    LzmaDec_WriteRem(p, limit);
  }
  while (p->dicPos < limit && p->buf < bufLimit && p->remainLen < kMatchSpecLenStart);

  if (p->remainLen > kMatchSpecLenStart)
  {
    p->remainLen = kMatchSpecLenStart;
  }
  return 0;
}

typedef enum
{
  DUMMY_ERROR, /* unexpected end of input stream */
  DUMMY_LIT,
  DUMMY_MATCH,
  DUMMY_REP
} ELzmaDummy;

static ELzmaDummy LzmaDec_TryDummy(const CLzmaDec *p, const Byte *buf, size_t inSize)
{
  UInt32 range = p->range;
  UInt32 code = p->code;
  const Byte *bufLimit = buf + inSize;
  CLzmaProb *probs = p->probs;
  unsigned state = p->state;
  ELzmaDummy res;

  {
    CLzmaProb *prob;
    UInt32 bound;
    unsigned ttt;
    unsigned posState = (p->processedPos) & ((1 << p->prop.pb) - 1);

    prob = probs + IsMatch + (state << kNumPosBitsMax) + posState;
    IF_BIT_0_CHECK(prob)
    {
      UPDATE_0_CHECK

      /* if (bufLimit - buf >= 7) return DUMMY_LIT; */

      prob = probs + Literal;
      if (p->checkDicSize != 0 || p->processedPos != 0)
        prob += (LZMA_LIT_SIZE *
          ((((p->processedPos) & ((1 << (p->prop.lp)) - 1)) << p->prop.lc) +
          (p->dic[(p->dicPos == 0 ? p->dicBufSize : p->dicPos) - 1] >> (8 - p->prop.lc))));

      if (state < kNumLitStates)
      {
        unsigned symbol = 1;
        do { GET_BIT_CHECK(prob + symbol, symbol) } while (symbol < 0x100);
      }
      else
      {
        unsigned matchByte = p->dic[p->dicPos - p->reps[0] +
            ((p->dicPos < p->reps[0]) ? p->dicBufSize : 0)];
        unsigned offs = 0x100;
        unsigned symbol = 1;
        do
        {
          unsigned bit;
          CLzmaProb *probLit;
          matchByte <<= 1;
          bit = (matchByte & offs);
          probLit = prob + offs + bit + symbol;
          GET_BIT2_CHECK(probLit, symbol, offs &= ~bit, offs &= bit)
        }
        while (symbol < 0x100);
      }
      res = DUMMY_LIT;
    }
    else
    {
      unsigned len;
      UPDATE_1_CHECK;

      prob = probs + IsRep + state;
      IF_BIT_0_CHECK(prob)
      {
        UPDATE_0_CHECK;
        state = 0;
        prob = probs + LenCoder;
        res = DUMMY_MATCH;
      }
      else
      {
        UPDATE_1_CHECK;
        res = DUMMY_REP;
        prob = probs + IsRepG0 + state;
        IF_BIT_0_CHECK(prob)
        {
          UPDATE_0_CHECK;
          prob = probs + IsRep0Long + (state << kNumPosBitsMax) + posState;
          IF_BIT_0_CHECK(prob)
          {
            UPDATE_0_CHECK;
            NORMALIZE_CHECK;
            return DUMMY_REP;
          }
          else
          {
            UPDATE_1_CHECK;
          }
        }
        else
        {
          UPDATE_1_CHECK;
          prob = probs + IsRepG1 + state;
          IF_BIT_0_CHECK(prob)
          {
            UPDATE_0_CHECK;
          }
          else
          {
            UPDATE_1_CHECK;
            prob = probs + IsRepG2 + state;
            IF_BIT_0_CHECK(prob)
            {
              UPDATE_0_CHECK;
            }
            else
            {
              UPDATE_1_CHECK;
            }
          }
        }
        state = kNumStates;
        prob = probs + RepLenCoder;
      }
      {
        unsigned limit, offset;
        CLzmaProb *probLen = prob + LenChoice;
        IF_BIT_0_CHECK(probLen)
        {
          UPDATE_0_CHECK;
          probLen = prob + LenLow + (posState << kLenNumLowBits);
          offset = 0;
          limit = 1 << kLenNumLowBits;
        }
        else
        {
          UPDATE_1_CHECK;
          probLen = prob + LenChoice2;
          IF_BIT_0_CHECK(probLen)
          {
            UPDATE_0_CHECK;
            probLen = prob + LenMid + (posState << kLenNumMidBits);
            offset = kLenNumLowSymbols;
            limit = 1 << kLenNumMidBits;
          }
          else
          {
            UPDATE_1_CHECK;
            probLen = prob + LenHigh;
            offset = kLenNumLowSymbols + kLenNumMidSymbols;
            limit = 1 << kLenNumHighBits;
          }
        }
        TREE_DECODE_CHECK(probLen, limit, len);
        len += offset;
      }

      if (state < 4)
      {
        unsigned posSlot;
        prob = probs + PosSlot +
            ((len < kNumLenToPosStates ? len : kNumLenToPosStates - 1) <<
            kNumPosSlotBits);
        TREE_DECODE_CHECK(prob, 1 << kNumPosSlotBits, posSlot);
        if (posSlot >= kStartPosModelIndex)
        {
          int numDirectBits = ((posSlot >> 1) - 1);

          /* if (bufLimit - buf >= 8) return DUMMY_MATCH; */

          if (posSlot < kEndPosModelIndex)
          {
            prob = probs + SpecPos + ((2 | (posSlot & 1)) << numDirectBits) - posSlot - 1;
          }
          else
          {
            numDirectBits -= kNumAlignBits;
            do
            {
              NORMALIZE_CHECK
              range >>= 1;
              code -= range & (((code - range) >> 31) - 1);
              /* if (code >= range) code -= range; */
            }
            while (--numDirectBits != 0);
            prob = probs + Align;
            numDirectBits = kNumAlignBits;
          }
          {
            unsigned i = 1;
            do
            {
              GET_BIT_CHECK(prob + i, i);
            }
            while (--numDirectBits != 0);
          }
        }
      }
    }
  }
  NORMALIZE_CHECK;
  return res;
}


static void LzmaDec_InitRc(CLzmaDec *p, const Byte *data)
{
  p->code = ((UInt32)data[1] << 24) | ((UInt32)data[2] << 16) | ((UInt32)data[3] << 8) | ((UInt32)data[4]);
  p->range = 0xFFFFFFFF;
  p->needFlush = 0;
}

STATIC void LzmaDec_InitDicAndState(CLzmaDec *p, Bool initDic, Bool initState)
{
  p->needFlush = 1;
  p->remainLen = 0;
  p->tempBufSize = 0;

  if (initDic)
  {
    p->processedPos = 0;
    p->checkDicSize = 0;
    p->needInitState = 1;
  }
  if (initState)
    p->needInitState = 1;
}

STATIC void LzmaDec_Init(CLzmaDec *p)
{
  p->dicPos = 0;
  LzmaDec_InitDicAndState(p, True, True);
}

static void LzmaDec_InitStateReal(CLzmaDec *p)
{
  UInt32 numProbs = Literal + ((UInt32)LZMA_LIT_SIZE << (p->prop.lc + p->prop.lp));
  UInt32 i;
  CLzmaProb *probs = p->probs;
  for (i = 0; i < numProbs; i++)
    probs[i] = kBitModelTotal >> 1;
  p->reps[0] = p->reps[1] = p->reps[2] = p->reps[3] = 1;
  p->state = 0;
  p->needInitState = 0;
}

STATIC SRes LzmaDec_DecodeToDic(CLzmaDec *p, size_t dicLimit, const Byte *src, size_t *srcLen,
    ELzmaFinishMode finishMode, ELzmaStatus *status)
{
  size_t inSize = *srcLen;
  (*srcLen) = 0;
  LzmaDec_WriteRem(p, dicLimit);

  *status = LZMA_STATUS_NOT_SPECIFIED;

  while (p->remainLen != kMatchSpecLenStart)
  {
      int checkEndMarkNow;

      if (p->needFlush != 0)
      {
        for (; inSize > 0 && p->tempBufSize < RC_INIT_SIZE; (*srcLen)++, inSize--)
          p->tempBuf[p->tempBufSize++] = *src++;
        if (p->tempBufSize < RC_INIT_SIZE)
        {
          *status = LZMA_STATUS_NEEDS_MORE_INPUT;
          return SZ_OK;
        }
        if (p->tempBuf[0] != 0)
          return SZ_ERROR_DATA;

        LzmaDec_InitRc(p, p->tempBuf);
        p->tempBufSize = 0;
      }

      checkEndMarkNow = 0;
      if (p->dicPos >= dicLimit)
      {
        if (p->remainLen == 0 && p->code == 0)
        {
          *status = LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK;
          return SZ_OK;
        }
        if (finishMode == LZMA_FINISH_ANY)
        {
          *status = LZMA_STATUS_NOT_FINISHED;
          return SZ_OK;
        }
        if (p->remainLen != 0)
        {
          *status = LZMA_STATUS_NOT_FINISHED;
          return SZ_ERROR_DATA;
        }
        checkEndMarkNow = 1;
      }

      if (p->needInitState)
        LzmaDec_InitStateReal(p);

      if (p->tempBufSize == 0)
      {
        size_t processed;
        const Byte *bufLimit;
        if (inSize < LZMA_REQUIRED_INPUT_MAX || checkEndMarkNow)
        {
          int dummyRes = LzmaDec_TryDummy(p, src, inSize);
          if (dummyRes == DUMMY_ERROR)
          {
            memcpy(p->tempBuf, src, inSize);
            p->tempBufSize = (unsigned)inSize;
            (*srcLen) += inSize;
            *status = LZMA_STATUS_NEEDS_MORE_INPUT;
            return SZ_OK;
          }
          if (checkEndMarkNow && dummyRes != DUMMY_MATCH)
          {
            *status = LZMA_STATUS_NOT_FINISHED;
            return SZ_ERROR_DATA;
          }
          bufLimit = src;
        }
        else
          bufLimit = src + inSize - LZMA_REQUIRED_INPUT_MAX;
        p->buf = src;
        if (LzmaDec_DecodeReal2(p, dicLimit, bufLimit) != 0)
          return SZ_ERROR_DATA;
        processed = (size_t)(p->buf - src);
        (*srcLen) += processed;
        src += processed;
        inSize -= processed;
      }
      else
      {
        unsigned rem = p->tempBufSize, lookAhead = 0;
        while (rem < LZMA_REQUIRED_INPUT_MAX && lookAhead < inSize)
          p->tempBuf[rem++] = src[lookAhead++];
        p->tempBufSize = rem;
        if (rem < LZMA_REQUIRED_INPUT_MAX || checkEndMarkNow)
        {
          int dummyRes = LzmaDec_TryDummy(p, p->tempBuf, rem);
          if (dummyRes == DUMMY_ERROR)
          {
            (*srcLen) += lookAhead;
            *status = LZMA_STATUS_NEEDS_MORE_INPUT;
            return SZ_OK;
          }
          if (checkEndMarkNow && dummyRes != DUMMY_MATCH)
          {
            *status = LZMA_STATUS_NOT_FINISHED;
            return SZ_ERROR_DATA;
          }
        }
        p->buf = p->tempBuf;
        if (LzmaDec_DecodeReal2(p, dicLimit, p->buf) != 0)
          return SZ_ERROR_DATA;
        lookAhead -= (rem - (unsigned)(p->buf - p->tempBuf));
        (*srcLen) += lookAhead;
        src += lookAhead;
        inSize -= lookAhead;
        p->tempBufSize = 0;
      }
  }
  if (p->code == 0)
    *status = LZMA_STATUS_FINISHED_WITH_MARK;
  return (p->code == 0) ? SZ_OK : SZ_ERROR_DATA;
}

STATIC void LzmaDec_FreeProbs(CLzmaDec *p)
{
  SzFree(p->probs);
  p->probs = 0;
}

STATIC SRes LzmaProps_Decode(CLzmaProps *p, const Byte *data, unsigned size)
{
  UInt32 dicSize;
  Byte d;

  if (size < LZMA_PROPS_SIZE)
    return SZ_ERROR_UNSUPPORTED;
  else
    dicSize = data[1] | ((UInt32)data[2] << 8) | ((UInt32)data[3] << 16) | ((UInt32)data[4] << 24);

  if (dicSize < LZMA_DIC_MIN)
    dicSize = LZMA_DIC_MIN;
  p->dicSize = dicSize;

  d = data[0];
  if (d >= (9 * 5 * 5))
    return SZ_ERROR_UNSUPPORTED;

  p->lc = d % 9;
  d /= 9;
  p->pb = d / 5;
  p->lp = d % 5;

  return SZ_OK;
}

static SRes LzmaDec_AllocateProbs2(CLzmaDec *p, const CLzmaProps *propNew)
{
  UInt32 numProbs = LzmaProps_GetNumProbs(propNew);
  if (p->probs == 0 || numProbs != p->numProbs)
  {
    LzmaDec_FreeProbs(p);
    p->probs = (CLzmaProb *)SzAlloc(numProbs * sizeof(CLzmaProb));
    p->numProbs = numProbs;
    if (p->probs == 0)
      return SZ_ERROR_MEM;
  }
  return SZ_OK;
}

STATIC SRes LzmaDec_AllocateProbs(CLzmaDec *p, const Byte *props, unsigned propsSize)
{
  CLzmaProps propNew;
  RINOK(LzmaProps_Decode(&propNew, props, propsSize));
  RINOK(LzmaDec_AllocateProbs2(p, &propNew));
  p->prop = propNew;
  return SZ_OK;
}

/* 7zIn.c -- 7z Input functions */

#if 0
/* Using 'S' instead of '7' in the beginning so that the 7-Zip signature
 * won't be detected with the SFX binary. Will replace it with '7' later.
 */
STATIC const Byte k7zSignature[k7zSignatureSize] = {'7', 'z', 0xBC, 0xAF, 0x27, 0x1C};
#endif

#if 0
/* This is a nice trick, but unfortunately it's not a const expression.
 * http://stackoverflow.com/questions/4286671/endianness-conversion-in-arm
 */
STATIC const char isBigEndian = (*(UInt16*)"\0\xff" < 0x100);
#endif

/* gcc -m64 -dM -E - </dev/null defines: i386 __i386 __i386__ __x86_64
 * __x86_64__ __amd64 __amd64__
 */
#ifdef MY_CPU_LE_UNALIGN
#define IS_7Z_SIGNATURE(p) (*(const UInt16*)(p) == ('z' << 8 | '7') && *(const UInt32*)((const UInt16*)(p) + 1) == 0x1C27AFBC)
#else
STATIC const Byte k57zSignature[k7zSignatureSize - 1] = {'z', 0xBC, 0xAF, 0x27, 0x1C};
/* We check the 1st byte separately to avoid having k7ZSignature in the
 * executable .rodata, thus detecting our signature instea of the .7z file in an sfx.
 */
#define IS_7Z_SIGNATURE(p) (((const Byte*)(p))[0] == '7' && 0 == memcmp((const Byte*)(p) + 1, k57zSignature, 5))
#endif

#define RINOM(x) { if ((x) == 0) return SZ_ERROR_MEM; }

#define NUM_FOLDER_CODERS_MAX 32
#define NUM_CODER_STREAMS_MAX 32

static void SzCoderInfo_Init(CSzCoderInfo *p) {
  p->Props = NULL;
  p->PropsSize = 0;
}

static void SzCoderInfo_Free(CSzCoderInfo *p)
{
  SzFree(p->Props);
  SzCoderInfo_Init(p);
}

STATIC void SzFolder_Init(CSzFolder *p)
{
  p->Coders = 0;
  p->BindPairs = 0;
  p->PackStreams = 0;
  p->UnpackSizes = 0;
  p->NumCoders = 0;
  p->NumBindPairs = 0;
  p->NumPackStreams = 0;
  p->UnpackCRCDefined = 0;
  p->UnpackCRC = 0;
  p->NumUnpackStreams = 0;
}

STATIC void SzFolder_Free(CSzFolder *p)
{
  UInt32 i;
  if (p->Coders)
    for (i = 0; i < p->NumCoders; i++)
      SzCoderInfo_Free(&p->Coders[i]);
  SzFree(p->Coders);
  SzFree(p->BindPairs);
  SzFree(p->PackStreams);
  SzFree(p->UnpackSizes);
  SzFolder_Init(p);
}

STATIC UInt32 SzFolder_GetNumOutStreams(CSzFolder *p)
{
  UInt32 result = 0;
  UInt32 i;
  for (i = 0; i < p->NumCoders; i++)
    result += p->Coders[i].NumOutStreams;
  return result;
}

STATIC int SzFolder_FindBindPairForInStream(CSzFolder *p, UInt32 inStreamIndex)
{
  UInt32 i;
  for (i = 0; i < p->NumBindPairs; i++)
    if (p->BindPairs[i].InIndex == inStreamIndex)
      return i;
  return -1;
}


STATIC int SzFolder_FindBindPairForOutStream(CSzFolder *p, UInt32 outStreamIndex)
{
  UInt32 i;
  for (i = 0; i < p->NumBindPairs; i++)
    if (p->BindPairs[i].OutIndex == outStreamIndex)
      return i;
  return -1;
}

STATIC UInt64 SzFolder_GetUnpackSize(CSzFolder *p)
{
  int i = (int)SzFolder_GetNumOutStreams(p);
  if (i == 0)
    return 0;
  for (i--; i >= 0; i--)
    if (SzFolder_FindBindPairForOutStream(p, i) < 0)
      return p->UnpackSizes[i];
  /* throw 1; */
  return 0;
}

STATIC void SzAr_Init(CSzAr *p)
{
  p->PackSizes = 0;
  p->PackCRCsDefined = 0;
  p->PackCRCs = 0;
  p->Folders = 0;
  p->Files = 0;
  p->NumPackStreams = 0;
  p->NumFolders = 0;
  p->NumFiles = 0;
}

STATIC void SzAr_Free(CSzAr *p)
{
  UInt32 i;
  if (p->Folders)
    for (i = 0; i < p->NumFolders; i++)
      SzFolder_Free(&p->Folders[i]);

  SzFree(p->PackSizes);
  SzFree(p->PackCRCsDefined);
  SzFree(p->PackCRCs);
  SzFree(p->Folders);
  SzFree(p->Files);
  SzAr_Init(p);
}


static void SzArEx_Init(CSzArEx *p)
{
  SzAr_Init(&p->db);
  p->FolderStartPackStreamIndex = 0;
  p->PackStreamStartPositions = 0;
  p->FolderStartFileIndex = 0;
  p->FileIndexToFolderIndexMap = 0;
  p->FileNameOffsets = 0;
  p->FileNamesInHeaderBufPtr = 0;
  p->HeaderBufStart = 0;
}

STATIC void SzArEx_Free(CSzArEx *p)
{
  SzFree(p->FolderStartPackStreamIndex);
  SzFree(p->PackStreamStartPositions);
  SzFree(p->FolderStartFileIndex);
  SzFree(p->FileIndexToFolderIndexMap);

  SzFree(p->FileNameOffsets);
  SzFree(p->HeaderBufStart);

  SzAr_Free(&p->db);
  SzArEx_Init(p);
}

/*
UInt64 GetFolderPackStreamSize(int folderIndex, int streamIndex) const
{
  return PackSizes[FolderStartPackStreamIndex[folderIndex] + streamIndex];
}

UInt64 GetFilePackSize(int fileIndex) const
{
  int folderIndex = FileIndexToFolderIndexMap[fileIndex];
  if (folderIndex >= 0)
  {
    const CSzFolder &folderInfo = Folders[folderIndex];
    if (FolderStartFileIndex[folderIndex] == fileIndex)
    return GetFolderFullPackSize(folderIndex);
  }
  return 0;
}
*/

#define MY_ALLOC(T, p, size) { if ((size) == 0) p = 0; else \
  if ((p = (T *)SzAlloc((size) * sizeof(T))) == 0) return SZ_ERROR_MEM; }

static SRes SzArEx_Fill(CSzArEx *p)
{
  UInt32 startPos = 0;
  UInt64 startPosSize = 0;
  UInt32 i;
  UInt32 folderIndex = 0;
  UInt32 indexInFolder = 0;

  MY_ALLOC(UInt32, p->FolderStartPackStreamIndex, p->db.NumFolders);
  for (i = 0; i < p->db.NumFolders; i++)
  {
    p->FolderStartPackStreamIndex[i] = startPos;
    startPos += p->db.Folders[i].NumPackStreams;
  }

  MY_ALLOC(UInt64, p->PackStreamStartPositions, p->db.NumPackStreams);

  for (i = 0; i < p->db.NumPackStreams; i++)
  {
    p->PackStreamStartPositions[i] = startPosSize;
    startPosSize += p->db.PackSizes[i];
  }

  MY_ALLOC(UInt32, p->FolderStartFileIndex, p->db.NumFolders);
  MY_ALLOC(UInt32, p->FileIndexToFolderIndexMap, p->db.NumFiles);

  for (i = 0; i < p->db.NumFiles; i++)
  {
    CSzFileItem *file = p->db.Files + i;
    int emptyStream = !file->HasStream;
    if (emptyStream && indexInFolder == 0)
    {
      p->FileIndexToFolderIndexMap[i] = (UInt32)-1;
      continue;
    }
    if (indexInFolder == 0)
    {
      /*
      v3.13 incorrectly worked with empty folders
      v4.07: Loop for skipping empty folders
      */
      for (;;)
      {
        if (folderIndex >= p->db.NumFolders)
          return SZ_ERROR_ARCHIVE;
        p->FolderStartFileIndex[folderIndex] = i;
        if (p->db.Folders[folderIndex].NumUnpackStreams != 0)
          break;
        folderIndex++;
      }
    }
    p->FileIndexToFolderIndexMap[i] = folderIndex;
    if (emptyStream)
      continue;
    indexInFolder++;
    if (indexInFolder >= p->db.Folders[folderIndex].NumUnpackStreams)
    {
      folderIndex++;
      indexInFolder = 0;
    }
  }
  return SZ_OK;
}


STATIC UInt64 SzArEx_GetFolderStreamPos(const CSzArEx *p, UInt32 folderIndex, UInt32 indexInFolder)
{
  return p->dataPos +
    p->PackStreamStartPositions[p->FolderStartPackStreamIndex[folderIndex] + indexInFolder];
}

typedef struct _CSzState
{
  Byte *Data;
  size_t Size;
} CSzData;

static SRes SzReadByte(CSzData *sd, Byte *b)
{
  if (sd->Size == 0)
    return SZ_ERROR_ARCHIVE;
  sd->Size--;
  *b = *sd->Data++;
  return SZ_OK;
}

static SRes SzReadBytes(CSzData *sd, Byte *data, size_t size)
{
  size_t i;
  for (i = 0; i < size; i++)
  {
    RINOK(SzReadByte(sd, data + i));
  }
  return SZ_OK;
}

static SRes SzReadUInt32(CSzData *sd, UInt32 *value)
{
  int i;
  *value = 0;
  for (i = 0; i < 4; i++)
  {
    Byte b;
    RINOK(SzReadByte(sd, &b));
    *value |= ((UInt32)(b) << (8 * i));
  }
  return SZ_OK;
}

static SRes SzReadNumber(CSzData *sd, UInt64 *value)
{
  Byte firstByte;
  Byte mask = 0x80;
  int i;
  RINOK(SzReadByte(sd, &firstByte));
  *value = 0;
  for (i = 0; i < 8; i++)
  {
    Byte b;
    if ((firstByte & mask) == 0)
    {
      UInt64 highPart = firstByte & (mask - 1);
      *value += (highPart << (8 * i));
      return SZ_OK;
    }
    RINOK(SzReadByte(sd, &b));
    *value |= ((UInt64)b << (8 * i));
    mask >>= 1;
  }
  return SZ_OK;
}

static SRes SzReadNumber32(CSzData *sd, UInt32 *value)
{
  UInt64 value64;
  RINOK(SzReadNumber(sd, &value64));
  if (value64 >= 0x80000000)
    return SZ_ERROR_UNSUPPORTED;
  if (value64 >= ((UInt64)(1) << ((sizeof(size_t) - 1) * 8 + 2)))
    return SZ_ERROR_UNSUPPORTED;
  *value = (UInt32)value64;
  return SZ_OK;
}

static SRes SzReadID(CSzData *sd, UInt64 *value)
{
  return SzReadNumber(sd, value);
}

static SRes SzSkeepDataSize(CSzData *sd, UInt64 size)
{
  if (size > sd->Size)
    return SZ_ERROR_ARCHIVE;
  sd->Size -= (size_t)size;
  sd->Data += (size_t)size;
  return SZ_OK;
}

static SRes SzSkeepData(CSzData *sd)
{
  UInt64 size;
  RINOK(SzReadNumber(sd, &size));
  return SzSkeepDataSize(sd, size);
}

static SRes SzReadArchiveProperties(CSzData *sd)
{
  for (;;)
  {
    UInt64 type;
    RINOK(SzReadID(sd, &type));
    if (type == k7zIdEnd)
      break;
    SzSkeepData(sd);
  }
  return SZ_OK;
}

static SRes SzWaitAttribute(CSzData *sd, UInt64 attribute)
{
  for (;;)
  {
    UInt64 type;
    RINOK(SzReadID(sd, &type));
    if (type == attribute)
      return SZ_OK;
    if (type == k7zIdEnd)
      return SZ_ERROR_ARCHIVE;
    RINOK(SzSkeepData(sd));
  }
}

static SRes SzReadBoolVector(CSzData *sd, size_t numItems, Byte **v)
{
  Byte b = 0;
  Byte mask = 0;
  size_t i;
  MY_ALLOC(Byte, *v, numItems);
  for (i = 0; i < numItems; i++)
  {
    if (mask == 0)
    {
      RINOK(SzReadByte(sd, &b));
      mask = 0x80;
    }
    (*v)[i] = (Byte)(((b & mask) != 0) ? 1 : 0);
    mask >>= 1;
  }
  return SZ_OK;
}

static SRes SzReadBoolVector2(CSzData *sd, size_t numItems, Byte **v)
{
  Byte allAreDefined;
  size_t i;
  RINOK(SzReadByte(sd, &allAreDefined));
  if (allAreDefined == 0)
    return SzReadBoolVector(sd, numItems, v);
  MY_ALLOC(Byte, *v, numItems);
  for (i = 0; i < numItems; i++)
    (*v)[i] = 1;
  return SZ_OK;
}

static SRes SzReadHashDigests(
    CSzData *sd,
    size_t numItems,
    Byte **digestsDefined,
    UInt32 **digests)
{
  size_t i;
  RINOK(SzReadBoolVector2(sd, numItems, digestsDefined));
  MY_ALLOC(UInt32, *digests, numItems);
  for (i = 0; i < numItems; i++)
    if ((*digestsDefined)[i])
    {
      RINOK(SzReadUInt32(sd, (*digests) + i));
    }
  return SZ_OK;
}

static SRes SzReadPackInfo(
    CSzData *sd,
    UInt64 *dataOffset,
    UInt32 *numPackStreams,
    UInt64 **packSizes,
    Byte **packCRCsDefined,
    UInt32 **packCRCs)
{
  UInt32 i;
  RINOK(SzReadNumber(sd, dataOffset));
  RINOK(SzReadNumber32(sd, numPackStreams));

  RINOK(SzWaitAttribute(sd, k7zIdSize));

  MY_ALLOC(UInt64, *packSizes, (size_t)*numPackStreams);

  for (i = 0; i < *numPackStreams; i++)
  {
    RINOK(SzReadNumber(sd, (*packSizes) + i));
  }

  for (;;)
  {
    UInt64 type;
    RINOK(SzReadID(sd, &type));
    if (type == k7zIdEnd)
      break;
    if (type == k7zIdCRC)
    {
      RINOK(SzReadHashDigests(sd, (size_t)*numPackStreams, packCRCsDefined, packCRCs));
      continue;
    }
    RINOK(SzSkeepData(sd));
  }
  if (*packCRCsDefined == 0)
  {
    MY_ALLOC(Byte, *packCRCsDefined, (size_t)*numPackStreams);
    MY_ALLOC(UInt32, *packCRCs, (size_t)*numPackStreams);
    for (i = 0; i < *numPackStreams; i++)
    {
      (*packCRCsDefined)[i] = 0;
      (*packCRCs)[i] = 0;
    }
  }
  return SZ_OK;
}

static SRes SzReadSwitch(CSzData *sd)
{
  Byte external;
  RINOK(SzReadByte(sd, &external));
  return (external == 0) ? SZ_OK: SZ_ERROR_UNSUPPORTED;
}

static SRes SzGetNextFolderItem(CSzData *sd, CSzFolder *folder)
{
  UInt32 numCoders, numBindPairs, numPackStreams, i;
  UInt32 numInStreams = 0, numOutStreams = 0;

  RINOK(SzReadNumber32(sd, &numCoders));
  if (numCoders > NUM_FOLDER_CODERS_MAX)
    return SZ_ERROR_UNSUPPORTED;
  folder->NumCoders = numCoders;

  MY_ALLOC(CSzCoderInfo, folder->Coders, (size_t)numCoders);

  for (i = 0; i < numCoders; i++)
    SzCoderInfo_Init(folder->Coders + i);

  for (i = 0; i < numCoders; i++)
  {
    Byte mainByte;
    CSzCoderInfo *coder = folder->Coders + i;
    {
      unsigned idSize, j;
      Byte longID[15];
      RINOK(SzReadByte(sd, &mainByte));
      idSize = (unsigned)(mainByte & 0xF);
      RINOK(SzReadBytes(sd, longID, idSize));
      if (idSize > sizeof(coder->MethodID))
        return SZ_ERROR_UNSUPPORTED;
      coder->MethodID = 0;
      for (j = 0; j < idSize; j++)
        coder->MethodID |= (UInt64)longID[idSize - 1 - j] << (8 * j);

      if ((mainByte & 0x10) != 0)
      {
        RINOK(SzReadNumber32(sd, &coder->NumInStreams));
        RINOK(SzReadNumber32(sd, &coder->NumOutStreams));
        if (coder->NumInStreams > NUM_CODER_STREAMS_MAX ||
            coder->NumOutStreams > NUM_CODER_STREAMS_MAX)
          return SZ_ERROR_UNSUPPORTED;
      }
      else
      {
        coder->NumInStreams = 1;
        coder->NumOutStreams = 1;
      }
      if ((mainByte & 0x20) != 0)
      {
        UInt64 propertiesSize = 0;
        RINOK(SzReadNumber(sd, &propertiesSize));
        coder->PropsSize = propertiesSize;
        if (coder->PropsSize != propertiesSize ||
           (coder->PropsSize != 0 && !(coder->Props = (Byte*)SzAlloc(coder->PropsSize)))) return SZ_ERROR_MEM;
        RINOK(SzReadBytes(sd, coder->Props, coder->PropsSize));
      }
    }
    while ((mainByte & 0x80) != 0)
    {
      RINOK(SzReadByte(sd, &mainByte));
      RINOK(SzSkeepDataSize(sd, (mainByte & 0xF)));
      if ((mainByte & 0x10) != 0)
      {
        UInt32 n;
        RINOK(SzReadNumber32(sd, &n));
        RINOK(SzReadNumber32(sd, &n));
      }
      if ((mainByte & 0x20) != 0)
      {
        UInt64 propertiesSize = 0;
        RINOK(SzReadNumber(sd, &propertiesSize));
        RINOK(SzSkeepDataSize(sd, propertiesSize));
      }
    }
    numInStreams += coder->NumInStreams;
    numOutStreams += coder->NumOutStreams;
  }

  if (numOutStreams == 0)
    return SZ_ERROR_UNSUPPORTED;

  folder->NumBindPairs = numBindPairs = numOutStreams - 1;
  MY_ALLOC(CSzBindPair, folder->BindPairs, (size_t)numBindPairs);

  for (i = 0; i < numBindPairs; i++)
  {
    CSzBindPair *bp = folder->BindPairs + i;
    RINOK(SzReadNumber32(sd, &bp->InIndex));
    RINOK(SzReadNumber32(sd, &bp->OutIndex));
  }

  if (numInStreams < numBindPairs)
    return SZ_ERROR_UNSUPPORTED;

  folder->NumPackStreams = numPackStreams = numInStreams - numBindPairs;
  MY_ALLOC(UInt32, folder->PackStreams, (size_t)numPackStreams);

  if (numPackStreams == 1)
  {
    for (i = 0; i < numInStreams ; i++)
      if (SzFolder_FindBindPairForInStream(folder, i) < 0)
        break;
    if (i == numInStreams)
      return SZ_ERROR_UNSUPPORTED;
    folder->PackStreams[0] = i;
  }
  else
    for (i = 0; i < numPackStreams; i++)
    {
      RINOK(SzReadNumber32(sd, folder->PackStreams + i));
    }
  return SZ_OK;
}

static SRes SzReadUnpackInfo(
    CSzData *sd,
    UInt32 *numFolders,
    CSzFolder **folders)  /* for alloc */
{
  UInt32 i;
  RINOK(SzWaitAttribute(sd, k7zIdFolder));
  RINOK(SzReadNumber32(sd, numFolders));
  {
    RINOK(SzReadSwitch(sd));

    MY_ALLOC(CSzFolder, *folders, (size_t)*numFolders);

    for (i = 0; i < *numFolders; i++)
      SzFolder_Init((*folders) + i);

    for (i = 0; i < *numFolders; i++)
    {
      RINOK(SzGetNextFolderItem(sd, (*folders) + i));
    }
  }

  RINOK(SzWaitAttribute(sd, k7zIdCodersUnpackSize));

  for (i = 0; i < *numFolders; i++)
  {
    UInt32 j;
    CSzFolder *folder = (*folders) + i;
    UInt32 numOutStreams = SzFolder_GetNumOutStreams(folder);

    MY_ALLOC(UInt64, folder->UnpackSizes, (size_t)numOutStreams);

    for (j = 0; j < numOutStreams; j++)
    {
      RINOK(SzReadNumber(sd, folder->UnpackSizes + j));
    }
  }

  for (;;)
  {
    UInt64 type;
    RINOK(SzReadID(sd, &type));
    if (type == k7zIdEnd)
      return SZ_OK;
    if (type == k7zIdCRC)
    {
      SRes res;
      Byte *crcsDefined = 0;
      UInt32 *crcs = 0;
      res = SzReadHashDigests(sd, *numFolders, &crcsDefined, &crcs);
      if (res == SZ_OK)
      {
        for (i = 0; i < *numFolders; i++)
        {
          CSzFolder *folder = (*folders) + i;
          folder->UnpackCRCDefined = crcsDefined[i];
          folder->UnpackCRC = crcs[i];
        }
      }
      SzFree(crcs);
      SzFree(crcsDefined);
      RINOK(res);
      continue;
    }
    RINOK(SzSkeepData(sd));
  }
}

static SRes SzReadSubStreamsInfo(
    CSzData *sd,
    UInt32 numFolders,
    CSzFolder *folders,
    UInt32 *numUnpackStreams,
    UInt64 **unpackSizes,
    Byte **digestsDefined,
    UInt32 **digests)
{
  UInt64 type = 0;
  UInt32 i;
  UInt32 si = 0;
  UInt32 numDigests = 0;

  for (i = 0; i < numFolders; i++)
    folders[i].NumUnpackStreams = 1;
  *numUnpackStreams = numFolders;

  for (;;)
  {
    RINOK(SzReadID(sd, &type));
    if (type == k7zIdNumUnpackStream)
    {
      *numUnpackStreams = 0;
      for (i = 0; i < numFolders; i++)
      {
        UInt32 numStreams;
        RINOK(SzReadNumber32(sd, &numStreams));
        folders[i].NumUnpackStreams = numStreams;
        *numUnpackStreams += numStreams;
      }
      continue;
    }
    if (type == k7zIdCRC || type == k7zIdSize)
      break;
    if (type == k7zIdEnd)
      break;
    RINOK(SzSkeepData(sd));
  }

  if (*numUnpackStreams == 0)
  {
    *unpackSizes = 0;
    *digestsDefined = 0;
    *digests = 0;
  }
  else
  {
    *unpackSizes = (UInt64 *)SzAlloc((size_t)*numUnpackStreams * sizeof(UInt64));
    RINOM(*unpackSizes);
    *digestsDefined = (Byte *)SzAlloc((size_t)*numUnpackStreams * sizeof(Byte));
    RINOM(*digestsDefined);
    *digests = (UInt32 *)SzAlloc((size_t)*numUnpackStreams * sizeof(UInt32));
    RINOM(*digests);
  }

  for (i = 0; i < numFolders; i++)
  {
    /*
    v3.13 incorrectly worked with empty folders
    v4.07: we check that folder is empty
    */
    UInt64 sum = 0;
    UInt32 j;
    UInt32 numSubstreams = folders[i].NumUnpackStreams;
    if (numSubstreams == 0)
      continue;
    if (type == k7zIdSize)
    for (j = 1; j < numSubstreams; j++)
    {
      UInt64 size;
      RINOK(SzReadNumber(sd, &size));
      (*unpackSizes)[si++] = size;
      sum += size;
    }
    (*unpackSizes)[si++] = SzFolder_GetUnpackSize(folders + i) - sum;
  }
  if (type == k7zIdSize)
  {
    RINOK(SzReadID(sd, &type));
  }

  for (i = 0; i < *numUnpackStreams; i++)
  {
    (*digestsDefined)[i] = 0;
    (*digests)[i] = 0;
  }


  for (i = 0; i < numFolders; i++)
  {
    UInt32 numSubstreams = folders[i].NumUnpackStreams;
    if (numSubstreams != 1 || !folders[i].UnpackCRCDefined)
      numDigests += numSubstreams;
  }


  si = 0;
  for (;;)
  {
    if (type == k7zIdCRC)
    {
      int digestIndex = 0;
      Byte *digestsDefined2 = 0;
      UInt32 *digests2 = 0;
      SRes res = SzReadHashDigests(sd, numDigests, &digestsDefined2, &digests2);
      if (res == SZ_OK)
      {
        for (i = 0; i < numFolders; i++)
        {
          CSzFolder *folder = folders + i;
          UInt32 numSubstreams = folder->NumUnpackStreams;
          if (numSubstreams == 1 && folder->UnpackCRCDefined)
          {
            (*digestsDefined)[si] = 1;
            (*digests)[si] = folder->UnpackCRC;
            si++;
          }
          else
          {
            UInt32 j;
            for (j = 0; j < numSubstreams; j++, digestIndex++)
            {
              (*digestsDefined)[si] = digestsDefined2[digestIndex];
              (*digests)[si] = digests2[digestIndex];
              si++;
            }
          }
        }
      }
      SzFree(digestsDefined2);
      SzFree(digests2);
      RINOK(res);
    }
    else if (type == k7zIdEnd)
      return SZ_OK;
    else
    {
      RINOK(SzSkeepData(sd));
    }
    RINOK(SzReadID(sd, &type));
  }
}


static SRes SzReadStreamsInfo(
    CSzData *sd,
    UInt64 *dataOffset,
    CSzAr *p,
    UInt32 *numUnpackStreams,
    UInt64 **unpackSizes, /* allocTemp */
    Byte **digestsDefined,   /* allocTemp */
    UInt32 **digests)        /* allocTemp */
{
  for (;;)
  {
    UInt64 type;
    RINOK(SzReadID(sd, &type));
    if ((UInt64)(int)type != type)
      return SZ_ERROR_UNSUPPORTED;
    switch((int)type)
    {
      case k7zIdEnd:
        return SZ_OK;
      case k7zIdPackInfo:
      {
        RINOK(SzReadPackInfo(sd, dataOffset, &p->NumPackStreams,
            &p->PackSizes, &p->PackCRCsDefined, &p->PackCRCs));
        break;
      }
      case k7zIdUnpackInfo:
      {
        RINOK(SzReadUnpackInfo(sd, &p->NumFolders, &p->Folders));
        break;
      }
      case k7zIdSubStreamsInfo:
      {
        RINOK(SzReadSubStreamsInfo(sd, p->NumFolders, p->Folders,
            numUnpackStreams, unpackSizes, digestsDefined, digests));
        break;
      }
      default:
        return SZ_ERROR_UNSUPPORTED;
    }
  }
}

static SRes SzReadFileNames(const Byte *p, size_t size, UInt32 numFiles, size_t *sizes)
{
  UInt32 i;
  size_t pos = 0;
  for (i = 0; i < numFiles; i++)
  {
    sizes[i] = pos;
    for (;;)
    {
      if (pos >= size)
        return SZ_ERROR_ARCHIVE;
      ++pos;
#ifdef MY_CPU_LE_UNALIGN
      if ((*(UInt16**)&p)++[0] == 0)
        break;
#else
      p += 2;
      if (p[-1] == 0 && p[-2] == 0)
        break;
#endif
    }
  }
  sizes[i] = pos;
  return (pos == size) ? SZ_OK : SZ_ERROR_ARCHIVE;
}

#define RDINOK(x) do { if ((res = (x)) != SZ_OK) goto done; } while(0)
#define RDALLOC(T, p, size) { if ((size) == 0) p = 0; else \
  if ((p = (T *)SzAlloc((size) * sizeof(T))) == 0) { res = SZ_ERROR_MEM; goto done; } }

static SRes SzReadHeader(
    CSzArEx *p,   /* allocMain */
    CSzData *sd) {
  UInt64 *unpackSizes = 0;  /* Unpacked size for each file. SzAlloc(8 * numUnpackStreams). */
  Byte *digestsDefined = 0;  /* SzAlloc(numUnpackStreams). */
  UInt32 *digests = 0;  /* SzAlloc(4 * numUnpackStreams). */
  Byte *emptyStreamVector = 0;  /* SzAlloc(numFiles) or NULL. */
  Byte *emptyFileVector = 0;
  Byte *lwtVector = 0;  /* SzAlloc(numFiles), only temporarily. */
  UInt64 type;
  UInt32 numUnpackStreams = 0;  /* numUnpackStreams <= numFiles. */
  UInt32 numFiles = 0;
  CSzFileItem *files = 0;
  UInt32 numEmptyStreams = 0;
  UInt32 i;
  SRes res = SZ_OK;

  RDINOK(SzReadID(sd, &type));

  if (type == k7zIdArchiveProperties)
  {
    RDINOK(SzReadArchiveProperties(sd));
    RDINOK(SzReadID(sd, &type));
  }


  if (type == k7zIdMainStreamsInfo)
  {
    RDINOK(SzReadStreamsInfo(sd,
        &p->dataPos,
        &p->db,
        &numUnpackStreams,
        &unpackSizes,
        &digestsDefined,
        &digests));
    p->dataPos += p->startPosAfterHeader;
    RDINOK(SzReadID(sd, &type));
  }

  if (type == k7zIdEnd) goto done;
  if (type != k7zIdFilesInfo) {
    res = SZ_ERROR_ARCHIVE;
    goto done;
  }

  RDINOK(SzReadNumber32(sd, &numFiles));
  p->db.NumFiles = numFiles;

  RDALLOC(CSzFileItem, files, (size_t)numFiles);

  p->db.Files = files;
  for (i = 0; i < numFiles; i++) {
    CSzFileItem *p = files + i;
    /* p->Size will be initialized later. */
    /* p->HasStream will be initialized later. */
    /* p->IsDir will be initialized later. */
    /* p->MTime will be initialized later, conditionally. */
    p->MTimeDefined = 0;
    /* p->Crc will be initialized later, conditionally */
    p->CrcDefined = 0;
    p->Attrib = (UInt32)-1;
  }

  for (;;)
  {
    UInt64 type;
    UInt64 size;
    RDINOK(SzReadID(sd, &type));
    if (type == k7zIdEnd)
      break;
    RDINOK(SzReadNumber(sd, &size));
    if (size > sd->Size) {
      res = SZ_ERROR_ARCHIVE;
      goto done;
    }
    if ((UInt64)(int)type != type)
    {
      RDINOK(SzSkeepDataSize(sd, size));
    }
    else
    switch((int)type)
    {
      case k7zIdName:
      {
        size_t namesSize;
        RDINOK(SzReadSwitch(sd));
        namesSize = (size_t)size - 1;
        if ((namesSize & 1) != 0) {
          res = SZ_ERROR_ARCHIVE;
          goto done;
        }
        /* if (!(p->FileNamesPtr = SzAlloc( namesSize))) */
        RDALLOC(size_t, p->FileNameOffsets, numFiles + 1);  /* SzAlloc(4 * numFiles + 4).; */
        p->FileNamesInHeaderBufPtr = sd->Data;
        /* memcpy(p->FileNamesPtr, sd->Data, namesSize); */
        RDINOK(SzReadFileNames(sd->Data, namesSize >> 1, numFiles, p->FileNameOffsets));
        RDINOK(SzSkeepDataSize(sd, namesSize));
        break;
      }
      case k7zIdEmptyStream:
      {
        RDINOK(SzReadBoolVector(sd, numFiles, &emptyStreamVector));  /* SzAlloc(numFiles). */
        numEmptyStreams = 0;
        for (i = 0; i < numFiles; i++)
          if (emptyStreamVector[i])
            numEmptyStreams++;
        break;
      }
      case k7zIdEmptyFile:
      {
        RDINOK(SzReadBoolVector(sd, numEmptyStreams, &emptyFileVector));  /* SzAlloc(numEmptyStreams), can be as much as SzAlloc(numFiles). */
        break;
      }
      case k7zIdWinAttributes:
      {
        RDINOK(SzReadBoolVector2(sd, numFiles, &lwtVector));  /* SzAlloc(numFiles), will get freed quickly. */
        RDINOK(SzReadSwitch(sd));
        for (i = 0; i < numFiles; i++)
        {
          CSzFileItem *file = &files[i];
          if (lwtVector[i]) {
            RDINOK(SzReadUInt32(sd, &file->Attrib));
          }
        }
        SzFree(lwtVector);
        lwtVector = NULL;
        break;
      }
      case k7zIdMTime:
      {
        RDINOK(SzReadBoolVector2(sd, numFiles, &lwtVector));  /* SzAlloc(numFiles), will get freed quickly. */
        RDINOK(SzReadSwitch(sd));
        for (i = 0; i < numFiles; i++)
        {
          CSzFileItem *file = &files[i];
          if (lwtVector[i]) {
            file->MTimeDefined = 1;
            RDINOK(SzReadUInt32(sd, &file->MTime.Low));
            RDINOK(SzReadUInt32(sd, &file->MTime.High));
          }
        }
        SzFree(lwtVector);
        lwtVector = NULL;
        break;
      }
      default:
      {
        RDINOK(SzSkeepDataSize(sd, size));
      }
    }
  }

  {
    UInt32 emptyFileIndex = 0;
    UInt32 sizeIndex = 0;
    for (i = 0; i < numFiles; i++) {
      CSzFileItem *file = files + i;
      file->HasStream = !emptyStreamVector || !emptyStreamVector[i];
      if (file->HasStream) {
        file->IsDir = 0;
        file->Size = unpackSizes[sizeIndex];
        file->Crc = digests[sizeIndex];
        file->CrcDefined = digestsDefined[sizeIndex];
        sizeIndex++;
      } else {
        file->IsDir = !emptyFileVector || !emptyFileVector[emptyFileIndex];
        file->Size = 0;
        emptyFileIndex++;
      }
    }
  }

 done:
  SzFree(unpackSizes);
  SzFree(digestsDefined);
  SzFree(digests);
  SzFree(emptyStreamVector);
  SzFree(emptyFileVector);
  SzFree(lwtVector);
  return res == SZ_OK ? SzArEx_Fill(p) : res;
}

/* Merging this function SzReadAndDecodePackedStreams2 with
 * SzReadAndDecodePackedStreams actually increases the executable size of
 * tiny7zx.
 */
static SRes SzReadAndDecodePackedStreams2(
    CLookToRead *inStream,
    CSzData *sd,
    Byte **outBuffer,
    size_t *outBufferSize,
    UInt64 baseOffset,
    CSzAr *p,
    UInt64 **unpackSizes,
    Byte **digestsDefined,
    UInt32 **digests)
{

  UInt32 numUnpackStreams = 0;
  UInt64 dataStartPos;
  CSzFolder *folder;
  UInt64 unpackSize;
  SRes res;

  *outBuffer = NULL;
  RINOK(SzReadStreamsInfo(sd, &dataStartPos, p,
      &numUnpackStreams,  unpackSizes, digestsDefined, digests));

  dataStartPos += baseOffset;
  if (p->NumFolders != 1)
    return SZ_ERROR_ARCHIVE;

  folder = p->Folders;
  unpackSize = SzFolder_GetUnpackSize(folder);

#ifdef _SZ_SEEK_DEBUG
  fprintf(stderr, "SEEKN 4\n");
#endif
  RINOK(LookInStream_SeekTo(inStream, dataStartPos));

  *outBufferSize = unpackSize;
  if (*outBufferSize != unpackSize) return SZ_ERROR_MEM;
  if (!(*outBuffer = (Byte*)SzAlloc(unpackSize))) return SZ_ERROR_MEM;

  res = SzFolder_Decode(folder, p->PackSizes,
          inStream, dataStartPos,
          *outBuffer, *outBufferSize);
  RINOK(res);
  if (folder->UnpackCRCDefined)
    if (CrcCalc(*outBuffer, *outBufferSize) != folder->UnpackCRC)
      return SZ_ERROR_CRC;
  return SZ_OK;
}

static SRes SzReadAndDecodePackedStreams(
    CLookToRead *inStream,
    CSzData *sd,
    Byte **outBuffer,
    size_t *outBufferSize,
    UInt64 baseOffset)
{
  CSzAr p;
  UInt64 *unpackSizes = 0;
  Byte *digestsDefined = 0;
  UInt32 *digests = 0;
  SRes res;
  SzAr_Init(&p);
  res = SzReadAndDecodePackedStreams2(inStream, sd, outBuffer, outBufferSize, baseOffset,
    &p, &unpackSizes, &digestsDefined, &digests);
  SzAr_Free(&p);
  SzFree(unpackSizes);
  SzFree(digestsDefined);
  SzFree(digests);
  return res;
}

/* TODO(pts): Make this fast. */
static Int64 FindStartArcPos(CLookToRead *inStream, Byte **buf_out) {
  Int64 ofs = k7zStartHeaderSize;
  Byte *buf, *p, *pend;
  size_t size;
  /* Find k7zSignature in the beginning. */
  while (ofs < (2 << 20)) {  /* 2 MB. */
    size = LookToRead_BUF_SIZE;
    if (LookToRead_Look(inStream, (const void**)&buf, &size) != SZ_OK ||
        size < k7zStartHeaderSize) {
      break;
    }
    size -= k7zStartHeaderSize - 1;  /* size is usually much more. */
    for (p = buf, pend = buf + size;
         p != pend && !IS_7Z_SIGNATURE(p);
         ++p) {}
    if (p != pend) {
      *buf_out = p + k7zSignatureSize;
      return ofs + (p - buf);
    }
    LOOKTOREAD_SKIP(inStream, size);  /* No need for error checking. */
    ofs += size;
  }
  return 0;
}

STATIC SRes SzArEx_Open(
    CSzArEx *p,
    CLookToRead *inStream) {
  Int64 startArcPos;
  UInt64 nextHeaderOffset, nextHeaderSize;
  UInt32 nextHeaderCRC;
  SRes res;
  Byte *buf = 0;
  Byte *bufStart;
  CSzData sd;
  UInt64 type;

  SzArEx_Init(p);
  startArcPos = FindStartArcPos(inStream, &buf);
  if (startArcPos == 0) return SZ_ERROR_NO_ARCHIVE;
  if (buf[0] != k7zMajorVersion) return SZ_ERROR_UNSUPPORTED;

  nextHeaderOffset = GetUi64(buf + 6);
  nextHeaderSize = GetUi64(buf + 14);
  nextHeaderCRC = GetUi32(buf + 22);

  p->startPosAfterHeader = startArcPos;

  if (CrcCalc(buf + 6, 20) != GetUi32(buf + 2))
    return SZ_ERROR_CRC;

  sd.Size = (size_t)nextHeaderSize;
  if (sd.Size != nextHeaderSize)
    return SZ_ERROR_MEM;
  if (sd.Size == 0)
    return SZ_OK;
  if (nextHeaderOffset > nextHeaderOffset + startArcPos)  /* Check for overflow. */
    return SZ_ERROR_NO_ARCHIVE;

  /* If the file is not long enough, we want to return SZ_ERROR_INPUT_EOF, which LookInStream_Read will do for us, so there is no need to check the file size here. */
  /* This is a real seek, actually changing the file offset. */
#ifdef _SZ_SEEK_DEBUG
  fprintf(stderr, "SEEKN 1\n");
#endif
  RINOK(LookInStream_SeekTo(inStream, startArcPos + nextHeaderOffset));


#ifdef _SZ_HEADER_DEBUG
  /* Typically only 36..39 bytes */
  fprintf(stderr, "HEADER read_next size=%ld\n", (long)sd.Size);
#endif
  if (!(bufStart = (Byte*)SzAlloc(sd.Size))) return SZ_ERROR_MEM;
  sd.Data = bufStart;
  /* We need a loop here (implemented by LookToRead_ReadAll) to read
   * sd.Size bytes to sd.Data, because LookToRead_Look_Exact is
   * able to read about 16 kB at once, and we may ned 500 kB or more for the
   * archive header.
   */
  if ((res = LookToRead_ReadAll(inStream, sd.Data, sd.Size)) != SZ_OK) { erra:
    SzFree(bufStart);
    return res;
  }
  if (CrcCalc(sd.Data, sd.Size) != nextHeaderCRC) {
    res = SZ_ERROR_ARCHIVE;
    goto erra;
  }
  if ((res = SzReadID(&sd, &type)) != SZ_OK) goto erra;
  if (type == k7zIdEncodedHeader) {
    CSzData sdu = sd;
#ifdef _SZ_HEADER_DEBUG
    /* Typically happens. */
    fprintf(stderr, "HEADER found_encoded_header\n");
#endif
    res = SzReadAndDecodePackedStreams(inStream, &sdu, &sd.Data, &sd.Size, p->startPosAfterHeader);
    SzFree(bufStart);
    bufStart = sd.Data;
    if (res != SZ_OK) goto erra;
#ifdef _SZ_HEADER_DEBUG
    /* Typical value: 521688 bytes */
    fprintf(stderr, "HEADER encoded_header unpacked size=%lld\n", (long long)sd.Size);
#endif
    if ((res = SzReadID(&sd, &type)) != SZ_OK) goto erra;
  }
  if (type != k7zIdHeader) {
    res = SZ_ERROR_UNSUPPORTED;
    goto erra;
  }
#ifdef _SZ_HEADER_DEBUG
  fprintf(stderr, "HEADER found_header\n");
#endif
  if ((res = SzReadHeader(p, &sd)) != SZ_OK) goto erra;
#ifdef _SZ_HEADER_DEBUG
  {
    const Bool FileNamesInHeaderBufPtr_inside = p->FileNamesInHeaderBufPtr >= bufStart && p->FileNamesInHeaderBufPtr < sd.Data + sd.Size;
    fprintf(stderr, "HEADER FileNamesInHeaderBufPtr_inside=%d\n", FileNamesInHeaderBufPtr_inside);
    if (!FileNamesInHeaderBufPtr_inside) abort();
  }
#endif
  p->HeaderBufStart = bufStart;  /* p takes ownership of the buffer starting at bufStart. */
  return res;
}

STATIC SRes SzArEx_Extract(
    const CSzArEx *p,
    CLookToRead *inStream,
    UInt32 fileIndex,
    UInt32 *blockIndex,
    Byte **outBuffer,
    size_t *outBufferSize,
    size_t *offset,
    size_t *outSizeProcessed)
{
  UInt32 folderIndex = p->FileIndexToFolderIndexMap[fileIndex];
  SRes res = SZ_OK;
  *offset = 0;
  *outSizeProcessed = 0;
  if (folderIndex == (UInt32)-1) {  /* This happens for empty files. */
    *blockIndex = folderIndex;
    return SZ_OK;
  }

  if (*outBuffer == 0 || *blockIndex != folderIndex)
  {
    CSzFolder *folder = p->db.Folders + folderIndex;
    UInt64 unpackSizeSpec = SzFolder_GetUnpackSize(folder);
    size_t unpackSize = (size_t)unpackSizeSpec;
    UInt64 startOffset = SzArEx_GetFolderStreamPos(p, folderIndex, 0);

    if (unpackSize != unpackSizeSpec)
      return SZ_ERROR_MEM;
    *blockIndex = folderIndex;
    SzFree(*outBuffer);
    *outBuffer = 0;

#ifdef _SZ_SEEK_DEBUG
    fprintf(stderr, "SEEKN 5\n");
#endif
    RINOK(LookInStream_SeekTo(inStream, startOffset));

    if (res == SZ_OK)
    {
      *outBufferSize = unpackSize;
      if (unpackSize != 0)
      {
        /* Allocate 1 extra byte for possible NUL-termination later.
         * symlink() needs the NUL.
         */
        *outBuffer = (Byte *)SzAlloc(unpackSize + 1);
        if (*outBuffer == 0)
          res = SZ_ERROR_MEM;
      }
      if (res == SZ_OK)
      {
        res = SzFolder_Decode(folder,
          p->db.PackSizes + p->FolderStartPackStreamIndex[folderIndex],
          inStream, startOffset,
          *outBuffer, unpackSize);
        if (res == SZ_OK)
        {
          if (folder->UnpackCRCDefined)
          {
            if (CrcCalc(*outBuffer, unpackSize) != folder->UnpackCRC)
              res = SZ_ERROR_CRC;
          }
        }
      }
    }
  }
  if (res == SZ_OK)
  {
    UInt32 i;
    CSzFileItem *fileItem = p->db.Files + fileIndex;
    *offset = 0;
    for (i = p->FolderStartFileIndex[folderIndex]; i < fileIndex; i++)
      *offset += (UInt32)p->db.Files[i].Size;
    *outSizeProcessed = (size_t)fileItem->Size;
    if (*offset + *outSizeProcessed > *outBufferSize)
      return SZ_ERROR_FAIL;
    if (fileItem->CrcDefined && CrcCalc(*outBuffer + *offset, *outSizeProcessed) != fileItem->Crc)
      res = SZ_ERROR_CRC;
  }
  return res;
}
