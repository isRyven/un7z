/* Igor Pavlov : Public domain */
/* un7z.h -- un7z interface */

#ifndef __7Z_H
#define __7Z_H
	
#ifdef __cplusplus
extern "C" {
#endif

#ifndef STATIC
#define STATIC
#endif

#include <stddef.h>  /* size_t */

#ifdef _WIN32
	#include <windows.h>
#endif

#ifdef _SZ_NO_INT_64
	/* define _SZ_NO_INT_64, if your compiler doesn't support 64-bit integers.
	   NOTES: Some code will work incorrectly in that case! */

	typedef long Int64;
	typedef unsigned long UInt64;
#else
	#include <stdint.h>

	#if defined(_MSC_VER) || defined(__BORLANDC__)
		typedef __int64 Int64;
		typedef unsigned __int64 UInt64;
		#define UINT64_CONST(n) n
	#else
		typedef int64_t Int64;
		typedef uint64_t UInt64;
		#define UINT64_CONST(n) n ## ULL
	#endif
#endif


#define SZ_OK 0

#define SZ_ERROR_DATA 1
#define SZ_ERROR_MEM 2
#define SZ_ERROR_CRC 3
#define SZ_ERROR_UNSUPPORTED 4
#define SZ_ERROR_PARAM 5
#define SZ_ERROR_INPUT_EOF 6
#define SZ_ERROR_OUTPUT_EOF 7
#define SZ_ERROR_READ 8
#define SZ_ERROR_WRITE 9
#define SZ_ERROR_PROGRESS 10
#define SZ_ERROR_FAIL 11
#define SZ_ERROR_THREAD 12
#define SZ_ERROR_BAD_FILENAME 13
#define SZ_ERROR_UNSAFE_FILENAME 14

#define SZ_ERROR_ARCHIVE 16
#define SZ_ERROR_NO_ARCHIVE 17

#define SZ_ERROR_OVERWRITE 21
#define SZ_ERROR_WRITE_OPEN 22
#define SZ_ERROR_WRITE_CHMOD 23
#define SZ_ERROR_WRITE_MKDIR 24
#define SZ_ERROR_WRITE_MKDIR_CHMOD 25
#define SZ_ERROR_WRITE_SYMLINK 26

typedef int SRes;

#ifdef _WIN32
	typedef DWORD WRes;
#else
	typedef int WRes;
#endif

#ifndef RINOK
#define RINOK(x) { int __result__ = (x); if (__result__ != 0) return __result__; }
#endif

typedef unsigned char Byte;
typedef short Int16;
typedef unsigned short UInt16;

#ifdef _LZMA_UINT32_IS_ULONG
typedef long Int32;
typedef unsigned long UInt32;
#else
typedef int Int32;
typedef unsigned int UInt32;
#endif

#ifdef _LZMA_NO_SYSTEM_SIZE_T
typedef UInt32 size_t;
typedef Int32 ssize_t;
#endif

typedef int Bool;
#define True 1
#define False 0

#ifdef _WIN32
	#define MY_STD_CALL __stdcall
#else
	#define MY_STD_CALL
#endif

#ifdef _MSC_VER
	#if _MSC_VER >= 1300
		#define MY_NO_INLINE __declspec(noinline)
	#else
		#define MY_NO_INLINE
	#endif
	#define MY_CDECL __cdecl
	#define MY_FAST_CALL __fastcall
#else
	#define MY_CDECL
	#define MY_FAST_CALL
#endif

/* The following interfaces use first parameter as pointer to structure */

typedef struct
{
  Byte (*Read)(void *p); /* reads one byte, returns 0 in case of EOF or error */
} IByteIn;

typedef struct
{
  void (*Write)(void *p, Byte b);
} IByteOut;

typedef struct
{
  SRes (*Read)(void *p, void *buf, size_t *size);
    /* if (input(*size) != 0 && output(*size) == 0) means end_of_stream.
       (output(*size) < input(*size)) is allowed */
} ISeqInStream;

typedef struct
{
  size_t (*Write)(void *p, const void *buf, size_t size);
    /* Returns: result - the number of actually written bytes.
       (result < size) means error */
} ISeqOutStream;

struct CFileInStream;

#define LookToRead_BUF_SIZE (1 << 14)

typedef struct
{
  const void *data;
  size_t data_pos;
  size_t data_len;
  size_t pos;
  size_t size;
  Byte buf[LookToRead_BUF_SIZE];
} CLookToRead;

STATIC SRes LookInStream_SeekTo(CLookToRead *p, UInt64 offset);

/* STATIC void LookToRead_Init(CLookToRead *p) */
#define LOOKTOREAD_INIT(p) do { memset(p, 0, sizeof(*p)); } while (0)
/* 1. If less than *size bytes are already in the input buffer, then fills the
 *    rest of the input buffer from disk.
 * 2. Sets *size to the number of bytes now in the input buffer. Can be more or
 *    less or equal to the original *size. Detect EOF by calling
 *    LOOKTOREAD_SKIP(*size), calling LookToRead_Look again, and then checking
 *    *size == 0.
 */
STATIC SRes LookToRead_Look(CLookToRead *p, const void **buf, size_t *size);
STATIC SRes LookToRead_ReadAll(CLookToRead *p, void *buf, size_t size);
/* offset must be <= output(*size) of Look */
/* STATIC SRes LookToRead_Skip(CLookToRead *p, size_t offset) */
#define LOOKTOREAD_SKIP(p, offset) do { (p)->pos += (offset); } while (0)

typedef struct
{
  SRes (*Progress)(void *p, UInt64 inSize, UInt64 outSize);
    /* Returns: result. (result != SZ_OK) means break.
       Value (UInt64)(Int64)-1 for size means unknown value. */
} ICompressProgress;

#ifdef _WIN32

	#define CHAR_PATH_SEPARATOR '\\'
	#define WCHAR_PATH_SEPARATOR L'\\'
	#define STRING_PATH_SEPARATOR "\\"
	#define WSTRING_PATH_SEPARATOR L"\\"

#else

	#define CHAR_PATH_SEPARATOR '/'
	#define WCHAR_PATH_SEPARATOR L'/'
	#define STRING_PATH_SEPARATOR "/"
	#define WSTRING_PATH_SEPARATOR L"/"

#endif


#define k7zStartHeaderSize 0x20
#define k7zSignatureSize 6
/* The first byte is deliberately wrong, it should be '7' */
/* extern const Byte k7zSignature[k7zSignatureSize]; */
#define k7zMajorVersion 0

enum EIdEnum
{
  k7zIdEnd,
  k7zIdHeader,
  k7zIdArchiveProperties,
  k7zIdAdditionalStreamsInfo,
  k7zIdMainStreamsInfo,
  k7zIdFilesInfo,
  k7zIdPackInfo,
  k7zIdUnpackInfo,
  k7zIdSubStreamsInfo,
  k7zIdSize,
  k7zIdCRC,
  k7zIdFolder,
  k7zIdCodersUnpackSize,
  k7zIdNumUnpackStream,
  k7zIdEmptyStream,
  k7zIdEmptyFile,
  k7zIdAnti,
  k7zIdName,
  k7zIdCTime,
  k7zIdATime,
  k7zIdMTime,
  k7zIdWinAttributes,
  k7zIdComment,
  k7zIdEncodedHeader,
  k7zIdStartPos,
  k7zIdDummy
};

typedef struct
{
  UInt32 NumInStreams;
  UInt32 NumOutStreams;
  UInt64 MethodID;
  Byte *Props;
  size_t PropsSize;
} CSzCoderInfo;

typedef struct
{
  UInt32 InIndex;
  UInt32 OutIndex;
} CSzBindPair;

typedef struct
{
  CSzCoderInfo *Coders;
  CSzBindPair *BindPairs;
  UInt32 *PackStreams;
  UInt64 *UnpackSizes;
  UInt32 NumCoders;
  UInt32 NumBindPairs;
  UInt32 NumPackStreams;
  int UnpackCRCDefined;
  UInt32 UnpackCRC;

  UInt32 NumUnpackStreams;
} CSzFolder;

STATIC void SzFolder_Init(CSzFolder *p);
STATIC UInt64 SzFolder_GetUnpackSize(CSzFolder *p);
STATIC int SzFolder_FindBindPairForInStream(CSzFolder *p, UInt32 inStreamIndex);
STATIC UInt32 SzFolder_GetNumOutStreams(CSzFolder *p);
STATIC UInt64 SzFolder_GetUnpackSize(CSzFolder *p);

STATIC SRes SzFolder_Decode(const CSzFolder *folder, const UInt64 *packSizes,
    CLookToRead *stream, UInt64 startPos,
    Byte *outBuffer, size_t outSize);

typedef struct
{
  UInt32 Low;
  UInt32 High;
} CNtfsFileTime;

typedef struct
{
  CNtfsFileTime MTime;  /* Initialized only if MTimeDefined. */
  UInt64 Size;
  UInt32 Crc;  /* Initialized only if CrcDefined. */
  UInt32 Attrib;  /* Undefined of (UInt32)-1. */
  Byte HasStream;
  Byte IsDir;
  Byte CrcDefined;
  Byte MTimeDefined;
} CSzFileItem;
#define FILE_ATTRIBUTE_READONLY             1
/*#define FILE_ATTRIBUTE_DIRECTORY           16*/
#define FILE_ATTRIBUTE_UNIX_EXTENSION   0x8000

typedef struct
{
  UInt64 *PackSizes;
  Byte *PackCRCsDefined;
  UInt32 *PackCRCs;
  CSzFolder *Folders;
  CSzFileItem *Files;
  UInt32 NumPackStreams;
  UInt32 NumFolders;
  UInt32 NumFiles;
} CSzAr;

STATIC void SzAr_Init(CSzAr *p);
STATIC void SzAr_Free(CSzAr *p);


/*
  SzExtract extracts file from archive

  *outBuffer must be 0 before first call for each new archive.

  Extracting cache:
    If you need to decompress more than one file, you can send
    these values from previous call:
      *blockIndex,
      *outBuffer,
      *outBufferSize
    You can consider "*outBuffer" as cache of solid block. If your archive is solid,
    it will increase decompression speed.

    If you use external function, you can declare these 3 cache variables
    (blockIndex, outBuffer, outBufferSize) as static in that external function.

    Free *outBuffer and set *outBuffer to 0, if you want to flush cache.
*/

typedef struct
{
  CSzAr db;

  UInt64 startPosAfterHeader;
  UInt64 dataPos;

  UInt32 *FolderStartPackStreamIndex;
  UInt64 *PackStreamStartPositions;
  UInt32 *FolderStartFileIndex;
  UInt32 *FileIndexToFolderIndexMap;

  size_t *FileNameOffsets; /* in 2-byte steps */
  Byte *FileNamesInHeaderBufPtr;  /* UTF-16-LE */
  Byte *HeaderBufStart;  /* Buffer containing FileNamesInHeaderBufPtr. */
} CSzArEx;

/*static void SzArEx_Init(CSzArEx *p);*/
STATIC void SzArEx_Free(CSzArEx *p);
STATIC UInt64 SzArEx_GetFolderStreamPos(const CSzArEx *p, UInt32 folderIndex, UInt32 indexInFolder);

STATIC SRes SzArEx_Extract(
    const CSzArEx *db,
    CLookToRead *inStream,
    UInt32 fileIndex,         /* index of file */
    UInt32 *blockIndex,       /* index of solid block */
    Byte **outBuffer,         /* pointer to pointer to output buffer (allocated with allocMain) */
    size_t *outBufferSize,    /* buffer size for output buffer */
    size_t *offset,           /* offset of stream for required file in *outBuffer */
    size_t *outSizeProcessed); /* size of file in *outBuffer */


/*
SzArEx_Open Errors:
SZ_ERROR_NO_ARCHIVE
SZ_ERROR_ARCHIVE
SZ_ERROR_UNSUPPORTED
SZ_ERROR_MEM
SZ_ERROR_CRC
SZ_ERROR_INPUT_EOF
SZ_ERROR_FAIL
*/

STATIC SRes SzArEx_Open(CSzArEx *p, CLookToRead *inStream);

STATIC void *SzAlloc(size_t size);
STATIC void SzFree(void *address);
STATIC UInt32 MY_FAST_CALL CrcCalc(const void *data, size_t size);

/*
MY_CPU_LE means that CPU is LITTLE ENDIAN.
If MY_CPU_LE is not defined, we don't know about that property of platform (it can be LITTLE ENDIAN).

MY_CPU_LE_UNALIGN means that CPU is LITTLE ENDIAN and CPU supports unaligned memory accesses.
If MY_CPU_LE_UNALIGN is not defined, we don't know about these properties of platform.
*/

#if defined(_M_X64) || defined(_M_AMD64) || defined(__x86_64__)
#define MY_CPU_AMD64
#endif

#if defined(MY_CPU_AMD64) || defined(_M_IA64)
#define MY_CPU_64BIT
#endif

#if defined(_M_IX86) || defined(__i386__)
#define MY_CPU_X86
#endif

#if defined(MY_CPU_X86) || defined(MY_CPU_AMD64)
#define MY_CPU_X86_OR_AMD64
#endif

#if defined(MY_CPU_X86) || defined(_M_ARM)
#define MY_CPU_32BIT
#endif

#if defined(_WIN32) && defined(_M_ARM)
#define MY_CPU_ARM_LE
#endif

#if defined(_WIN32) && defined(_M_IA64)
#define MY_CPU_IA64_LE
#endif

#if defined(MY_CPU_X86_OR_AMD64)
#define MY_CPU_LE_UNALIGN
#endif

#if defined(MY_CPU_X86_OR_AMD64) || defined(MY_CPU_ARM_LE)  || defined(MY_CPU_IA64_LE) || defined(__ARMEL__) || defined(__MIPSEL__) || defined(__LITTLE_ENDIAN__)
#define MY_CPU_LE
#endif

#if defined(__BIG_ENDIAN__) || defined(__m68k__) ||  defined(__ARMEB__) || defined(__MIPSEB__)
#define MY_CPU_BE
#endif

#if defined(MY_CPU_LE) && defined(MY_CPU_BE)
Stop_Compiling_Bad_Endian
#endif

#ifdef MY_CPU_LE_UNALIGN

#define GetUi16(p) (*(const UInt16 *)(p))
#define GetUi32(p) (*(const UInt32 *)(p))
#define GetUi64(p) (*(const UInt64 *)(p))
#define SetUi16(p, d) *(UInt16 *)(p) = (d);
#define SetUi32(p, d) *(UInt32 *)(p) = (d);
#define SetUi64(p, d) *(UInt64 *)(p) = (d);

#else

#define GetUi16(p) (((const Byte *)(p))[0] | ((UInt16)((const Byte *)(p))[1] << 8))

#define GetUi32(p) ( \
             ((const Byte *)(p))[0]        | \
    ((UInt32)((const Byte *)(p))[1] <<  8) | \
    ((UInt32)((const Byte *)(p))[2] << 16) | \
    ((UInt32)((const Byte *)(p))[3] << 24))

#define GetUi64(p) (GetUi32(p) | ((UInt64)GetUi32(((const Byte *)(p)) + 4) << 32))

#define SetUi16(p, d) { UInt32 _x_ = (d); \
    ((Byte *)(p))[0] = (Byte)_x_; \
    ((Byte *)(p))[1] = (Byte)(_x_ >> 8); }

#define SetUi32(p, d) { UInt32 _x_ = (d); \
    ((Byte *)(p))[0] = (Byte)_x_; \
    ((Byte *)(p))[1] = (Byte)(_x_ >> 8); \
    ((Byte *)(p))[2] = (Byte)(_x_ >> 16); \
    ((Byte *)(p))[3] = (Byte)(_x_ >> 24); }

#define SetUi64(p, d) { UInt64 _x64_ = (d); \
    SetUi32(p, (UInt32)_x64_); \
    SetUi32(((Byte *)(p)) + 4, (UInt32)(_x64_ >> 32)); }

#endif

#if defined(MY_CPU_LE_UNALIGN) && defined(_WIN64) && (_MSC_VER >= 1300)

#pragma intrinsic(_byteswap_ulong)
#pragma intrinsic(_byteswap_uint64)
#define GetBe32(p) _byteswap_ulong(*(const UInt32 *)(const Byte *)(p))
#define GetBe64(p) _byteswap_uint64(*(const UInt64 *)(const Byte *)(p))

#else

#define GetBe32(p) ( \
    ((UInt32)((const Byte *)(p))[0] << 24) | \
    ((UInt32)((const Byte *)(p))[1] << 16) | \
    ((UInt32)((const Byte *)(p))[2] <<  8) | \
             ((const Byte *)(p))[3] )

#define GetBe64(p) (((UInt64)GetBe32(p) << 32) | GetBe32(((const Byte *)(p)) + 4))

#endif

#define GetBe16(p) (((UInt16)((const Byte *)(p))[0] << 8) | ((const Byte *)(p))[1])

#ifdef __cplusplus
}
#endif
#endif