#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include "un7z.h"

extern const unsigned char pak_data[];
extern const unsigned int  pak_data_length;

static Byte kUtf8Limits[5] = { 0xC0, 0xE0, 0xF0, 0xF8, 0xFC };

static Bool Utf16Le_To_Utf8(Byte *dest, size_t *destLen, const Byte *srcUtf16Le, size_t srcUtf16LeLen)
{
  size_t destPos = 0;
  const Byte *srcUtf16LeEnd = srcUtf16Le + srcUtf16LeLen * 2;
  for (;;)
  {
	unsigned numAdds;
	UInt32 value;
	if (srcUtf16Le == srcUtf16LeEnd)
	{
	  *destLen = destPos;
	  return True;
	}
	value = GetUi16(srcUtf16Le);
	srcUtf16Le += 2;
	if (value < 0x80)
	{
	  if (dest)
		dest[destPos] = (char)value;
	  destPos++;
	  continue;
	}
	if (value >= 0xD800 && value < 0xE000)
	{
	  UInt32 c2;
	  if (value >= 0xDC00 || srcUtf16Le == srcUtf16LeEnd)
		break;
	  c2 = GetUi16(srcUtf16Le);
	  srcUtf16Le += 2;
	  if (c2 < 0xDC00 || c2 >= 0xE000)
		break;
	  value = (((value - 0xD800) << 10) | (c2 - 0xDC00)) + 0x10000;
	}
	for (numAdds = 1; numAdds < 5; numAdds++)
	  if (value < (((UInt32)1) << (numAdds * 5 + 6)))
		break;
	if (dest)
	  dest[destPos] = (char)(kUtf8Limits[numAdds - 1] + (value >> (6 * numAdds)));
	destPos++;
	do
	{
	  numAdds--;
	  if (dest)
		dest[destPos] = (char)(0x80 + ((value >> (6 * numAdds)) & 0x3F));
	  destPos++;
	}
	while (numAdds != 0);
  }
  *destLen = destPos;
  return False;
}

int main(int argc, const char **argv)
{
	CSzArEx db;
	CLookToRead lookStream;
	SRes res;
	Byte *filename_utf8 = NULL;
	size_t filename_utf8_capacity = 0;

	if (argc < 2) {
		return 1;
	}

	LOOKTOREAD_INIT(&lookStream);
	lookStream.data = pak_data;
	lookStream.data_len = pak_data_length;

	res = SzArEx_Open(&db, &lookStream);

	if (res == SZ_OK) {
		UInt32 fileIndex;
		/*
		if you need cache, use these 3 variables.
		if you use external function, you can make these variable as static.
		*/
		UInt32 blockIndex = (UInt32)-1; /* it can have any value before first call (if outBuffer = 0) */
		Byte *outBuffer = 0; /* it must be 0 before first call for each new archive. */
		size_t outBufferSize = 0;  /* it can have any value before first call (if outBuffer = 0) */
		for (fileIndex = 0; fileIndex < db.db.NumFiles; fileIndex++) {
			size_t offset = 0;
			size_t outSizeProcessed = 0;
			const CSzFileItem *f = db.db.Files + fileIndex;
			const size_t filename_offset = db.FileNameOffsets[fileIndex];
			/* The length includes the trailing 0. */
			const size_t filename_utf16le_len =  db.FileNameOffsets[fileIndex + 1] - filename_offset;
			const Byte *filename_utf16le = db.FileNamesInHeaderBufPtr + filename_offset * 2;
			/* 2 for UTF-18 + 3 for UTF-8. 1 UTF-16 entry point can create at most 3 UTF-8 bytes (averaging for surrogates). */
			size_t filename_utf8_len = filename_utf16le_len * 3;
			SRes extract_res = SZ_OK;

			if (f->IsDir) {
				continue;
			} else {
				if (blockIndex != db.FileIndexToFolderIndexMap[fileIndex]) {
				  SzFree(filename_utf8);
				  filename_utf8 = NULL;
				  filename_utf8_capacity = 0;
				}
				extract_res = SzArEx_Extract(&db, &lookStream, fileIndex,
				&blockIndex, &outBuffer, &outBufferSize,
				&offset, &outSizeProcessed);
				if (extract_res) {
					break;
				}
			}

			if (filename_utf8_len > filename_utf8_capacity) {
				SzFree(filename_utf8);
				if (filename_utf8_capacity == 0) filename_utf8_capacity = 128;
				while (filename_utf8_capacity < filename_utf8_len) {
					filename_utf8_capacity <<= 1;
				}
				if ((filename_utf8 = (Byte*)SzAlloc(filename_utf8_capacity)) == 0) {
					res = SZ_ERROR_MEM;
					break;
				}
			}

			if (!Utf16Le_To_Utf8(filename_utf8, &filename_utf8_len, filename_utf16le, filename_utf16le_len)) {
				res = SZ_ERROR_BAD_FILENAME;
				break;
			}
			
			if (!strcmp((char*)filename_utf8, argv[1])) {
				fwrite(outBuffer + offset, 1, outSizeProcessed, stdout);
				fputc('\n', stdout);
				break;
			}
		}
		SzFree(outBuffer);
	}

	SzArEx_Free(&db);
	SzFree(filename_utf8);

	if (res == SZ_OK) {
		return 0;
	} else if (res == SZ_ERROR_UNSUPPORTED) {
		fprintf(stderr, "%s\n", "decoder doesn't support this archive");
	} else if (res == SZ_ERROR_MEM) {
		fprintf(stderr, "%s\n", "can not allocate memory");
	} else if (res == SZ_ERROR_CRC) {
		fprintf(stderr, "%s\n", "CRC error");
	} else if (res == SZ_ERROR_NO_ARCHIVE) {
		fprintf(stderr, "%s\n", "input file is not a .7z archive");
	} else if (res == SZ_ERROR_OVERWRITE) {
		fprintf(stderr, "%s\n", "already exists, specify -y to overwrite");
	} else if (res == SZ_ERROR_WRITE_OPEN) {
		fprintf(stderr, "%s\n", "can not open output file");
	} else if (res == SZ_ERROR_WRITE_CHMOD) {
		fprintf(stderr, "%s\n", "can not chmod output file");
	} else if (res == SZ_ERROR_WRITE) {
		fprintf(stderr, "%s\n", "can not write output file");
	} else if (res == SZ_ERROR_BAD_FILENAME) {
		fprintf(stderr, "%s\n", "bad filename (UTF-16 encoding)");
	} else if (res == SZ_ERROR_UNSAFE_FILENAME) {
		fprintf(stderr, "%s\n", "unsafe filename");  /* See IsFilenameSafe. */
	} else if (res == SZ_ERROR_WRITE_MKDIR) {
		fprintf(stderr, "%s\n", "can not create output dir");
	} else if (res == SZ_ERROR_WRITE_MKDIR_CHMOD) {
		fprintf(stderr, "%s\n", "can not chmod output dir");
	} else if (res == SZ_ERROR_WRITE_SYMLINK) {
		fprintf(stderr, "%s\n", "can not create symlink");
	} else {
		fprintf(stderr, "ERROR # %i\n", res);
	}

	return 0;
}