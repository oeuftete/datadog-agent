
#ifndef DD_CRASHDUMP_H
#define DD_CRASHDUMP_H

#include <windows.h>
#include <winerror.h>
#include <DbgHelp.h>
#include <DbgEng.h>

#ifdef __cplusplus
extern "C"
#endif
int readCrashDump(char *fname, void *ctx);

#endif /* DD_CRASHDUMP_H */
