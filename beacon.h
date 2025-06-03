#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

// Data parser structure
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

// Beacon API declarations for Cobalt Strike BOF
DECLSPEC_IMPORT void __cdecl BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void __cdecl BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT char* __cdecl BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT int __cdecl BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short __cdecl BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int __cdecl BeaconDataLength(datap* parser);

// Beacon format types
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

#endif // BEACON_H