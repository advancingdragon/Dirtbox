#ifndef MICROEXE_H
#define MICROEXE_H

#include "Types.h"

#include "AlignPrefix1.h"
struct MICRO_EXE_HEADERS
{
    // DOS Header
    struct DOS_HEADER
    {
        uint16 Magic;                       // DOS .EXE magic number
        uint16 Unused;
    } DosHeader;

    // PE Header
    struct HEADER
    {
        uint32 Magic;                       // magic number [should be "PE\0\0"]
        uint16 Machine;                     // machine type
        uint16 NumberOfSections;            // number of sections
        uint32 TimeDateStamp;               // timedate stamp
        uint32 PointerToSymbolTable;        // symbol table address
        uint32 NumberOfSymbols;             // number of symbols
        uint16 SizeOfOptionalHeader;        // size of optional header
        uint16 Characteristics;             // characteristics
    } Header;

    // Optional Header
    struct OPTIONAL_HEADER
    {
        uint16 Magic;                       // magic number [should be 0x010B]
        uint08 MajorLinkerVersion;          // linker version [major]
        uint08 MinorLinkerVersion;          // linker version [minor]
        uint32 SizeOfCode;                  // size of code
        uint32 SizeOfInitializedData;       // size of initialized data
        uint32 SizeOfUninitializedData;     // size of uninitialized data
        uint32 AddressOfEntryPoint;         // address of entry point
        uint32 BaseOfCode;                  // address of code base
        uint32 BaseOfData;                  // address of data base

        // NT Additional Fields
        uint32 ImageBase;                   // address of image base
        uint32 Lfanew_SectionAlignment;     // section alignment
                                            // (DOS Header) file address of new .EXE header
        uint32 FileAlignment;               // file alignment
        uint16 MajorOperatingSystemVersion; // operating system version [major]
        uint16 MinorOperatingSystemVersion; // operating system version [minor]
        // image version not normally used, thus the imported
        // Dirtbox DLL name is placed here to save a few bytes.
        int08 DirtboxDllName[4];
        // uint16 MajorImageVersion;        // image version [major]
        // uint16 MinorImageVersion;        // image version [minor]
        uint16 MajorSubsystemVersion;       // subsystem version [major]
        uint16 MinorSubsystemVersion;       // subsystem version [minor]
        uint32 Win32VersionValue;           // win32 version
        uint32 SizeOfImage;                 // size of image
        uint32 SizeOfHeaders;               // size of headers
        uint32 CheckSum;                    // checksum
        uint16 Subsystem;                   // subsystem
        uint16 DllCharacteristics;          // dll characteristics
        uint32 SizeOfStackReserve;          // size of stack reserve
        uint32 SizeOfStackCommit;           // size of stack commit
        uint32 SizeOfHeapReserve;           // size of heap reserve
        uint32 SizeOfHeapCommit;            // size of heap commit
        uint32 LoaderFlags;                 // loader flags
        uint32 NumberOfRvaAndSizes;         // data directories
        struct IMAGE_DATA_DIRECTORY
        {
            uint32 VirtualAddress;
            uint32 Size;
        } DataDirectory[4];
    } OptionalHeader;

    struct SECTION_HEADER
    {
        int08  Name[8];
        uint32 VirtualSize;
        uint32 VirtualAddress;
        uint32 SizeOfRawData;
        uint32 PointerToRawData;
        uint32 PointerToRelocations;
        uint32 PointerToLinenumbers;
        uint16 NumberOfRelocations;
        uint16 NumberOfLinenumbers;
        uint32 Characteristics;
    } SectionHeader;

    struct IMAGE_IMPORT_DESCRIPTOR
    {
        uint32 OriginalFirstThunk; // address of import lookup table
        uint32 TimeDateStamp;      // time date stamp
        uint32 ForwarderChain;     // forwarder chain, -1 if no forwarders
        uint32 Name;               // address of DLL name string
        uint32 FirstThunk;         // address of import address table
    } ImageImportDescriptor[2];

    uint32 ImportAddressTable[2];
    uint08 Trampoline[16];
};
#include "AlignPosfix1.h"


const uint16 IMAGE_FILE_MACHINE_I386             = 0x014c;  // Intel 386.

const uint16 IMAGE_SUBSYSTEM_UNKNOWN             = 0;
const uint16 IMAGE_SUBSYSTEM_NATIVE              = 1;
const uint16 IMAGE_SUBSYSTEM_WINDOWS_GUI         = 2;
const uint16 IMAGE_SUBSYSTEM_WINDOWS_CUI         = 3;

const uint32 EXE_ALIGNMENT = 4;

#endif