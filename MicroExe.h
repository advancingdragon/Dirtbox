#ifndef MICROEXE_H
#define MICROEXE_H

#include "Types.h"

#include "AlignPrefix1.h"
struct MicroExeHeaders
{
    // DOS Header
    struct DOSHeader
    {
        uint16 wMagic;                         // DOS .EXE magic number
        uint16 Unused;
    } m_DOSHeader;

    // PE Header
    struct Header
    {
        uint32 dwMagic;                      // magic number [should be "PE\0\0"]
        uint16 wMachine;                     // machine type
        uint16 wNumberOfSections;            // number of sections
        uint32 dwTimeDateStamp;              // timedate stamp
        uint32 dwPointerToSymbolTable;       // symbol table address
        uint32 dwNumberOfSymbols;            // number of symbols
        uint16 wSizeOfOptionalHeader;        // size of optional header
        uint16 wCharacteristics;             // characteristics
    } m_Header;

    // Optional Header
    struct OptionalHeader
    {
        uint16 wMagic;                       // magic number [should be 0x010B]
        uint08 bMajorLinkerVersion;          // linker version [major]
        uint08 bMinorLinkerVersion;          // linker version [minor]
        uint32 dwSizeOfCode;                 // size of code
        uint32 dwSizeOfInitializedData;      // size of initialized data
        uint32 dwSizeOfUninitializedData;    // size of uninitialized data
        uint32 dwAddressOfEntryPoint;        // address of entry point
        uint32 dwBaseOfCode;                 // address of code base
        uint32 dwBaseOfData;                 // address of data base

        // NT Additional Fields
        uint32 dwImageBase;                  // address of image base
        uint32 dwLfanew_SectionAlignment;    // section alignment
                                             // (DOS Header) file address of new .EXE header
        uint32 dwFileAlignment;              // file alignment
        uint16 wMajorOperatingSystemVersion; // operating system version [major]
        uint16 wMinorOperatingSystemVersion; // operating system version [minor]
        uint16 wMajorImageVersion;           // image version [major]
        uint16 wMinorImageVersion;           // image version [minor]
        uint16 wMajorSubsystemVersion;       // subsystem version [major]
        uint16 wMinorSubsystemVersion;       // subsystem version [minor]
        uint32 dwWin32VersionValue;          // win32 version
        uint32 dwSizeOfImage;                // size of image
        uint32 dwSizeOfHeaders;              // size of headers
        uint32 dwCheckSum;                   // checksum
        uint16 wSubsystem;                   // subsystem
        uint16 wDllCharacteristics;          // dll characteristics
        uint32 dwSizeOfStackReserve;         // size of stack reserve
        uint32 dwSizeOfStackCommit;          // size of stack commit
        uint32 dwSizeOfHeapReserve;          // size of heap reserve
        uint32 dwSizeOfHeapCommit;           // size of heap commit
        uint32 dwLoaderFlags;                // loader flags
        uint32 dwNumberOfRvaAndSizes;        // data directories
        struct ImageDataDirectory
        {
            uint32 dwVirtualAddress;
            uint32 dwSize;
        } astDataDirectory[4];
    } m_OptionalHeader;

    struct SectionHeader
    {
        uint08 szName[8];
        uint32 dwVirtualSize;
        uint32 dwVirtualAddress;
        uint32 dwSizeOfRawData;
        uint32 dwPointerToRawData;
        uint32 dwPointerToRelocations;
        uint32 dwPointerToLinenumbers;
        uint16 wNumberOfRelocations;
        uint16 wNumberOfLinenumbers;
        uint32 dwCharacteristics;
    } m_SectionHeader;

    struct ImageImportDescriptor
    {
        uint32 dwOriginalFirstThunk; // address of import lookup table
        uint32 dwTimeDateStamp;      // time date stamp
        uint32 dwForwarderChain;     // forwarder chain, -1 if no forwarders
        uint32 dwName;               // address of DLL name string
        uint32 dwFirstThunk;         // address of import address table
    } m_ImageImportDescriptor[2];

    uint32 m_ImportAddressTable[2];
    char m_ImportName[10];
    uint08 m_Trampoline[6];
};
#include "AlignPosfix1.h"


const uint16 IMAGE_FILE_MACHINE_I386             = 0x014c;  // Intel 386.

const uint16 IMAGE_SUBSYSTEM_UNKNOWN             = 0;
const uint16 IMAGE_SUBSYSTEM_NATIVE              = 1;
const uint16 IMAGE_SUBSYSTEM_WINDOWS_GUI         = 2;
const uint16 IMAGE_SUBSYSTEM_WINDOWS_CUI         = 3;

const uint32 EXE_ALIGNMENT = 4;

#endif