// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;; 
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['  
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P    
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,  
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Cxbx->Core->Xbe.cpp
// *
// *  This file is part of the Cxbx project.
// *
// *  Cxbx and Cxbe are free software; you can redistribute them
// *  and/or modify them under the terms of the GNU General Public
// *  License as published by the Free Software Foundation; either
// *  version 2 of the license, or (at your option) any later version.
// *
// *  This program is distributed in the hope that it will be useful,
// *  but WITHOUT ANY WARRANTY; without even the implied warranty of
// *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// *  GNU General Public License for more details.
// *
// *  You should have recieved a copy of the GNU General Public License
// *  along with this program; see the file COPYING.
// *  If not, write to the Free Software Foundation, Inc.,
// *  59 Temple Place - Suite 330, Bostom, MA 02111-1307, USA.
// *
// *  (c) 2002-2003 Aaron Robinson <caustik@caustik.com>
// *
// *  All rights reserved
// *
// ******************************************************************
#include "Xbe.h"
#include "MicroExe.h"

#include <memory.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#define XBE_ERROR(str, ...) do \
    { \
        printf("\nError in Xbe::Xbe: " str "\n", __VA_ARGS__); \
        if (XbeFile != 0) \
            fclose(XbeFile); \
        exit(1); \
    } while(0)

#define XBE_PATCH_ERROR(str, ...) do \
    { \
        printf("\nError in Xbe::PatchExe: " str "\n", __VA_ARGS__); \
        return 1; \
    } while(0)

#define XBE_WRITE_ERROR(str, ...) do \
    { \
        printf("\nError in Xbe::WriteExe: " str "\n", __VA_ARGS__); \
        if (ExeBuffer != 0) \
            delete [] ExeBuffer; \
        return 1; \
    } while(0)

// ******************************************************************
// * Signature for MapRegisters patch and the replacing code
// ******************************************************************

#define PATCH_LENGTH 11

static uint08 PatchSignature[] = 
    "\xC7\x01\x00\x00\x00\xFD"
    "\xA1\x04\x18\x00\xFD";

static void __declspec(naked) PatchCode()
{
    __asm
    {
        mov dword ptr [ecx], 0x84000000
        xor eax, eax
        inc eax
        ret
        int 3
    }
}

// ******************************************************************
// * Trampoline that will be located at entry point
// ******************************************************************
#define TRAMPOLINE_LENGTH 10

static void __declspec(naked) TrampolineCode()
{
    __asm
    {
        mov edx, 0x000100EC
        call dword ptr [edx]
        ret 
        nop
        nop
    }
}

// ******************************************************************
// * constructor
// ******************************************************************
Xbe::Xbe(const char *Filename)
{
    HeaderEx             = 0;
    HeaderExSize         = 0;
    SectionHeader        = 0;
    SectionName          = 0;
    LibraryVersion       = 0;
    KernelLibraryVersion = 0;
    XapiLibraryVersion   = 0;
    Tls                  = 0;
    Section              = 0;

    printf("Xbe::Xbe: Opening Xbe file...");

    FILE *XbeFile = fopen(Filename, "rb");
    if(XbeFile == 0)
        XBE_ERROR("Could not open Xbe file.");

    printf("OK\n");

    // ******************************************************************
    // * remember xbe path
    // ******************************************************************
    {
        printf("Xbe::Xbe Storing Xbe Path...");

        strcpy(Path, Filename);
        int v = 0, c = 0;
        while(Path[v] != '\0')
        {
            if(Path[v] == '\\')
                c = v + 1;
            v++;
        }
        Path[c] = '\0';
    }

    printf("OK\n");

    // ******************************************************************
    // * read xbe image header
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Image Header...");

        if(fread(&Header, sizeof(Xbe::HEADER), 1, XbeFile) != 1)
            XBE_ERROR("Unexpected end of file while reading Xbe Image Header");
        if(Header.Magic != *(uint32 *)"XBEH")
            XBE_ERROR("Invalid magic number in Xbe file");

        printf("OK\n");
    }

    // ******************************************************************
    // * read xbe image header extra bytes
    // ******************************************************************
    if(Header.SizeOfHeaders > sizeof(Xbe::HEADER))
    {
        printf("Xbe::Xbe: Reading Image Header Extra Bytes...");

        uint32 HeaderExSize = RoundUp(Header.SizeOfHeaders, PAGE_SIZE) - sizeof(Header);

		HeaderEx = new char[HeaderExSize];

		if(fread(HeaderEx, HeaderExSize, 1, XbeFile) != 1)
			XBE_ERROR("Unexpected end of file while reading Xbe Image Header (Ex)");

        printf("OK\n");
    }

    // ******************************************************************
    // * read xbe certificate
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Certificate...");

        fseek(XbeFile, Header.CertificateAddr - Header.BaseAddr, SEEK_SET);
        if(fread(&Certificate, sizeof(Xbe::CERTIFICATE), 1, XbeFile) != 1)
            XBE_ERROR("Unexpected end of file while reading Xbe Certificate");

        setlocale(LC_ALL, "English");
        wcstombs(AsciiTitle, Certificate.TitleName, 40);

        printf("OK\n");

        printf("Xbe::Xbe: Title identified as %s\n", AsciiTitle);
    }

    // ******************************************************************
    // * read xbe section headers
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Section Headers...\n");

        fseek(XbeFile, Header.SectionHeadersAddr - Header.BaseAddr, SEEK_SET);

        SectionHeader = new Xbe::SECTION_HEADER[Header.Sections];
        for(uint32 v = 0; v < Header.Sections; v++)
        {
            printf("Xbe::Xbe: Reading Section Header 0x%.04X...", v);

            if(fread(&SectionHeader[v], sizeof(Xbe::SECTION_HEADER), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Section Header %d (%Xh)", v, v);

            printf("OK\n");
        }
    }

    // ******************************************************************
    // * read xbe section names
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Section Names...\n");

        SectionName = new char[Header.Sections][9];
        for(uint32 v = 0; v < Header.Sections; v++)
        {
            printf("Xbe::Xbe: Reading Section Name 0x%.04X...", v);

            uint08 *sn = GetAddr(SectionHeader[v].SectionNameAddr);

            memset(SectionName[v], 0, 9);

            if(sn != 0)
            {
                for(int b = 0; b < 8; b++)
                {
                    SectionName[v][b] = sn[b];
                    if(SectionName[v][b] == '\0')
                        break;
                }
            }

            printf("OK (%s)\n", SectionName[v]);
        }
    }

    // ******************************************************************
    // * read xbe library versions
    // ******************************************************************
    if(Header.LibraryVersionsAddr != 0)
    {
        printf("Xbe::Xbe: Reading Library Versions...\n");

        fseek(XbeFile, Header.LibraryVersionsAddr - Header.BaseAddr, SEEK_SET);

        LibraryVersion = new Xbe::LIBRARY_VERSION[Header.LibraryVersions];
        for(uint32 v = 0; v < Header.LibraryVersions; v++)
        {
            printf("Xbe::Xbe: Reading Library Version 0x%.04X...", v);

            if(fread(&LibraryVersion[v], sizeof(Xbe::LIBRARY_VERSION), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Library Version %d (%Xh)", v, v);

            printf("OK\n");
        }

        // ******************************************************************
        // * read xbe kernel library version
        // ******************************************************************
        {
            printf("Xbe::Xbe: Reading Kernel Library Version...");

            if(Header.KernelLibraryVersionAddr == 0)
                XBE_ERROR("Could not locate kernel library version");

            fseek(XbeFile, Header.KernelLibraryVersionAddr - Header.BaseAddr, SEEK_SET);

            KernelLibraryVersion = new Xbe::LIBRARY_VERSION;
            if(fread(KernelLibraryVersion, sizeof(Xbe::LIBRARY_VERSION), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Kernel Version");

            printf("OK\n");
        }

        // ******************************************************************
        // * read xbe xapi library version
        // ******************************************************************
        {
            printf("Xbe::Xbe: Reading Xapi Library Version...");

            if(Header.XapiLibraryVersionAddr == 0)
                XBE_ERROR("Could not locate Xapi Library Version", true);

            fseek(XbeFile, Header.XapiLibraryVersionAddr - Header.BaseAddr, SEEK_SET);

            XapiLibraryVersion = new Xbe::LIBRARY_VERSION;
            if(fread(XapiLibraryVersion, sizeof(Xbe::LIBRARY_VERSION), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Xapi Version", true);

            printf("OK\n");
        }
    }

    // ******************************************************************
    // * read xbe sections
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Sections...\n");

        Section = new uint08*[Header.Sections];

        memset(Section, 0, Header.Sections);

        for(uint32 v = 0; v < Header.Sections; v++)
        {
            printf("Xbe::Xbe: Reading Section 0x%.04X...", v);

            uint32 RawSize = SectionHeader[v].SizeOfRaw;
            uint32 RawAddr = SectionHeader[v].RawAddr;

            Section[v] = new uint08[RawSize];

            fseek(XbeFile, RawAddr, SEEK_SET);

            if(RawSize == 0)
            {
                printf("OK\n");
                continue;
            }

            if(fread(Section[v], RawSize, 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Section %d (%Xh) (%s)", v, v, SectionName[v]);

            printf("OK\n");
        }
    }

    // ******************************************************************
    // * read xbe thread local storage
    // ******************************************************************
    if(Header.TlsAddr != 0)
    {
        printf("Xbe::Xbe: Reading Thread Local Storage...");

        void *Addr = GetAddr(Header.TlsAddr);
        if(Addr == 0)
            XBE_ERROR("Could not locate Thread Local Storage");

        Tls = new Xbe::TLS;
        memcpy(Tls, Addr, sizeof(Xbe::TLS));

        printf("OK\n");
    }

    fclose(XbeFile);
    return;
}

// ******************************************************************
// * deconstructor
// ******************************************************************
Xbe::~Xbe()
{
    if(Section != 0)
    {
        for(uint32 v = 0; v < Header.Sections; v++)
            delete[] Section[v];

        delete[] Section;
    }

    delete   XapiLibraryVersion;
    delete   KernelLibraryVersion;
    delete[] LibraryVersion;
    delete   Tls;
    delete[] SectionName;
    delete[] SectionHeader;
	delete[] HeaderEx;
}

// ******************************************************************
// * Patcher
// ******************************************************************
int32 Xbe::PatchXbe()
{
    printf("Xbe::PatchExe Patching initialization flags in Xbe...");
    Header.InitFlags.MountUtilityDrive = 0;
    Header.InitFlags.FormatUtilityDrive = 0;
    printf("OK\n");

    printf("Xbe::PatchExe Patching MapRegisters in Xbe...");

    // ******************************************************************
    // * find section with Direct3D code
    // ******************************************************************
    uint32 v;
    for (v = 0; v < Header.Sections; v++)
        if (strncmp(SectionName[v], "D3D", 9) == 0)
            break;

    if (v == Header.Sections)
        XBE_PATCH_ERROR("Could not find D3D section");

    // ******************************************************************
    // * find patching location in D3D section
    // ******************************************************************
    uint32 i;
    for (i = 0; i < SectionHeader[v].SizeOfRaw - PATCH_LENGTH; i++)
        if (memcmp(&Section[v][i], PatchSignature, PATCH_LENGTH) == 0)
            break;

    if (i == SectionHeader[v].SizeOfRaw - PATCH_LENGTH)
        XBE_PATCH_ERROR("Could not find signature in D3D section");

    // ******************************************************************
    // * patch MapRegisters
    // ******************************************************************
    memcpy(&Section[v][i], &PatchCode, PATCH_LENGTH);

    printf("OK\n");

    return 0;
}

// ******************************************************************
// * Writer
// ******************************************************************
int32 Xbe::WriteExe(const char *Filename)
{
    printf("Xbe::WriteExe Converting Xbe to Exe...");

    if (PatchXbe() != 0)
        return 1;

    // ******************************************************************
    // * create buffer for "as-loaded" XBE/EXE hybrid
    // ******************************************************************
    uint08 *ExeBuffer = new uint08[Header.SizeOfImage];
    if (ExeBuffer == 0)
        XBE_WRITE_ERROR("Cannot allocate buffer for Exe");

    memset(ExeBuffer, 0, Header.SizeOfImage);

    // ******************************************************************
    // * write xbe section headers
    // ******************************************************************
    memcpy(ExeBuffer + 0, &Header, sizeof(Xbe::HEADER));
    memcpy(ExeBuffer + Header.SizeOfImageHeader, HeaderEx, HeaderExSize);

    // ******************************************************************
    // * write xbe sections
    // ******************************************************************
    for (uint32 v = 0; v < Header.Sections; v++)
    {
        uint32 offs = SectionHeader[v].VirtualAddr - Header.BaseAddr;
        memcpy(ExeBuffer + offs, Section[v], SectionHeader[v].SizeOfRaw);
    }

    // ******************************************************************
    // * patch digital signature with PE stub
    // ******************************************************************
    MICRO_EXE_HEADERS ExeHeaders;

    ExeHeaders.DosHeader.Magic = *(uint16 *)"MZ";
    ExeHeaders.DosHeader.Unused = 0;

    ExeHeaders.Header.Magic = *(uint32 *)"PE\0\0";
    ExeHeaders.Header.Machine = IMAGE_FILE_MACHINE_I386;
    ExeHeaders.Header.NumberOfSections = 1;
    ExeHeaders.Header.TimeDateStamp = Header.TimeDate;
    ExeHeaders.Header.PointerToSymbolTable = 0;
    ExeHeaders.Header.NumberOfSymbols = 0;
    ExeHeaders.Header.SizeOfOptionalHeader = sizeof(MICRO_EXE_HEADERS::OPTIONAL_HEADER);
    ExeHeaders.Header.Characteristics = 
        IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | 
        IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_32BIT_MACHINE;

    ExeHeaders.OptionalHeader.Magic = 0x010B;
    ExeHeaders.OptionalHeader.MajorLinkerVersion = 0x06;
    ExeHeaders.OptionalHeader.MinorLinkerVersion = 0x00;
    ExeHeaders.OptionalHeader.SizeOfCode = 0;
    ExeHeaders.OptionalHeader.SizeOfInitializedData = 0;
    ExeHeaders.OptionalHeader.SizeOfUninitializedData = 0;
    ExeHeaders.OptionalHeader.AddressOfEntryPoint = (uint32)&ExeHeaders.Trampoline - (uint32)&ExeHeaders;
    ExeHeaders.OptionalHeader.BaseOfCode = 0;
    ExeHeaders.OptionalHeader.BaseOfData = 0;

    ExeHeaders.OptionalHeader.ImageBase = Header.BaseAddr;
    ExeHeaders.OptionalHeader.Lfanew_SectionAlignment = EXE_ALIGNMENT;
    ExeHeaders.OptionalHeader.FileAlignment = EXE_ALIGNMENT;
    ExeHeaders.OptionalHeader.MajorOperatingSystemVersion = 4;
    ExeHeaders.OptionalHeader.MinorOperatingSystemVersion = 0;
    // This is where the imported DLL name "DbE\0" will be located
    strncpy(ExeHeaders.OptionalHeader.DirtboxDllName, "DbE", 4);
    ExeHeaders.OptionalHeader.MajorSubsystemVersion = 4;
    ExeHeaders.OptionalHeader.MinorSubsystemVersion = 0;
    ExeHeaders.OptionalHeader.Win32VersionValue = 0;
    ExeHeaders.OptionalHeader.SizeOfImage = Header.SizeOfImage; // already aligned at 0x20
    ExeHeaders.OptionalHeader.SizeOfHeaders = RoundUp(sizeof(MICRO_EXE_HEADERS), EXE_ALIGNMENT);
    ExeHeaders.OptionalHeader.CheckSum = 0;
    ExeHeaders.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    ExeHeaders.OptionalHeader.DllCharacteristics = 0x400;
    ExeHeaders.OptionalHeader.SizeOfStackReserve = 0x100000;
    ExeHeaders.OptionalHeader.SizeOfStackCommit = 0x1000;
    ExeHeaders.OptionalHeader.SizeOfHeapReserve = 0x100000;
    ExeHeaders.OptionalHeader.SizeOfHeapCommit = 0x1000;
    ExeHeaders.OptionalHeader.LoaderFlags = 0;
    ExeHeaders.OptionalHeader.NumberOfRvaAndSizes = 4;

    // ******************************************************************
    // * the other directories
    // ******************************************************************
    for (uint32 v = 0; v < 4; v++)
    {
        ExeHeaders.OptionalHeader.DataDirectory[v].VirtualAddress = 0;
        ExeHeaders.OptionalHeader.DataDirectory[v].Size = 0;
    }

    // ******************************************************************
    // * import directory
    // ******************************************************************
    uint32 offs = (uint32)&ExeHeaders.ImageImportDescriptor - (uint32)&ExeHeaders;

    ExeHeaders.OptionalHeader.DataDirectory[1].VirtualAddress = offs;
    ExeHeaders.OptionalHeader.DataDirectory[1].Size = 
        2*sizeof(MICRO_EXE_HEADERS::IMAGE_IMPORT_DESCRIPTOR);

    // ******************************************************************
    // * the one and only section header
    // ******************************************************************
    uint32 XbeSectionAddress = 0; // the whole image
    uint32 XbeSectionSize = Header.SizeOfImage - XbeSectionAddress; // already aligned at 0x20

    strncpy(ExeHeaders.SectionHeader.Name, "loldong", 8);
    ExeHeaders.SectionHeader.VirtualSize = XbeSectionSize;
    ExeHeaders.SectionHeader.VirtualAddress = XbeSectionAddress;
    ExeHeaders.SectionHeader.SizeOfRawData = XbeSectionSize;
    ExeHeaders.SectionHeader.PointerToRawData = XbeSectionAddress;
    ExeHeaders.SectionHeader.PointerToRelocations = 0;
    ExeHeaders.SectionHeader.PointerToLinenumbers = 0;
    ExeHeaders.SectionHeader.NumberOfRelocations = 0;
    ExeHeaders.SectionHeader.NumberOfLinenumbers = 0;
    ExeHeaders.SectionHeader.Characteristics = 0x60000020;

    // ******************************************************************
    // * image import descriptor, only one DLL
    // ******************************************************************
    uint32 offsIat = (uint32)&ExeHeaders.ImportAddressTable - (uint32)&ExeHeaders;
    uint32 offsName = (uint32)ExeHeaders.OptionalHeader.DirtboxDllName - (uint32)&ExeHeaders;

    ExeHeaders.ImageImportDescriptor[0].OriginalFirstThunk = offsIat;
    ExeHeaders.ImageImportDescriptor[0].TimeDateStamp = 0;
    ExeHeaders.ImageImportDescriptor[0].ForwarderChain = 0;
    ExeHeaders.ImageImportDescriptor[0].Name = offsName;
    ExeHeaders.ImageImportDescriptor[0].FirstThunk = offsIat;

    ExeHeaders.ImageImportDescriptor[1].OriginalFirstThunk = 0;
    ExeHeaders.ImageImportDescriptor[1].TimeDateStamp = 0;
    ExeHeaders.ImageImportDescriptor[1].ForwarderChain = 0;
    ExeHeaders.ImageImportDescriptor[1].Name = 0;
    ExeHeaders.ImageImportDescriptor[1].FirstThunk = 0;

    // ******************************************************************
    // * import address table, import by ordinal
    // ******************************************************************
    ExeHeaders.ImportAddressTable[0] = 0x80000001;
    ExeHeaders.ImportAddressTable[1] = 0;

    // ******************************************************************
    // * trampoline that calls the Dirtbox loader in the DLL
    // ******************************************************************
    memcpy(ExeHeaders.Trampoline, &TrampolineCode, TRAMPOLINE_LENGTH);

    // ******************************************************************
    // * replaces the magic and digital signature with PE headers
    // ******************************************************************
    memcpy(ExeBuffer + 0, &ExeHeaders, sizeof(MICRO_EXE_HEADERS));

    // ******************************************************************
    // * write the created buffer into EXE file
    // ******************************************************************
    FILE *ExeFile = fopen(Filename, "wb");
    if (ExeFile == 0)
        XBE_WRITE_ERROR("Could not open Exe file");

    fwrite(ExeBuffer, Header.SizeOfImage, 1, ExeFile);
    fclose(ExeFile);

    // ******************************************************************
    // * free buffer for Exe file
    // ******************************************************************
    delete [] ExeBuffer;

    printf("OK\n");

    return 0;
}

// ******************************************************************
// * GetAddr
// ******************************************************************
uint08 *Xbe::GetAddr(uint32 VirtualAddress)
{
    uint32 offs = VirtualAddress - Header.BaseAddr;

    // ******************************************************************
    // * offset in image header
    // ******************************************************************
    if(offs < sizeof(Header))
        return &((uint08*)&Header)[offs];

    // ******************************************************************
    // * offset in image header extra bytes
    // ******************************************************************
    if(offs < Header.SizeOfHeaders)
 		return (uint08*)&HeaderEx[offs - sizeof(Header)];

    // ******************************************************************
    // * offset in some random section
    // ******************************************************************
    {
        for(uint32 v = 0; v < Header.Sections; v++)
        {
            uint32 VirtAddr = SectionHeader[v].VirtualAddr;
            uint32 VirtSize = SectionHeader[v].VirtualSize;

            if( (VirtualAddress >= VirtAddr) && (VirtualAddress < (VirtAddr + VirtSize)) )
                return &Section[v][VirtualAddress - VirtAddr];
        }
    }

    return 0;
}
