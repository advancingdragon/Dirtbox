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

#define XBE_WRITE_ERROR(str, ...) do \
    { \
        printf("\nError in Xbe::WriteExe: " str "\n", __VA_ARGS__); \
        if (ExeBuffer != 0) \
            delete [] ExeBuffer; \
        return 1; \
    } while(0)

// ******************************************************************
// * constructor
// ******************************************************************
Xbe::Xbe(const char *x_szFilename)
{
    m_HeaderEx             = 0;
    m_HeaderExSize         = 0;
    m_SectionHeader        = 0;
    m_szSectionName        = 0;
    m_LibraryVersion       = 0;
    m_KernelLibraryVersion = 0;
    m_XAPILibraryVersion   = 0;
    m_TLS                  = 0;
    m_bzSection            = 0;

    printf("Xbe::Xbe: Opening Xbe file...");

    FILE *XbeFile = fopen(x_szFilename, "rb");
    if(XbeFile == 0)
        XBE_ERROR("Could not open Xbe file.");

    printf("OK\n");

    // ******************************************************************
    // * remember xbe path
    // ******************************************************************
    {
        printf("Xbe::Xbe Storing Xbe Path...");

        strcpy(m_szPath, x_szFilename);
        int v=0, c=0;
        while(m_szPath[v] != '\0')
        {
            if(m_szPath[v] == '\\')
                c = v+1;
            v++;
        }
        m_szPath[c] = '\0';
    }

    printf("OK\n");

    // ******************************************************************
    // * read xbe image header
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Image Header...");

        if(fread(&m_Header, sizeof(m_Header), 1, XbeFile) != 1)
            XBE_ERROR("Unexpected end of file while reading Xbe Image Header");
        if(m_Header.dwMagic != *(uint32 *)"XBEH")
            XBE_ERROR("Invalid magic number in Xbe file");

        printf("OK\n");
    }

    // ******************************************************************
    // * read xbe image header extra bytes
    // ******************************************************************
    if(m_Header.dwSizeOfHeaders > sizeof(m_Header))
    {
        printf("Xbe::Xbe: Reading Image Header Extra Bytes...");

        uint32 m_HeaderExSize = RoundUp(m_Header.dwSizeOfHeaders, PAGE_SIZE) - sizeof(m_Header);

		m_HeaderEx = new char[m_HeaderExSize];

		if(fread(m_HeaderEx, m_HeaderExSize, 1, XbeFile) != 1)
			XBE_ERROR("Unexpected end of file while reading Xbe Image Header (Ex)");

        printf("OK\n");
    }

    // ******************************************************************
    // * read xbe certificate
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Certificate...");

        fseek(XbeFile, m_Header.dwCertificateAddr - m_Header.dwBaseAddr, SEEK_SET);
        if(fread(&m_Certificate, sizeof(m_Certificate), 1, XbeFile) != 1)
            XBE_ERROR("Unexpected end of file while reading Xbe Certificate");

        setlocale(LC_ALL, "English");
        wcstombs(m_szAsciiTitle, m_Certificate.wszTitleName, 40);

        printf("OK\n");

        printf("Xbe::Xbe: Title identified as %s\n", m_szAsciiTitle);
    }

    // ******************************************************************
    // * read xbe section headers
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Section Headers...\n");

        fseek(XbeFile, m_Header.dwSectionHeadersAddr - m_Header.dwBaseAddr, SEEK_SET);

        m_SectionHeader = new SectionHeader[m_Header.dwSections];
        for(uint32 v=0; v<m_Header.dwSections; v++)
        {
            printf("Xbe::Xbe: Reading Section Header 0x%.04X...", v);

            if(fread(&m_SectionHeader[v], sizeof(*m_SectionHeader), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Section Header %d (%Xh)", v, v);

            printf("OK\n");
        }
    }

    // ******************************************************************
    // * read xbe section names
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Section Names...\n");

        m_szSectionName = new char[m_Header.dwSections][9];
        for(uint32 v=0; v<m_Header.dwSections; v++)
        {
            printf("Xbe::Xbe: Reading Section Name 0x%.04X...", v);

            uint08 *sn = GetAddr(m_SectionHeader[v].dwSectionNameAddr);

            memset(m_szSectionName[v], 0, 9);

            if(sn != 0)
            {
                for(int b=0; b<8; b++)
                {
                    m_szSectionName[v][b] = sn[b];
                    if(m_szSectionName[v][b] == '\0')
                        break;
                }
            }

            printf("OK (%s)\n", m_szSectionName[v]);
        }
    }

    // ******************************************************************
    // * read xbe library versions
    // ******************************************************************
    if(m_Header.dwLibraryVersionsAddr != 0)
    {
        printf("Xbe::Xbe: Reading Library Versions...\n");

        fseek(XbeFile, m_Header.dwLibraryVersionsAddr - m_Header.dwBaseAddr, SEEK_SET);

        m_LibraryVersion = new LibraryVersion[m_Header.dwLibraryVersions];
        for(uint32 v=0; v<m_Header.dwLibraryVersions; v++)
        {
            printf("Xbe::Xbe: Reading Library Version 0x%.04X...", v);

            if(fread(&m_LibraryVersion[v], sizeof(*m_LibraryVersion), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Library Version %d (%Xh)", v, v);

            printf("OK\n");
        }

        // ******************************************************************
        // * read xbe kernel library version
        // ******************************************************************
        {
            printf("Xbe::Xbe: Reading Kernel Library Version...");

            if(m_Header.dwKernelLibraryVersionAddr == 0)
                XBE_ERROR("Could not locate kernel library version");

            fseek(XbeFile, m_Header.dwKernelLibraryVersionAddr - m_Header.dwBaseAddr, SEEK_SET);

            m_KernelLibraryVersion = new LibraryVersion;
            if(fread(m_KernelLibraryVersion, sizeof(*m_LibraryVersion), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Kernel Version");

            printf("OK\n");
        }

        // ******************************************************************
        // * read xbe xapi library version
        // ******************************************************************
        {
            printf("Xbe::Xbe: Reading Xapi Library Version...");

            if(m_Header.dwXAPILibraryVersionAddr == 0)
                XBE_ERROR("Could not locate Xapi Library Version", true);

            fseek(XbeFile, m_Header.dwXAPILibraryVersionAddr - m_Header.dwBaseAddr, SEEK_SET);

            m_XAPILibraryVersion = new LibraryVersion;
            if(fread(m_XAPILibraryVersion, sizeof(*m_LibraryVersion), 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Xapi Version", true);

            printf("OK\n");
        }
    }

    // ******************************************************************
    // * read xbe sections
    // ******************************************************************
    {
        printf("Xbe::Xbe: Reading Sections...\n");

        m_bzSection = new uint08*[m_Header.dwSections];

        memset(m_bzSection, 0, m_Header.dwSections);

        for(uint32 v=0; v<m_Header.dwSections; v++)
        {
            printf("Xbe::Xbe: Reading Section 0x%.04X...", v);

            uint32 RawSize = m_SectionHeader[v].dwSizeOfRaw;
            uint32 RawAddr = m_SectionHeader[v].dwRawAddr;

            m_bzSection[v] = new uint08[RawSize];

            fseek(XbeFile, RawAddr, SEEK_SET);

            if(RawSize == 0)
            {
                printf("OK\n");
                continue;
            }

            if(fread(m_bzSection[v], RawSize, 1, XbeFile) != 1)
                XBE_ERROR("Unexpected end of file while reading Xbe Section %d (%Xh) (%s)", v, v, m_szSectionName[v]);

            printf("OK\n");
        }
    }

    // ******************************************************************
    // * read xbe thread local storage
    // ******************************************************************
    if(m_Header.dwTLSAddr != 0)
    {
        printf("Xbe::Xbe: Reading Thread Local Storage...");

        void *Addr = GetAddr(m_Header.dwTLSAddr);
        if(Addr == 0)
            XBE_ERROR("Could not locate Thread Local Storage");

        m_TLS = new TLS;
        memcpy(m_TLS, Addr, sizeof(*m_TLS));

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
    if(m_bzSection != 0)
    {
        for(uint32 v=0; v<m_Header.dwSections; v++)
            delete[] m_bzSection[v];

        delete[] m_bzSection;
    }

    delete   m_XAPILibraryVersion;
    delete   m_KernelLibraryVersion;
    delete[] m_LibraryVersion;
    delete   m_TLS;
    delete[] m_szSectionName;
    delete[] m_SectionHeader;
	delete[] m_HeaderEx;
}

// ******************************************************************
// * Writer
// ******************************************************************
int32 Xbe::WriteExe(const char *x_szFilename)
{
    printf("Xbe::WriteExe Converting Xbe to Exe...");

    // ******************************************************************
    // * create buffer for "as-loaded" XBE/EXE hybrid
    // ******************************************************************
    uint08 *ExeBuffer = new uint08[m_Header.dwSizeOfImage];
    if (ExeBuffer == 0)
        XBE_WRITE_ERROR("Cannot allocate buffer for Exe");

    memset(ExeBuffer, 0, m_Header.dwSizeOfImage);

    // ******************************************************************
    // * write xbe section headers
    // ******************************************************************
    memcpy(ExeBuffer + 0, &m_Header, sizeof(Xbe::Header));
    memcpy(ExeBuffer + m_Header.dwSizeOfImageHeader, m_HeaderEx, m_HeaderExSize);

    // ******************************************************************
    // * write xbe sections
    // ******************************************************************
    for (uint32 v=0; v<m_Header.dwSections; v++)
    {
        uint32 offs = m_SectionHeader[v].dwVirtualAddr - m_Header.dwBaseAddr;
        memcpy(ExeBuffer + offs, m_bzSection[v], m_SectionHeader[v].dwSizeOfRaw);
    }

    // ******************************************************************
    // * patch digital signature with PE stub
    // ******************************************************************
    MicroExeHeaders ExeHeaders;

    ExeHeaders.m_DOSHeader.wMagic = *(uint16 *)"MZ";
    ExeHeaders.m_DOSHeader.Unused = 0;

    ExeHeaders.m_Header.dwMagic = *(uint32 *)"PE\0\0";
    ExeHeaders.m_Header.wMachine = IMAGE_FILE_MACHINE_I386;
    ExeHeaders.m_Header.wNumberOfSections = 1;
    ExeHeaders.m_Header.dwTimeDateStamp = m_Header.dwTimeDate;
    ExeHeaders.m_Header.dwPointerToSymbolTable = 0;
    ExeHeaders.m_Header.dwNumberOfSymbols = 0;
    ExeHeaders.m_Header.wSizeOfOptionalHeader = sizeof(MicroExeHeaders::OptionalHeader);
    ExeHeaders.m_Header.wCharacteristics = 0x0103;

    ExeHeaders.m_OptionalHeader.wMagic = 0x010B;
    ExeHeaders.m_OptionalHeader.bMajorLinkerVersion = 0x06;
    ExeHeaders.m_OptionalHeader.bMinorLinkerVersion = 0x00;
    ExeHeaders.m_OptionalHeader.dwSizeOfCode = 0;
    ExeHeaders.m_OptionalHeader.dwSizeOfInitializedData = 0;
    ExeHeaders.m_OptionalHeader.dwSizeOfUninitializedData = 0;
    ExeHeaders.m_OptionalHeader.dwAddressOfEntryPoint = (uint32)&ExeHeaders.m_Trampoline - (uint32)&ExeHeaders;
    ExeHeaders.m_OptionalHeader.dwBaseOfCode = 0;
    ExeHeaders.m_OptionalHeader.dwBaseOfData = 0;

    ExeHeaders.m_OptionalHeader.dwImageBase = m_Header.dwBaseAddr;
    ExeHeaders.m_OptionalHeader.dwLfanew_SectionAlignment = EXE_ALIGNMENT;
    ExeHeaders.m_OptionalHeader.dwFileAlignment = EXE_ALIGNMENT;
    ExeHeaders.m_OptionalHeader.wMajorOperatingSystemVersion = 4;
    ExeHeaders.m_OptionalHeader.wMinorOperatingSystemVersion = 0;
    ExeHeaders.m_OptionalHeader.wMajorImageVersion = 0;
    ExeHeaders.m_OptionalHeader.wMinorImageVersion = 0;
    ExeHeaders.m_OptionalHeader.wMajorSubsystemVersion = 4;
    ExeHeaders.m_OptionalHeader.wMinorSubsystemVersion = 0;
    ExeHeaders.m_OptionalHeader.dwWin32VersionValue = 0;
    ExeHeaders.m_OptionalHeader.dwSizeOfImage = m_Header.dwSizeOfImage; // already aligned at 0x20
    ExeHeaders.m_OptionalHeader.dwSizeOfHeaders = RoundUp(sizeof(MicroExeHeaders), EXE_ALIGNMENT);
    ExeHeaders.m_OptionalHeader.dwCheckSum = 0;
    ExeHeaders.m_OptionalHeader.wSubsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    ExeHeaders.m_OptionalHeader.wDllCharacteristics = 0x400;
    ExeHeaders.m_OptionalHeader.dwSizeOfStackReserve = 0x100000;
    ExeHeaders.m_OptionalHeader.dwSizeOfStackCommit = 0x1000;
    ExeHeaders.m_OptionalHeader.dwSizeOfHeapReserve = 0x100000;
    ExeHeaders.m_OptionalHeader.dwSizeOfHeapCommit = 0x1000;
    ExeHeaders.m_OptionalHeader.dwLoaderFlags = 0;
    ExeHeaders.m_OptionalHeader.dwNumberOfRvaAndSizes = 4;

    // ******************************************************************
    // * the other directories
    // ******************************************************************
    for (uint32 v=0; v<4; v++)
    {
        ExeHeaders.m_OptionalHeader.astDataDirectory[v].dwVirtualAddress = 0;
        ExeHeaders.m_OptionalHeader.astDataDirectory[v].dwSize = 0;
    }

    // ******************************************************************
    // * import directory
    // ******************************************************************
    uint32 offs = (uint32)&ExeHeaders.m_ImageImportDescriptor - (uint32)&ExeHeaders;

    ExeHeaders.m_OptionalHeader.astDataDirectory[1].dwVirtualAddress = offs;
    ExeHeaders.m_OptionalHeader.astDataDirectory[1].dwSize = 2*sizeof(MicroExeHeaders::ImageImportDescriptor);

    // ******************************************************************
    // * the one and only section header
    // ******************************************************************
    uint32 XbeSectionAddress = 0; // the whole image
    uint32 XbeSectionSize = m_Header.dwSizeOfImage - XbeSectionAddress; // already aligned at 0x20

    strncpy((char *)ExeHeaders.m_SectionHeader.szName, "loldongs", 8);
    ExeHeaders.m_SectionHeader.dwVirtualSize = XbeSectionSize;
    ExeHeaders.m_SectionHeader.dwVirtualAddress = XbeSectionAddress;
    ExeHeaders.m_SectionHeader.dwSizeOfRawData = XbeSectionSize;
    ExeHeaders.m_SectionHeader.dwPointerToRawData = XbeSectionAddress;
    ExeHeaders.m_SectionHeader.dwPointerToRelocations = 0;
    ExeHeaders.m_SectionHeader.dwPointerToLinenumbers = 0;
    ExeHeaders.m_SectionHeader.wNumberOfRelocations = 0;
    ExeHeaders.m_SectionHeader.wNumberOfLinenumbers = 0;
    ExeHeaders.m_SectionHeader.dwCharacteristics = 0x60000020;

    // ******************************************************************
    // * image import descriptor, only one DLL
    // ******************************************************************
    uint32 offsIat = (uint32)&ExeHeaders.m_ImportAddressTable - (uint32)&ExeHeaders;
    uint32 offsName = (uint32)&ExeHeaders.m_ImportName - (uint32)&ExeHeaders;

    ExeHeaders.m_ImageImportDescriptor[0].dwOriginalFirstThunk = offsIat;
    ExeHeaders.m_ImageImportDescriptor[0].dwTimeDateStamp = 0;
    ExeHeaders.m_ImageImportDescriptor[0].dwForwarderChain = 0;
    ExeHeaders.m_ImageImportDescriptor[0].dwName = offsName;
    ExeHeaders.m_ImageImportDescriptor[0].dwFirstThunk = offsIat;

    ExeHeaders.m_ImageImportDescriptor[1].dwOriginalFirstThunk = 0;
    ExeHeaders.m_ImageImportDescriptor[1].dwTimeDateStamp = 0;
    ExeHeaders.m_ImageImportDescriptor[1].dwForwarderChain = 0;
    ExeHeaders.m_ImageImportDescriptor[1].dwName = 0;
    ExeHeaders.m_ImageImportDescriptor[1].dwFirstThunk = 0;

    // ******************************************************************
    // * import address table, import by ordinal
    // ******************************************************************
    ExeHeaders.m_ImportAddressTable[0] = 0x80000001;
    ExeHeaders.m_ImportAddressTable[1] = 0;

    // ******************************************************************
    // * imported DLL name
    // ******************************************************************
    strncpy(ExeHeaders.m_ImportName, "DirtboxKe", 10);

    // ******************************************************************
    // * trampoline that calls the Dirtbox loader in the DLL
    // ******************************************************************
    ExeHeaders.m_Trampoline[0] = 0xFF; // JMP near absolute indirect
    ExeHeaders.m_Trampoline[1] = 0x25; // memory
    *(uint32 *)&ExeHeaders.m_Trampoline[2] = 0x000100EC;

    // ******************************************************************
    // * replaces the magic and digital signature with PE headers
    // ******************************************************************
    memcpy(ExeBuffer + 0, &ExeHeaders, sizeof(MicroExeHeaders));

    // ******************************************************************
    // * write the created buffer into EXE file
    // ******************************************************************
    FILE *ExeFile = fopen(x_szFilename, "wb");
    if (ExeFile == 0)
        XBE_WRITE_ERROR("Could not open Exe file");

    fwrite(ExeBuffer, m_Header.dwSizeOfImage, 1, ExeFile);
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
uint08 *Xbe::GetAddr(uint32 x_dwVirtualAddress)
{
    uint32 offs = x_dwVirtualAddress - m_Header.dwBaseAddr;

    // ******************************************************************
    // * offset in image header
    // ******************************************************************
    if(offs < sizeof(m_Header))
        return &((uint08*)&m_Header)[offs];

    // ******************************************************************
    // * offset in image header extra bytes
    // ******************************************************************
    if(offs < m_Header.dwSizeOfHeaders)
 		return (uint08*)&m_HeaderEx[offs - sizeof(m_Header)];

    // ******************************************************************
    // * offset in some random section
    // ******************************************************************
    {
        for(uint32 v=0; v<m_Header.dwSections; v++)
        {
            uint32 VirtAddr = m_SectionHeader[v].dwVirtualAddr;
            uint32 VirtSize = m_SectionHeader[v].dwVirtualSize;

            if( (x_dwVirtualAddress >= VirtAddr) && (x_dwVirtualAddress < (VirtAddr + VirtSize)) )
                return &m_bzSection[v][x_dwVirtualAddress - VirtAddr];
        }
    }

    return 0;
}
