// ******************************************************************
// *
// *    .,-:::::    .,::      .::::::::.    .,::      .:
// *  ,;;;'````'    `;;;,  .,;;  ;;;'';;'   `;;;,  .,;; 
// *  [[[             '[[,,[['   [[[__[[\.    '[[,,[['  
// *  $$$              Y$$$P     $$""""Y$$     Y$$$P    
// *  `88bo,__,o,    oP"``"Yo,  _88o,,od8P   oP"``"Yo,  
// *    "YUMMMMMP",m"       "Mm,""YUMMMP" ,m"       "Mm,
// *
// *   Cxbx->Core->Xbe.h
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
#ifndef XBE_H
#define XBE_H

#include "Types.h"

// ******************************************************************
// * Xbe (Xbox Executable) file object
// ******************************************************************
class Xbe
{
public:
    // ******************************************************************
    // * Construct via Xbe file
    // ******************************************************************
    Xbe(const char *x_szFilename);

    // ******************************************************************
    // * Deconstructor
    // ******************************************************************
   ~Xbe();

   // ******************************************************************
   // * Patcher
   // ******************************************************************
   int32 PatchXbe();

   // ******************************************************************
   // * Writer
   // ******************************************************************
   int32 WriteExe(const char *x_szFilename);

    // ******************************************************************
    // * XBE header
    // ******************************************************************
    #include "AlignPrefix1.h"
    struct HEADER
    {
        uint32 Magic;                        // 0x0000 - magic number [should be "XBEH"]
        uint08 DigitalSignature[256];        // 0x0004 - digital signature
        uint32 BaseAddr;                     // 0x0104 - base address
        uint32 SizeOfHeaders;                // 0x0108 - size of headers
        uint32 SizeOfImage;                  // 0x010C - size of image
        uint32 SizeOfImageHeader;            // 0x0110 - size of image header
        uint32 TimeDate;                     // 0x0114 - timedate stamp
        uint32 CertificateAddr;              // 0x0118 - certificate address
        uint32 Sections;                     // 0x011C - number of sections
        uint32 SectionHeadersAddr;           // 0x0120 - section headers address

        struct INIT_FLAGS                    // 0x0124 - initialization flags
        {
            uint32 MountUtilityDrive   : 1;  // mount utility drive flag
            uint32 FormatUtilityDrive  : 1;  // format utility drive flag
            uint32 Limit64MB           : 1;  // limit development kit run time memory to 64mb flag
            uint32 DontSetupHarddisk   : 1;  // don't setup hard disk flag
            uint32 Unused               : 4; // unused (or unknown)
            uint32 Unused_b1            : 8; // unused (or unknown)
            uint32 Unused_b2            : 8; // unused (or unknown)
            uint32 Unused_b3            : 8; // unused (or unknown)
        } InitFlags;

        uint32 EntryAddr;                    // 0x0128 - entry point address
        uint32 TlsAddr;                      // 0x012C - thread local storage directory address
        uint32 PeStackCommit;                // 0x0130 - size of stack commit
        uint32 PeHeapReserve;                // 0x0134 - size of heap reserve
        uint32 PeHeapCommit;                 // 0x0138 - size of heap commit
        uint32 PeBaseAddr;                   // 0x013C - original base address
        uint32 PeSizeOfImage;                // 0x0140 - size of original image
        uint32 PeChecksum;                   // 0x0144 - original checksum
        uint32 PeTimeDate;                   // 0x0148 - original timedate stamp
        uint32 DebugPathnameAddr;            // 0x014C - debug pathname address
        uint32 DebugFilenameAddr;            // 0x0150 - debug filename address
        uint32 DebugUnicodeFilenameAddr;     // 0x0154 - debug unicode filename address
        uint32 KernelImageThunkAddr;         // 0x0158 - kernel image thunk address
        uint32 NonKernelImportDirAddr;       // 0x015C - non kernel import directory address
        uint32 LibraryVersions;              // 0x0160 - number of library versions
        uint32 LibraryVersionsAddr;          // 0x0164 - library versions address
        uint32 KernelLibraryVersionAddr;     // 0x0168 - kernel library version address
        uint32 XapiLibraryVersionAddr;       // 0x016C - xapi library version address
        uint32 LogoBitmapAddr;               // 0x0170 - logo bitmap address
        uint32 SizeOfLogoBitmap;             // 0x0174 - logo bitmap size
    }
    #include "AlignPosfix1.h"
    Header;

    // ******************************************************************
    // * XBE header extra bytes (used to preserve unknown data)
    // ******************************************************************
	char *HeaderEx;
    uint32 HeaderExSize;

    // ******************************************************************
    // * XBE certificate
    // ******************************************************************
    #include "AlignPrefix1.h"
    struct CERTIFICATE
    {
        uint32  Size;                               // 0x0000 - size of certificate
        uint32  TimeDate;                           // 0x0004 - timedate stamp
        uint32  TitleId;                            // 0x0008 - title id
        wchar_t TitleName[40];                      // 0x000C - title name (unicode)
        uint32  AlternateTitleId[0x10];             // 0x005C - alternate title ids
        uint32  AllowedMedia;                       // 0x009C - allowed media types
        uint32  GameRegion;                         // 0x00A0 - game region
        uint32  GameRatings;                        // 0x00A4 - game ratings
        uint32  DiskNumber;                         // 0x00A8 - disk number
        uint32  Version;                            // 0x00AC - version
        uint08  LanKey[16];                         // 0x00B0 - lan key
        uint08  SignatureKey[16];                   // 0x00C0 - signature key
        uint08  TitleAlternateSignatureKey[16][16]; // 0x00D0 - alternate signature keys
    }
    #include "AlignPosfix1.h"
    Certificate;

    // ******************************************************************
    // * XBE section header
    // ******************************************************************
    #include "AlignPrefix1.h"
    struct SECTION_HEADER
    {
        struct _FLAGS
        {
            uint32 Writable        : 1;  // writable flag
            uint32 Preload         : 1;  // preload flag
            uint32 Executable      : 1;  // executable flag
            uint32 InsertedFile    : 1;  // inserted file flag
            uint32 HeadPageRO      : 1;  // head page read only flag
            uint32 TailPageRO      : 1;  // tail page read only flag
            uint32 Unused_a1        : 1; // unused (or unknown)
            uint32 Unused_a2        : 1; // unused (or unknown)
            uint32 Unused_b1        : 8; // unused (or unknown)
            uint32 Unused_b2        : 8; // unused (or unknown)
            uint32 Unused_b3        : 8; // unused (or unknown)
        }
        Flags;

        uint32 VirtualAddr;            // virtual address
        uint32 VirtualSize;            // virtual size
        uint32 RawAddr;                // file offset to raw data
        uint32 SizeOfRaw;              // size of raw data
        uint32 SectionNameAddr;        // section name addr
        uint32 SectionRefCount;        // section reference count
        uint32 HeadSharedRefCountAddr; // head shared page reference count address
        uint32 TailSharedRefCountAddr; // tail shared page reference count address
        uint08 SectionDigest[20];      // section digest
    }
    #include "AlignPosfix1.h"
    *SectionHeader;

    // ******************************************************************
    // * XBE library versions
    // ******************************************************************
    #include "AlignPrefix1.h"
    struct LIBRARY_VERSION
    {
        char   Name[8];      // library name
        uint16 MajorVersion; // major version
        uint16 MinorVersion; // minor version
        uint16 BuildVersion; // build version

        struct FLAGS
        {
            uint16 QFEVersion : 13; // QFE Version
            uint16 Approved   : 2;  // Approved? (0:no, 1:possibly, 2:yes)
            uint16 DebugBuild : 1;  // Is this a debug build?
        }
        Flags;
    }
    #include "AlignPosfix1.h"
    *LibraryVersion, *KernelLibraryVersion, *XapiLibraryVersion;

    // ******************************************************************
    // * XBE Thread Local Storage
    // ******************************************************************
    #include "AlignPrefix1.h"
    struct TLS
    {
        uint32 DataStartAddr;             // raw start address
        uint32 DataEndAddr;               // raw end address
        uint32 TlsIndexAddr;              // tls index  address
        uint32 TlsCallbackAddr;           // tls callback address
        uint32 SizeOfZeroFill;            // size of zero fill
        uint32 Characteristics;           // characteristics
    }
    #include "AlignPosfix1.h"
    *Tls;

    // ******************************************************************
    // * XBE section names, each 8 bytes max and null terminated
    // ******************************************************************
    char (*SectionName)[9];

    // ******************************************************************
    // * XBE sections
    // ******************************************************************
    uint08 **Section;

    // ******************************************************************
    // * XBE original path
    // ******************************************************************
    char Path[260];

    // ******************************************************************
    // * XBE ascii title, translated from certificate title
    // ******************************************************************
    char AsciiTitle[40];

    // ******************************************************************
    // * GetTlsData
    // ******************************************************************
    uint08 *GetTlsData() { if(Tls == 0) return 0; else return GetAddr(Tls->DataStartAddr); }

    // ******************************************************************
    // * GetTlsIndex
    // ******************************************************************
    uint32 *GetTlsIndex() { if(Tls == 0) return 0; else return (uint32*)GetAddr(Tls->TlsIndexAddr); }

private:
    // ******************************************************************
    // * return a modifiable pointer inside this structure that 
    // * corresponds to a virtual address
    // ******************************************************************
    uint08 *GetAddr(uint32 VirtualAddress);
};

// ******************************************************************
// * Page size
// ****************************************************************** 
const uint32 PAGE_SIZE                               = 0x1000;

// ******************************************************************
// * Debug / Retail XOR Keys
// ****************************************************************** 
const uint32 XOR_EP_DEBUG                            = 0x94859D4B; // Entry Point (Debug)
const uint32 XOR_EP_RETAIL                           = 0xA8FC57AB; // Entry Point (Retail)
const uint32 XOR_KT_DEBUG                            = 0xEFB1F152; // Kernel Thunk (Debug)
const uint32 XOR_KT_RETAIL                           = 0x5B6D40B6; // Kernel Thunk (Retail)

// ******************************************************************
// * Game region flags for XBE certificate
// ****************************************************************** 
const uint32 XBEIMAGE_GAME_REGION_NA                 = 0x00000001;
const uint32 XBEIMAGE_GAME_REGION_JAPAN              = 0x00000002;
const uint32 XBEIMAGE_GAME_REGION_RESTOFWORLD        = 0x00000004;
const uint32 XBEIMAGE_GAME_REGION_MANUFACTURING      = 0x80000000;
 
// ******************************************************************
// * Media type flags for XBE certificate
// ****************************************************************** 
const uint32 XBEIMAGE_MEDIA_TYPE_HARD_DISK           = 0x00000001;
const uint32 XBEIMAGE_MEDIA_TYPE_DVD_X2              = 0x00000002;
const uint32 XBEIMAGE_MEDIA_TYPE_DVD_CD              = 0x00000004;
const uint32 XBEIMAGE_MEDIA_TYPE_CD                  = 0x00000008;
const uint32 XBEIMAGE_MEDIA_TYPE_DVD_5_RO            = 0x00000010;
const uint32 XBEIMAGE_MEDIA_TYPE_DVD_9_RO            = 0x00000020;
const uint32 XBEIMAGE_MEDIA_TYPE_DVD_5_RW            = 0x00000040;
const uint32 XBEIMAGE_MEDIA_TYPE_DVD_9_RW            = 0x00000080;
const uint32 XBEIMAGE_MEDIA_TYPE_DONGLE              = 0x00000100;
const uint32 XBEIMAGE_MEDIA_TYPE_MEDIA_BOARD         = 0x00000200;
const uint32 XBEIMAGE_MEDIA_TYPE_NONSECURE_HARD_DISK = 0x40000000;
const uint32 XBEIMAGE_MEDIA_TYPE_NONSECURE_MODE      = 0x80000000;
const uint32 XBEIMAGE_MEDIA_TYPE_MEDIA_MASK          = 0x00FFFFFF;

// ******************************************************************
// * OpenXDK logo bitmap (used by cxbe by default)
// ****************************************************************** 
extern uint08 OpenXDK[];
extern uint32 SizeOfOpenXDK;

#endif
