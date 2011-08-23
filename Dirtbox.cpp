// Dirtbox.cpp : Defines the entry point for the console application.
//

#include "Types.h"
#include "Xbe.h"

#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("Usage: Dirtbox input output\n");
        return 1;
    }
    Xbe XbeFile(argv[1]);
    XbeFile.WriteExe(argv[2]);
    return 0;
}

