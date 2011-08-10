// Dirtbox.cpp : Defines the entry point for the console application.
//

#include "Types.h"
#include "Xbe.h"

#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    Xbe XbeFile("C:\\Projects\\Xbox\\XGraphicsTest\\Release\\XGraphicsTest.xbe");
    XbeFile.WriteExe("C:\\Projects\\Xbox\\DirtboxKernel\\Debug\\xbe.exe");
    return 0;
}

