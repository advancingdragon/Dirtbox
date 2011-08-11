#ifndef TYPES_H
#define TYPES_H

#define _CRT_SECURE_NO_WARNINGS

// ******************************************************************
// * Caustik's favorite typedefs
// ******************************************************************
typedef signed int     sint;
typedef unsigned int   uint;
typedef char           int08;
typedef short          int16;
typedef long           int32;
typedef unsigned char  uint08;
typedef unsigned short uint16;
typedef unsigned long  uint32;
typedef signed char    sint08;
typedef signed short   sint16;
typedef signed long    sint32;

inline static uint32 RoundUp(uint32 Value, uint32 Mult)
{
    if(Mult == 0)
        return Value;

    return Value - (Value - 1)%Mult + (Mult - 1);
}

#endif