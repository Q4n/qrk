#include "qrk_common.h"

void *memmem ( const void *haystack, size_t haystack_size, const void *needle, size_t needle_size )
{
    char *p;

    for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++ )
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;

    return NULL;
}

void *memstr ( const void *haystack, const char *needle, size_t size )
{
    char *p;
    size_t needle_size = strlen(needle);

    for ( p = (char *)haystack; p <= ((char *)haystack - needle_size + size); p++ )
        if ( memcmp(p, needle, needle_size) == 0 )
            return (void *)p;

    return NULL;
}