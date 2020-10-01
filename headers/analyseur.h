#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct dName {
    char *name;
    struct dName *next;
} dName;
