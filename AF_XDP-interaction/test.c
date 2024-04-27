#include <stdio.h>
#include "ethtool_utils.h"

int main(){
    int chanells = ethtool_get_channels("amigo");
    printf("chanells = %d\n", chanells);
    return 0;
}