#include "include/coolapk.h"

#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    char buf[512];
    char buff[512];

    strcpy(buf, "duangsuse");
    be(buf, "duangsuse");
    bd(buff, buf);

    printf("%s\n", buf);
    printf("%s\n", buff);
    r(buf);

    printf("%s\n", buf);

    me(buff, "duangsuse");
    printf("%s\n", buff);

    return 0;
}
