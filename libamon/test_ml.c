#include <stdlib.h>

void foo(int *ptr) {
  *(ptr) = 2024;
}

int main(int argc, char *argv[])
{
int *ptr_taint = (int*)malloc(sizeof(int));
foo(ptr_taint);
*(ptr_taint) = 2025;
return 0;
}