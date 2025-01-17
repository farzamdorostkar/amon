#include <stdlib.h>

void foo(int *ptr) {
  *(ptr) = 2024;
}

void bar(int *ptr) {
  *(ptr+1) = 2025;
}

int main(int argc, char *argv[])
{
int *ptr_taint = (int*)malloc(sizeof(int));
foo(ptr_taint);
bar(ptr_taint);
free(ptr_taint);
return 0;
}