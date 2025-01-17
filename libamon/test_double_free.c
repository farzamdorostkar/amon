#include <stdlib.h>

void foo(int *ptr) {
  *ptr = 2024;
  free(ptr);
}

void bar(int *ptr) {
  free(ptr);
}

int main(int argc, char *argv[])
{
int *ptr_taint = (int*)malloc(sizeof(int));
foo(ptr_taint);
bar(ptr_taint);
return 0;
}