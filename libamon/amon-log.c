#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "amon-log.h"

char* dw_log_level_name[] = {"ERROR", "WARNING", "INFO", "DEBUG"};

// We call directly write to avoid the wrappers.
ssize_t __write(int fd, const void *buf, size_t count);

void dw_log(enum amon_log_level level, const char *fmt, ...) 
{
  char buffer[1024];

  // Write to a stack buffer and then call the low level write. We avoid any malloc that glibc could do
  // First the level name and category name
  int ret = snprintf(buffer, 1024, "\tAddressMonitor: %s: ", dw_log_level_name[level]);
  __write(2, buffer, ret);
  
  // Then write the user supplied format and arguments
  va_list args;
  va_start(args, fmt);
  ret = vsnprintf(buffer, 1024, fmt, args);
  __write(2, buffer, ret);
  va_end(args);
  
  // If the log level is "ERROR", this is fatal and the program exits
  if(level == ERROR) exit(1);
}

// Simple fprintf facility that should not use malloc
void amon_fprintf(int fd, const char *fmt, ...)
{
  char buffer[1024];

  va_list args;
  va_start(args, fmt);
  int ret = vsnprintf(buffer, 1024, fmt, args);
  __write(fd, buffer, ret);
  va_end(args);
}