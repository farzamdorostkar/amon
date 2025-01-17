// We wrap all important calls to glibc to insure that pointers are checked and unprotected before being used 
// internally in glibc or passed to system calls.
//
// For each pointer argument, we need to check, unprotect, call the glibc function and reprotect.
// If a glibc function calls another nested glibc function, there is no need to do further
// processing, because the arguments should have already been checked and unprotected.

#define _GNU_SOURCE

#include <malloc.h>
#include <string.h>
#include <wchar.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <sched.h>
#include <limits.h>
#include <sys/mman.h>

#include <execinfo.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <libintl.h>
#include <locale.h>
#include <sys/param.h>
#include <ctype.h> /// isdigit
#include "amon-log.h"
#include "amon-protect.h"
#include "amon-wrap-glibc.h"

// Intercept common glibc functions to check access and remove the protection from pointers. 
// This is essential for system calls because otherwise they will fail.
// It is also useful for utility functions, as it can simplify the access check 
// (a single one instead of multiple ones) and avoid some functions that may perform 
// tricky pointer arithmetic (e.g. memcpy / memmove)
//
// Only a minimal set of wrappers was implemented, it is far from being complete. 
// Moreover, some of the wrappers are incomplete. For instance, for the execvpe and 
// similar functions, the argv and envp arrays are unprotected, but not the pointers
// contained within. This would require allocating a new array where to copy the unprotected
// pointers.

// Check that we can get the desired symbol

void *dlsym_check(void *restrict handle, const char *restrict symbol) {
    void *ret = dlsym(handle, symbol);
    if(ret == NULL) dw_log(WARNING, "Symbol %s not found\n", symbol);
    return ret;
}

// Size of argv arguments in execve and similar functions

static size_t arglen(char *const argv[])
{
    size_t i = 0;
    for(; argv[i] != NULL; i++);
    return sizeof(char *) * (i + 1);
}

// Have our own strlen, not called with tainted pointers, that will
// not be instrumented by libpatch.

size_t dw_strlen(const char* s)
{
  const char* cursor;
  for (cursor = s; *cursor != 0; cursor++);
  return (size_t)(cursor - s);
}

// Declare all the pointers to the original libc functions

static char* (*libc_strchr)(const char *s, int c);
static char* (*libc_strrchr)(const char *s, int c);
static int (*libc_strcmp)(const char *s1, const char *s2);
static int (*libc_strncmp)(const char *s1, const char *s2, size_t n);
static int (*libc_fputs)(const char *restrict s, FILE *restrict stream);
static int (*libc_puts)(const char *s);
static size_t (*libc_strlen)(const char *s);
static int (*libc_open)(const char *pathname, int flags, ...);
static int (*libc_openat)(int dirfd, const char *pathname, int flags, ...);
static int (*libc_creat)(const char *pathname, mode_t mode);
static int (*libc_access)(const char *pathname, int mode);
static char* (*libc_getcwd)(char *buf, size_t size);
static ssize_t (*libc_getrandom)(void *buf, size_t buflen, unsigned int flags);
static int (*libc_stat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstat)(int fd, struct stat *statbuf);
static int (*libc_lstat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstatat)(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);
static size_t (*libc_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
static size_t (*libc_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
static ssize_t (*libc_pread)(int fd, void *buf, size_t count, off_t offset);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count, off_t offset);
static ssize_t (*libc_read)(int fd, void *buf, size_t count);
extern ssize_t __read(int fd, void *buf, size_t count);
static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
extern ssize_t libc_real_write(int fd, const void *buf, size_t count);
static int (*libc_statfs)(const char *path, struct statfs *buf);
static int (*libc_fstatfs)(int fd, struct statfs *buf);
static ssize_t (*libc_getdents64)(int fd, void *dirp, size_t count);
static DIR* (*libc_opendir)(const char *name);
static int (*libc_bcmp)(const void *s1, const void *s2, size_t n);
static void (*libc_bcopy)(const void *src, void *dest, size_t n);
static void (*libc_bzero)(void *s, size_t n);
static void* (*libc_memccpy)(void *dest, const void *src, int c, size_t n);
static void* (*libc_memchr)(const void *s, int c, size_t n);
static int (*libc_memcmp)(const void *s1, const void *s2, size_t n);
static void* (*libc_memcpy)(void *dest, const void *src, size_t n);
static void* (*libc_memcpy_chk)(void *dest, const void *src, size_t len, size_t destlen);
static void* (*libc_memfrob)(void *s, size_t n);
static void* (*libc_memmem)(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
static void* (*libc_memmove)(void *dest, const void *src, size_t n);
static void* (*libc_mempcpy)(void *restrict dest, const void *restrict src, size_t n);
static void* (*libc_memset)(void *s, int c, size_t n);
static char* (*libc_strcpy)(char *restrict dest, const char *src);
static char* (*libc_strcat)(char *restrict dest, const char *src);
static char* (*libc_strncpy)(char *restrict dest, const char *restrict src, size_t n);
static wchar_t* (*libc_wmemmove)(wchar_t *dest, const wchar_t *src, size_t n);
static wchar_t* (*libc_wmempcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static wchar_t* (*libc_wmemcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static char* (*libc_gettext)(const char * msgid);
static char* (*libc_dgettext)(const char * domainname, const char * msgid);
extern char* __dgettext(const char * domainname, const char * msgid);
extern char* __dcgettext(const char * domainname, const char * msgid, int category);
static char* (*libc_ngettext)(const char *msgid, const char *msgid_plural, unsigned long int n);
static char* (*libc_dcngettext)(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category);
static char* (*libc_setlocale)(int category, const char *locale);
static char* (*libc_textdomain)(const char * domainname);
static int (*libc_execve)(const char *pathname, char *const argv[], char *const envp[]);
static int (*libc_execv)(const char *pathname, char *const argv[]);
static int (*libc_execvp)(const char *file, char *const argv[]);
static int (*libc_execvpe)(const char *file, char *const argv[], char *const envp[]);
//static int (*libc_vfscanf)(FILE *stream, const char *format, va_list args); //
static int (*libc_fscanf)(FILE *stream, const char *format, ...); //

// Get the address for all the wrapped libc functions. Some of these functions may get called
// very early. Therefore we do check for initialization right before use with the iss() macro.

int dw_init_stubs = 0;
// size_t (*dw_strlen)(const char *s);

void dw_init_syscall_stubs() {

    libc_strlen = dw_strlen;
    libc_strchr = dlsym_check(RTLD_NEXT, "strchr");
    libc_strrchr = dlsym_check(RTLD_NEXT, "strrchr");
    libc_strcmp = dlsym_check(RTLD_NEXT, "strcmp");
    libc_strncmp = dlsym_check(RTLD_NEXT, "strncmp");
    libc_fputs = dlsym_check(RTLD_NEXT, "fputs");
    libc_puts = dlsym_check(RTLD_NEXT, "puts");
    libc_open = dlsym_check(RTLD_NEXT, "open");
    libc_openat = dlsym_check(RTLD_NEXT, "openat");
    libc_creat = dlsym_check(RTLD_NEXT, "creat");
    libc_access = dlsym_check(RTLD_NEXT, "access");
    libc_getcwd = dlsym_check(RTLD_NEXT, "getcwd");
    libc_getrandom = dlsym_check(RTLD_NEXT, "getrandom");
    libc_stat = dlsym_check(RTLD_NEXT, "stat");
    libc_fstat = dlsym_check(RTLD_NEXT, "fstat");
    libc_lstat = dlsym_check(RTLD_NEXT, "lstat");
    libc_fstatat = dlsym_check(RTLD_NEXT, "fstatat");
    libc_fread = dlsym_check(RTLD_NEXT, "fread");
    libc_fwrite = dlsym_check(RTLD_NEXT, "fwrite");
    libc_pread = dlsym_check(RTLD_NEXT, "pread");
    libc_pwrite = dlsym_check(RTLD_NEXT, "pwrite");
    libc_read = __read; // dlsym_check(RTLD_NEXT, "read");
    libc_write = dlsym_check(RTLD_NEXT, "write");
    libc_statfs = dlsym_check(RTLD_NEXT, "statfs");
    libc_fstatfs = dlsym_check(RTLD_NEXT, "fstatfs");
    libc_getdents64 = dlsym_check(RTLD_NEXT, "getdents64");
    libc_bcmp = dlsym_check(RTLD_NEXT, "bcmp");
    libc_bcopy = dlsym_check(RTLD_NEXT, "bcopy");
    libc_bzero = dlsym_check(RTLD_NEXT, "bzero");
    libc_memccpy = dlsym_check(RTLD_NEXT, "memccpy");
    libc_memchr = dlsym_check(RTLD_NEXT, "memchr");
    libc_memcmp = dlsym_check(RTLD_NEXT, "memcmp");
    libc_memcpy = dlsym_check(RTLD_NEXT, "memcpy");
    libc_memcpy_chk = dlsym_check(RTLD_NEXT, "__memcpy_chk");
    libc_memfrob = dlsym_check(RTLD_NEXT, "memfrob");
    libc_memmem = dlsym_check(RTLD_NEXT, "memmem");
    libc_memmove = dlsym_check(RTLD_NEXT, "memmove");
    libc_mempcpy = dlsym_check(RTLD_NEXT, "mempcpy");
    libc_memset = dlsym_check(RTLD_NEXT, "memset");
    libc_strcpy = dlsym_check(RTLD_NEXT, "strcpy");
    libc_strcat = dlsym_check(RTLD_NEXT, "strcat");
    libc_strncpy = dlsym_check(RTLD_NEXT, "strncpy");
    libc_wmemmove = dlsym_check(RTLD_NEXT, "wmemmove");
    libc_wmempcpy = dlsym_check(RTLD_NEXT, "wmempcpy");
    libc_wmemcpy = dlsym_check(RTLD_NEXT, "wmemcpy");
    libc_gettext = dlsym_check(RTLD_NEXT, "gettext");
    libc_dgettext = __dgettext; // dlsym_check(RTLD_NEXT, "dgettext ");
    libc_ngettext = dlsym_check(RTLD_NEXT, "ngettext");
    libc_dcngettext = dlsym_check(RTLD_NEXT, "dcngettext");
    libc_setlocale = dlsym_check(RTLD_NEXT, "setlocale");
    libc_opendir = dlsym_check(RTLD_NEXT, "opendir");
    libc_textdomain = dlsym_check(RTLD_NEXT, "textdomain");
    libc_execve = dlsym_check(RTLD_NEXT, "execve");
    libc_execv = dlsym_check(RTLD_NEXT, "execv");
    libc_execvp = dlsym_check(RTLD_NEXT, "execvp");
    libc_execvpe = dlsym_check(RTLD_NEXT, "execvpe");
    libc_fscanf = dlsym_check(RTLD_NEXT, "fscanf");
    dw_init_stubs = 1;
}

// Make it shorter, every function calls those
#define sin() dw_sin()
#define sout() dw_sout()

// For each tainted pointer passed to a wrapper, we could eventually check if it is accessed properly,
// given the semantics of the function called and the bounds of the pointed object.
// The replacements for libc functions for now simply remove the taint before calling
// the replaced functions. In some cases, the taint must be reapplied. For instance,
// the memccpy function copies a string to a certain character then returns a pointer to
// that character. This pointer may be derived from a tainted pointer and the taint must be
// carried to it from the dest pointer.

size_t strlen(const char *s) { sin(); size_t ret = libc_strlen(amon_unprotect((void *)s)); dw_reprotect((void *)s); sout(); return ret; }

#include "dw-printf.h"

static inline void fputc_wrapper(char c, void* extra_arg)
{
    FILE *fp = (FILE *)extra_arg;
    fputc(c, fp);
}

static inline void dputc_wrapper(char c, void* extra_arg)
{
    int fd = (int)((uintptr_t)extra_arg);
    libc_write(fd, &c, 1);
}

int __fprintf_chk(FILE *stream, int flag, const char *format, ...) {
    va_list arg; va_start(arg, format); 
    const int ret = vfctprintf(fputc_wrapper, (void *)stream, format, arg);
    va_end(arg);
    return ret;
}

int fprintf(FILE *stream, const char *format, ...) {
    va_list arg; va_start(arg, format); 
    const int ret = vfctprintf(fputc_wrapper, (void *)stream, format, arg);
    va_end(arg);
    return ret;
}

int dprintf(int fd, const char *format, ...) {
    va_list arg; va_start(arg, format); 
    const int ret = vfctprintf(dputc_wrapper, (void *)((uintptr_t)fd), format, arg);
    va_end(arg);
    return ret;
}

int __sprintf_chk(char *s, int flag, size_t os, const char *fmt, ...) {
  va_list arg;
  va_start(arg, fmt);
  const int ret = vsnprintf(s, os, fmt, arg);
  va_end(arg);
  return ret;
}

int __snprintf_chk(char *s, size_t maxlen, int flag, size_t os, const char *fmt, ...) {
  va_list arg;
  va_start(arg, fmt);
  const int ret = vsnprintf(s, os, fmt, arg);
  va_end(arg);
  return ret;
}

int vfprintf(FILE *restrict stream, const char *restrict format, va_list arg)
{
    return vfctprintf(fputc_wrapper, (void *)stream, format, arg);
}

int vdprintf(int fd, const char *restrict format, va_list arg)
{
    return vfctprintf(dputc_wrapper, (void *)((uintptr_t)fd), format, arg);
}

char *strchr(const char *s, int c) { sin(); char *ns = amon_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); char *ret = libc_strchr(ns, c); dw_reprotect((void *)s); sout(); if(ret == NULL) return ret; return (void *)amon_retaint(ret, s); }
char *strrchr(const char *s, int c) { sin(); char *ns = amon_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); char *ret = libc_strrchr(ns, c); dw_reprotect((void *)s); sout(); if(ret == NULL) return ret; return (void *)amon_retaint(ret, s); }
int strcmp(const char *s1, const char *s2) { sin(); char *ns1 = amon_unprotect((void *)s1); dw_check_access((void *)s1, libc_strlen(ns1) + 1); char *ns2 = amon_unprotect((void *)s2); dw_check_access((void *)s2, libc_strlen(ns2) + 1); int ret = libc_strcmp(ns1, ns2); dw_reprotect((void *)s1); dw_reprotect((void *)s2); sout(); return ret; }
int strncmp(const char *s1, const char *s2, size_t n) { sin(); char *ns1 = amon_unprotect((void *)s1); dw_check_access((void *)s1, MIN(n, libc_strlen(ns1) + 1)); char *ns2 = amon_unprotect((void *)s2); dw_check_access((void *)s2, MIN(n, libc_strlen(ns2) + 1)); int ret = libc_strncmp(ns1, ns2, n); dw_reprotect((void *)s1); dw_reprotect((void *)s2); sout(); return ret; }
int fputs(const char *restrict s, FILE *restrict stream) { sin(); char *ns = amon_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); int ret = libc_fputs(ns, stream); dw_reprotect((void *)s); sout(); return ret; }
int puts(const char *s) { sin(); char *ns = amon_unprotect((void *)s); dw_check_access((void *)s, libc_strlen(ns) + 1); int ret = libc_puts(ns); dw_reprotect((void *)s); sout(); return ret; }

// Open can take 2 or 3 arguments, we handle it just like glibc does it internally.
int open(const char *pathname, int flags, ...) { 
    sin(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    char *npathname = amon_unprotect((void *)pathname);
    dw_check_access((void *)pathname, libc_strlen(npathname) + 1); int ret = libc_open(npathname, flags, mode);
    dw_reprotect((void *)pathname); sout(); return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...) { 
    sin(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    char *npathname = amon_unprotect((void *)pathname);
    dw_check_access((void *)pathname, libc_strlen(npathname) + 1); int ret = libc_openat(dirfd, npathname, flags, mode);
    dw_reprotect((void *)pathname); sout(); return ret;
}

int creat(const char *pathname, mode_t mode) { sin(); char *npathname = amon_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); int ret = libc_creat(npathname, mode); dw_reprotect((void *)pathname); sout(); return ret; }
int access(const char *pathname, int mode) { sin(); char *npathname = amon_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); int ret = libc_access(npathname, mode); dw_reprotect((void *)pathname); sout(); return ret; }
char *getcwd(char *buf, size_t size) { sin(); dw_check_access((void *)buf, size); char *ret = libc_getcwd(amon_unprotect((void *)buf), size); dw_reprotect((void *)buf); sout(); if(ret == amon_unprotect(buf)) return buf; return ret; }
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) { sin(); dw_check_access((void *)buf, buflen); ssize_t ret = libc_getrandom(amon_unprotect(buf), buflen, flags); dw_reprotect(buf); sout(); return ret; }
int stat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); char *npathname = amon_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_stat(npathname, (struct stat *)amon_unprotect((void *)statbuf)); dw_reprotect((void *)pathname); dw_reprotect((void *)statbuf); sout(); return ret; }
int fstat(int fd, struct stat *statbuf) { sin(); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_fstat(fd, (struct stat *)amon_unprotect(statbuf)); dw_reprotect(statbuf); sout(); return ret; }
int lstat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); char *npathname = amon_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_lstat(npathname, (struct stat *)amon_unprotect((void *)statbuf)); dw_reprotect((void *)pathname); dw_reprotect((void *)statbuf); sout(); return ret; }
int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags) { sin(); char *npathname = amon_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)statbuf, sizeof(struct stat)); int ret = libc_fstatat(dirfd, npathname, (struct stat *)amon_unprotect((void *)statbuf), flags); dw_reprotect((void *)pathname); dw_reprotect((void *)statbuf); sout(); return ret; }
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) { sin(); dw_check_access(ptr, size * nmemb); ssize_t ret = libc_fread(amon_unprotect(ptr), size, nmemb, stream); dw_reprotect(ptr); sout(); return ret; }
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) { sin(); dw_check_access(ptr, size * nmemb); ssize_t ret = libc_fwrite((const void *)amon_unprotect(ptr), size, nmemb, stream); dw_reprotect(ptr); sout(); return ret; }
ssize_t pread(int fd, void *buf, size_t count, off_t offset) { sin(); dw_check_access(buf, count); ssize_t ret = libc_pread(fd, amon_unprotect(buf), count, offset); dw_reprotect(buf); sout(); return ret; }
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) { sin(); dw_check_access(buf, count); ssize_t ret = libc_pwrite(fd, (const void *)amon_unprotect(buf), count, offset); dw_reprotect(buf); sout(); return ret; }
ssize_t read(int fd, void *buf, size_t count) { sin(); dw_check_access(buf, count); ssize_t ret = libc_read(fd, amon_unprotect(buf), count); dw_reprotect(buf); sout(); return ret; }
ssize_t write(int fd, const void *buf, size_t count) { sin(); dw_check_access(buf, count); ssize_t ret = libc_write(fd, (const void *)amon_unprotect(buf), count); dw_reprotect(buf); sout(); return ret; }
int statfs(const char *path, struct statfs *buf) { sin(); char *npath = amon_unprotect((void *)path); dw_check_access((void *)path, libc_strlen(npath) + 1); dw_check_access((void *)buf, sizeof(struct statfs)); int ret = libc_statfs(npath, (struct statfs *)amon_unprotect((void *)buf)); dw_reprotect((void *)path); dw_reprotect((void *)buf); sout(); return ret; }
int fstatfs(int fd, struct statfs *buf) { sin(); dw_check_access((void *)buf, sizeof(struct statfs)); int ret = libc_fstatfs(fd, (struct statfs *)amon_unprotect((void *)buf)); dw_reprotect((void *)buf); sout(); return ret; }
ssize_t getdents64(int fd, void *dirp, size_t count) { sin(); dw_check_access(dirp, count); ssize_t ret = libc_getdents64(fd, amon_unprotect(dirp), count); dw_reprotect(dirp); sout(); return ret; }
DIR *opendir(const char *name) { sin(); char *nname = amon_unprotect((void *)name); dw_check_access((void *)name, libc_strlen(nname) + 1); DIR *ret = libc_opendir(nname); dw_reprotect(name); sout(); return ret; }
int bcmp(const void *s1, const void *s2, size_t n) { sin(); dw_check_access(s1, n); dw_check_access(s2, n); int ret = libc_bcmp((const void *)amon_unprotect(s1), (const void *)amon_unprotect(s2), n); dw_reprotect(s1); dw_reprotect(s2); sout(); return ret; }
void bcopy(const void *src, void *dest, size_t n) { sin(); dw_check_access(src, n); dw_check_access(dest, n); libc_bcopy((const void *)amon_unprotect(src), (void *)amon_unprotect(dest), n); dw_reprotect(src); dw_reprotect(dest); sout(); }
void bzero(void *s, size_t n) { sin(); dw_check_access(s, n); libc_bzero((void *)amon_unprotect(s), n); dw_reprotect(s); sout(); }

void *memccpy(void *dest, const void *src, int c, size_t n) { 
    sin();
    dw_check_access(dest, n); dw_check_access(src, n); 
    void *ret = libc_memccpy((void *)amon_unprotect(dest), (const void *)amon_unprotect(src), c, n);
    dw_reprotect(dest);
    dw_reprotect(src);
    sout();
    if(ret == NULL) return ret;
    return (void *)amon_retaint(ret, dest);
}

void *memchr(const void *s, int c, size_t n) { 
    sin();
    dw_check_access(s, n); 
    void *ret = libc_memchr((const void *)amon_unprotect(s), c, n);
    dw_reprotect(s);
    sout();
    if(ret == NULL) return ret;
    return (void *)amon_retaint(ret, s);
}

int memcmp(const void *s1, const void *s2, size_t n) { sin(); dw_check_access(s1, n); dw_check_access(s2, n); int ret = libc_memcmp((const void *)amon_unprotect(s1), (const void *)amon_unprotect(s2), n); dw_reprotect(s1); dw_reprotect(s2); sout(); return ret; }
void *memcpy(void *dest, const void *src, size_t n) { sin(); dw_check_access(dest, n); dw_check_access(src, n); libc_memcpy((void *)amon_unprotect(dest), (const void *)amon_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
void *__memcpy_chk(void *dest, const void *src, size_t len, size_t destlen) { sin(); dw_check_access(dest, destlen); dw_check_access(src, len); libc_memcpy_chk((void *)amon_unprotect(dest), (const void *)amon_unprotect(src), len, destlen); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
// void *memfrob(void *s, size_t n) { sin(); return libc_memfrob(void *s, size_t n); }

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) { 
    sin();
    dw_check_access(haystack, haystacklen); dw_check_access(needle, needlelen); 
    void *ret = libc_memmem((const void *)amon_unprotect(haystack), haystacklen, (const void *)amon_unprotect(needle), needlelen); 
    dw_reprotect(haystack); dw_reprotect(needle);
    sout();
    if(ret == NULL) return ret;
    return (void *)amon_retaint(ret, haystack);
}

void *memmove(void *dest, const void *src, size_t n) { sin(); dw_check_access(dest, n); dw_check_access(src, n); libc_memmove((void *)amon_unprotect(dest), (void *)amon_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
void *mempcpy(void *restrict dest, const void *restrict src, size_t n) { sin(); dw_check_access(dest, n); dw_check_access(src, n); libc_mempcpy((void *)amon_unprotect(dest), (void *)amon_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
void *memset(void *s, int c, size_t n) { sin(); dw_check_access(s, n); libc_memset((void *)amon_unprotect(s), c, n); dw_reprotect(s); sout(); return s; }
char *strcpy(char *restrict dest, const char *src) { sin(); char *ndest = amon_unprotect((void *)dest); char *nsrc = amon_unprotect((void *)src); size_t len = libc_strlen(nsrc) + 1; dw_check_access(dest, len); dw_check_access(src, len); libc_strcpy(ndest, nsrc); dw_reprotect(dest); dw_reprotect(src); sout(); return dest;}
char *strcat(char *restrict dest, const char *src) { sin(); char *ndest = amon_unprotect((void *)dest); char *nsrc = amon_unprotect((void *)src); size_t dst_len = libc_strlen(ndest); size_t src_len = libc_strlen(nsrc); dw_check_access(dest, dst_len + src_len + 1); dw_check_access(src, src_len + 1); libc_strcat(ndest, nsrc); dw_reprotect(dest); dw_reprotect(src); sout(); return dest;}
char *strncpy(char *restrict dest, const char *restrict src, size_t n) { sin(); char *nsrc = amon_unprotect((void *)src); size_t len = libc_strlen(nsrc) + 1; dw_check_access(dest, n); dw_check_access(src, len < n ? len : n); libc_strncpy(amon_unprotect(dest), nsrc, n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
wchar_t *wmemmove(wchar_t *dest, const wchar_t *src, size_t n) { sin(); dw_check_access(dest, n * sizeof(wchar_t)); dw_check_access(src, n * sizeof(wchar_t)); libc_wmemmove((wchar_t *)amon_unprotect(dest), (wchar_t *)amon_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }

wchar_t *wmempcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { 
    sin();
    dw_check_access(dest, n * sizeof(wchar_t)); dw_check_access(src, n * sizeof(wchar_t));
    wchar_t *ret = libc_wmempcpy((wchar_t *)amon_unprotect(dest), (wchar_t *)amon_unprotect(src), n);
    dw_reprotect(dest); dw_reprotect(src);
    sout(); return (wchar_t *)amon_retaint(ret, dest);
}

wchar_t *wmemcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { sin(); dw_check_access(dest, n * sizeof(wchar_t)); dw_check_access(src, n * sizeof(wchar_t)); libc_wmemcpy((wchar_t *)amon_unprotect(dest), (wchar_t *)amon_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
/// char *gettext (const char * msgid) { sin(); char *nmsgid = amon_unprotect((void *)msgid); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); char *ret = libc_gettext(nmsgid); dw_reprotect(msgid); sout(); if(ret == nmsgid) return (char *)msgid; else return ret; }
/// char *dgettext (const char * domainname, const char * msgid) { sin(); char *ndomainname = amon_unprotect((void *)domainname); char *nmsgid = amon_unprotect((void *)msgid); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); char *ret = libc_dgettext(ndomainname, nmsgid); dw_reprotect(domainname); dw_reprotect(msgid); sout(); if(ret == nmsgid) return (char *)msgid; else return ret; }
char *dcgettext (const char * domainname, const char * msgid, int category) { sin(); char *ndomainname = amon_unprotect((void *)domainname); char *nmsgid = amon_unprotect((void *)msgid); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); char *ret = __dcgettext (ndomainname, nmsgid, category); dw_reprotect(domainname); dw_reprotect(msgid); sout(); if(ret == nmsgid) return (char *)msgid; else return ret; }
/// char *ngettext(const char *msgid, const char *msgid_plural, unsigned long int n) { sin(); char *nmsgid = amon_unprotect((void *)msgid); char *nmsgid_plural = amon_unprotect((void *)msgid_plural); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); dw_check_access((void *)msgid_plural, libc_strlen(nmsgid_plural) + 1); char *ret = libc_ngettext(nmsgid, nmsgid_plural, n); dw_reprotect(msgid); dw_reprotect(msgid_plural); sout(); if(ret == nmsgid) return (char *)msgid; else if(ret == nmsgid_plural) return (char *)msgid_plural; else return ret; } 
char *dcngettext(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category) { sin(); char *ndomainname = amon_unprotect((void *)domainname); char *nmsgid = amon_unprotect((void *)msgid); char *nmsgid_plural = amon_unprotect((void *)msgid_plural); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); dw_check_access((void *)msgid, libc_strlen(nmsgid) + 1); dw_check_access((void *)msgid_plural, libc_strlen(nmsgid_plural) + 1); char *ret = libc_dcngettext(ndomainname, nmsgid, nmsgid_plural, n, category); dw_reprotect(domainname); dw_reprotect(msgid); dw_reprotect(msgid_plural); sout(); if(ret == nmsgid) return (char *)msgid; else if(ret == nmsgid_plural) return (char *)msgid_plural; else return ret; }
char *setlocale(int category, const char *locale) { sin(); char *nlocale = amon_unprotect((void *)locale); dw_check_access((void *)locale, libc_strlen(nlocale) + 1); char *ret = libc_setlocale(category, nlocale); dw_reprotect(locale); sout(); return ret; }
char *textdomain(const char * domainname) { sin(); char *ndomainname = amon_unprotect((void *)domainname); dw_check_access((void *)domainname, libc_strlen(ndomainname) + 1); char *ret = libc_textdomain(ndomainname); dw_reprotect(domainname); sout(); return ret; }
int execve(const char *pathname, char *const argv[], char *const envp[]) { sin(); char *npathname = amon_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)argv, arglen(argv)); dw_check_access((void *)envp, arglen(envp)); int ret = libc_execve(npathname, amon_unprotect(argv), amon_unprotect(envp)); dw_reprotect(pathname); dw_reprotect(argv); dw_reprotect(envp); sout(); return ret; }
int execv(const char *pathname, char *const argv[]) { sin(); char *npathname = amon_unprotect((void *)pathname); dw_check_access((void *)pathname, libc_strlen(npathname) + 1); dw_check_access((void *)argv, arglen(argv)); int ret = libc_execv(npathname, amon_unprotect(argv)); dw_reprotect(pathname); dw_reprotect(argv); sout(); return ret; }
int execvp(const char *file, char *const argv[]) { sin(); char *nfile = amon_unprotect((void *)file); dw_check_access((void *)file, libc_strlen(nfile) + 1); dw_check_access((void *)argv, arglen(argv)); int ret = libc_execvp(nfile, amon_unprotect(argv)); dw_reprotect(file); dw_reprotect(argv); sout(); return ret; }
int execvpe(const char *file, char *const argv[], char *const envp[]) { sin(); char *nfile = amon_unprotect((void *)file); dw_check_access((void *)file, libc_strlen(nfile) + 1); dw_check_access((void *)argv, arglen(argv)); dw_check_access((void *)envp, arglen(envp)); int ret = libc_execvpe(nfile, amon_unprotect(argv), amon_unprotect(envp)); dw_reprotect(file); dw_reprotect(argv); dw_reprotect(envp); sout(); return ret; }

int __isoc99_fscanf(FILE *stream, const char *format, ...) {
	sin();

  va_list ap;
	va_start(ap, format);

	FILE *nstream = (FILE *)amon_unprotect((void *)stream);
	const char *nformat  = (const char *)amon_unprotect((void *)format);

	int total_scanned = 0;

	const char *fptr = nformat;
	while(*fptr) {
		if(*fptr == '%') {
			fptr++;

			// We collect the specifier in a small buffer, e.g., "%d" or "%10s"
			char spec[32];
			int idx = 0;
			spec[idx++] = '%';

			 // (A) Collect potential width (digits)
			 while (isdigit((unsigned char)*fptr) && idx < 30) {
				spec[idx++] = *fptr++;
			 }

			 // (B) Check if there is an 'l' (or 'L') next
			 int saw_l = 0;
			 if ((*fptr == 'l' || *fptr == 'L') && idx < 30) {
				spec[idx++] = *fptr++;
				saw_l = 1;
			 }

			 // (C) Now collect the main specifier type
			 if (*fptr && idx < 31) {
				spec[idx++] = *fptr++;
			 }
			 spec[idx] = '\0';

			 char final_ch = spec[idx-1];

			 switch (final_ch)
			 {
				case 'd':
				{
					int *arg_ptr = va_arg(ap, int *);
					int *p = (int *)amon_unprotect((void *)arg_ptr);

					libc_fscanf(nstream, spec, p);
					total_scanned++;
					break;
				}
				case 'f':
				case 'e':
				case 'g':
				{
					if (saw_l) {
						// e.g. '%lf', '%le', '%lg' => double*
						double *arg_ptr = va_arg(ap, double *);
						double *p = (double *)amon_unprotect((void *)arg_ptr);

						libc_fscanf(nstream, spec, p);
					} else {
						// e.g. '%f', '%e', '%g' => float*
						float *arg_ptr = va_arg(ap, float *);
						float *p = (float *)amon_unprotect((void *)arg_ptr);

						libc_fscanf(nstream, spec, p);
					}
					total_scanned++;
					break;
				}
				case 'c':
				{
					// %c -> char*
					char *arg_ptr = va_arg(ap, char *);
					char *p = (char *)amon_unprotect((void *)arg_ptr);

					libc_fscanf(nstream, spec, p);
					total_scanned++;
					break;
				}
				default:
					break;
			 }
		}
		else {
			// It is not a '%', so presumably a literal in the format.
			// We pass it to the real function or skip it.
			// For simplicity, we skip until next '%'.
			fptr++;
		}
	}

	va_end(ap);
	sout();
	return total_scanned;
}
