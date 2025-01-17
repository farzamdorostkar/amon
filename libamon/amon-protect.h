#ifndef AMON_PROTECT_H
#define AMON_PROTECT_H

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

typedef enum {UNDEFINED=0, ACTIVE=1, FREED=2} taint_status;

// Bounds information
typedef struct {
  uintptr_t base;
  size_t size;
  void **call_stack;
  int nb_frames;
  taint_status status;
} bound;

// Pointer to object table
extern bound *objtbl;

extern size_t nb_taints;



int objtbl_size(void *ptr);



// We are within the libamon internals, do not protect heap objects
// This variable should be thread local sotrage for multi-threading
extern bool amon_protect_active;

void objtbl_update_status(void *tainted_ptr, taint_status status);

//void* amon_retaint(const void *ptr, const void *old_ptr);

// Put back the taint on the modified (incremented) pointer
void* amon_retaint(const void *ptr, const void *old_ptr);






void* amon_unprotect(const void *ptr);

int amon_is_protected(const void *ptr);


// Alloc a protected object
void* amon_malloc_protect(size_t size);

// Realloc a protected object
void* amon_realloc_protect(void *ptr, size_t size);

// Free a protected object.
void amon_free_protect(void *ptr);

// // Memalign a protected object.
void* amon_memalign_protect(size_t alignment, size_t size);

void amon_callstack(uintptr_t taint);

extern void *__libc_malloc(size_t size);
extern void __libc_free(void *ptr);
extern void *__libc_calloc(size_t nmemb, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_memalign(size_t alignment, size_t size);


void dw_reprotect(const void *ptr);
void dw_check_access(const void *ptr, size_t size);

#endif // AMON_PROTECT_H

//extern int nb_taint_bits;