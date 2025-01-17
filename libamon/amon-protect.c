// AddressMonitor detects the following bug types:
// 1. out-of-bound accesses to heap (OOB)
// 2. use-after-free (UAF)
// 3. double free
// memory leaks

#include <malloc.h>
#include <stdint.h>
#include <execinfo.h> // declares backtrace
#include <unistd.h> // defines STDERR_FILENO

#include "amon-protect.h"
#include "amon-log.h"

const uintptr_t taint_mask =   (uintptr_t)0xffff000000000000;
const uintptr_t untaint_mask = (uintptr_t)0x0000ffffffffffff;

static uintptr_t taint = (uintptr_t)0x0001000000000000;

// Start without protecting objects, wait until libamon is fully initialized
bool amon_protect_active = false;

bound *objtbl = NULL;
const size_t max_nb_frames = 30; //farzam: memory 1 MB

// -------------------------------------------------------------------------------------

// Add a unique taint
// TODO: recycle taints of freed objects.
void*
amon_protect(const void *ptr)
{
  void *tainted_ptr = (void *)((uintptr_t)ptr | taint);
  taint += (uintptr_t)0x0001000000000000;
  return tainted_ptr;
}

static void
objtbl_add(void *tainted_ptr, size_t size)
{
  uintptr_t index = (uintptr_t)tainted_ptr >> 48;

  objtbl[index].base = (uintptr_t)tainted_ptr & untaint_mask;
  objtbl[index].size = size;
  objtbl[index].call_stack = (void**)__libc_malloc(max_nb_frames * sizeof(void*));
  objtbl[index].nb_frames = backtrace(objtbl[index].call_stack, max_nb_frames);
  objtbl[index].status = ACTIVE;
}

void
objtbl_update_status(void *tainted_ptr, taint_status status)
{
  uintptr_t index = (uintptr_t)tainted_ptr >> 48;

  objtbl[index].status = status;
}
// -------------------------------------------------------------------------------------

// malloc and return the tainted pointer
void*
amon_malloc_protect(size_t size)
{
  void *result = __libc_malloc(size);
  result = amon_protect(result);
  objtbl_add(result, size);
  return result;
}

void*
amon_realloc_protect(void *ptr, size_t size)
{
  void *result = __libc_realloc(amon_unprotect(ptr), size);

  // Check if realloc was successful
  if(result) {
    if(amon_is_protected(ptr)) objtbl_update_status(ptr, FREED);
    result = amon_protect(result);
    objtbl_add(result, size);
  }

  return result;
}
// -------------------------------------------------------------------------------------








//TODO: 
// 1. verify the taint is valid
// 2. verify ptr contains base address
int
objtbl_size(void *ptr)
{
  uintptr_t taint = (uintptr_t)ptr >> 48;

  if(taint == 0) return -1;
  else return objtbl[taint].size; 
}


// Remove the taint
void*
amon_unprotect(const void *ptr)
{
  return (void *)((uintptr_t)ptr & untaint_mask);
}

// TODO: add more checks
// For now we assume that every non-zero taint is valid
int
amon_is_protected(const void *ptr)
{
  uintptr_t taint = (uintptr_t)ptr >> 48;
  if(taint == 0) return 0;
  else return 1;
}




/* With the base_addr and the size, we can check if the bytes accessed 
are within the allocated bounds for the object. */

enum bug_type {HeapBOF=0, HeapUAF, DoubleFree, MemoryLeak};
char* bug_type_name[] = {"heap-buffer-overflow", "heap-use-after-free", "double-free", "memory-leak"};

void
amon_current_callstack(int first_frame)
{
  int nptrs, i;
  void *buffer[max_nb_frames];
  char **strings;

  nptrs = backtrace(buffer, max_nb_frames);
  strings = backtrace_symbols(buffer, nptrs);
  if(strings != NULL) {
    for(i = first_frame; i < nptrs; i++) {
      amon_fprintf(STDERR_FILENO, 
        "\t#%d %s\n", i - first_frame, strings[i]);
    }
  }

  free(strings);
}

void
amon_callstack(uintptr_t taint)
{
  char **strings;
  int i;

  strings = backtrace_symbols(objtbl[taint].call_stack, objtbl[taint].nb_frames);
  if(strings != NULL) {
    for(i = 0; i < objtbl[taint].nb_frames; i++) {
      amon_fprintf(STDERR_FILENO, 
        "\t#%d %s\n", i, strings[i]);
    }
  }
}

void
amon_report_generic(uintptr_t addr, enum bug_type type)
{
  amon_fprintf(STDERR_FILENO, 
    "=================================================================\n");
  
  amon_fprintf(STDERR_FILENO, 
    "\033[31mERROR: AddressMonitor: %s on address 0x%llx\033[0m\n\n", bug_type_name[type], addr);
}

void
amon_report_oob(uintptr_t taint, uintptr_t base, size_t size, bool is_write)
{
  amon_fprintf(STDERR_FILENO, 
    "\033[36m>> Violating access: %s of size %lu at 0x%llx\033[0m\n", is_write ? "write" : "read", size, base);
  amon_current_callstack(3);
  amon_fprintf(STDERR_FILENO, 
    "\n\033[36m>> Intended object bounds: %lu-byte region [0x%llx,0x%llx)\033[0m\n", objtbl[taint].size, objtbl[taint].base, objtbl[taint].base + objtbl[taint].size);
  amon_callstack(taint);
}

// Check if the access is out-of-bounds with respect to the intended object bounds
void
amon_oob(uintptr_t taint, uintptr_t base, size_t size, bool is_write)
{
  if(base < objtbl[taint].base || base > objtbl[taint].base + objtbl[taint].size - size) {
    // Report oob error
    amon_report_generic(base, HeapBOF);
    amon_report_oob(taint, base, size, is_write);
  }
}

void
amon_report_uaf(uintptr_t taint, uintptr_t base, size_t size, bool is_write)
{
  amon_report_generic(base, HeapUAF);
  amon_fprintf(STDERR_FILENO, 
    "\033[36m>> Violating access: %s of size %lu at 0x%llx\033[0m\n", is_write ? "write" : "read", size, base);
  amon_current_callstack(0);
  amon_fprintf(STDERR_FILENO, 
    "\n\033[36m>> Object has been freed: %lu-byte region [0x%llx,0x%llx)\033[0m\n", objtbl[taint].size, objtbl[taint].base, objtbl[taint].base + objtbl[taint].size);
  amon_callstack(taint);
}

void
amon_access(void *ptr, size_t size, bool is_write)
{
  uintptr_t taint = (uintptr_t)ptr >> 48;
  uintptr_t base = (uintptr_t)ptr & untaint_mask;

  // Return if the accessed pointer is not tainted
  if(taint == 0) return;

  switch (objtbl[taint].status)
  {
  case ACTIVE: 
    amon_oob(taint, base, size, is_write);
    break;
  case FREED:
    amon_report_uaf(taint, base, size, is_write);
    break;
  default: amon_fprintf(STDOUT_FILENO, "inside default!\n"); break;
  }
}

void
amon_write(void *ptr, size_t size)
{
  bool save_active = amon_protect_active;
  amon_protect_active = false;

  amon_access(ptr, size, true);

  amon_protect_active = save_active;
}

void
amon_read(void *ptr, size_t size)
{
  bool save_active = amon_protect_active;
  amon_protect_active = false;

  amon_access(ptr, size, false);

  amon_protect_active = save_active;
}

// Report a double free error
void
amon_report_double_free(uintptr_t addr, uintptr_t taint)
{
  amon_report_generic(addr, DoubleFree);
  amon_current_callstack(0);
  amon_fprintf(STDERR_FILENO, "\n\033[36m>> Previously freed here:\033[0m\n");
  amon_callstack(taint);
}

void
amon_free_protect(void *ptr)
{
  uintptr_t taint = (uintptr_t)ptr >> 48;
  uintptr_t addr = (uintptr_t)ptr & untaint_mask;

  switch (objtbl[taint].status) {
    case ACTIVE:
      __libc_free(amon_unprotect(ptr));
      // Update the object table
      objtbl[taint].status = FREED;
      objtbl[taint].nb_frames = backtrace(objtbl[taint].call_stack, max_nb_frames);
      break;
    case FREED:
      amon_report_double_free(addr, taint);
      break;
    default: break;
  }
}

void*
amon_memalign_protect(size_t alignment, size_t size)
{
  void *result = __libc_memalign(alignment, size);
  result = amon_protect(result);
  objtbl_add(result, size);
  return result;
}

// This would be used with the mprotect method
void
dw_reprotect(const void *ptr)
{
}

void dw_check_access(const void *ptr, size_t size)
{
    if(ptr == NULL) dw_log(WARNING, "Null pointer access\n");
    if(size == 0) dw_log(WARNING, "Zero size access\n");
}

void* amon_retaint(const void *ptr, const void *old_ptr)
{
  return (void *)((uintptr_t)ptr | ((uintptr_t)old_ptr & (uintptr_t)0xffff000000000000));
}
