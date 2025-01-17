#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h> // defines ULONG_MAX
#include <unistd.h> // defines STDERR_FILENO

#include "amon-protect.h"
#include "amon-log.h"

size_t nb_taints;

// Since this library is activated by LD_PRELOAD, we cannot use the main function argv
// to receive arguments. We use environment variables instead.

// Analysis mode, by default set to on-the-fly
static bool amon_otf = true;

// Number of bits dedicated to taint
static size_t nb_taint_bits = 16;

// Range of object sizes to protect, by default protect all
static size_t 
  min_protect_size = 0,
  max_protect_size = ULONG_MAX;

// This is the initialisation function called at preload time
extern void __attribute__((constructor(65535)))
amon_init()
{
  // Set the analysis mode
  char *arg = getenv("AMON_OTF");
  if(arg != NULL) amon_otf = atol(arg) != 0;
  
  // Set the number of taint bits in pm mode, by default 10
  if(!amon_otf) nb_taint_bits = 10;
  arg = getenv("AMON_NB_TAINT_BITS");
  if(arg != NULL) {
    if(amon_otf) dw_log(INFO, "AMON_NB_TAINT_BITS ignored in on-the-fly mode\n");
    else if(atol(arg) < 1 || atol(arg) > 13) dw_log(INFO, "Invalid AMON_NB_TAINT_BITS. Using default value (10)\n");
    else nb_taint_bits = atol(arg);
  }

  // Set the min and max protect sizes
  arg = getenv("AMON_MIN_PROTECT_SIZE");
  if(arg != NULL) min_protect_size = atol(arg);
  arg = getenv("AMON_MAX_PROTECT_SIZE");
  if(arg != NULL) max_protect_size = atol(arg);

  // Allocate memory for the object table
  nb_taints = ((size_t)1 << nb_taint_bits) - 1;
  objtbl = (bound*) __libc_malloc(nb_taints * sizeof(bound));
  
  // Start intercepting allocation functions
  if(objtbl) {
    amon_protect_active = true;
    dw_log(INFO, "Monitoring execution with AMon in %s mode\n", amon_otf ? "on-the-fly" : "post-mortem");
  }
  else dw_log(ERROR, "Failed to allocate memory for the object table.\n");
}

extern void __attribute__((destructor))
amon_fini()
{
  for(int index=1; index < nb_taints; ++index) {
    if(objtbl[index].status== ACTIVE) {
      amon_fprintf(STDERR_FILENO, 
      "=================================================================\n");
      amon_fprintf(STDERR_FILENO, 
      "\033[31mERROR: AddressMonitor: %s on address 0x%llx\033[0m\n\n", "memory-leak", objtbl[index].base);
      amon_fprintf(STDERR_FILENO, 
      "Allocated by\n");
      amon_callstack(index);
    }
  }
  __libc_free(objtbl);
  amon_protect_active = false;
}

// Filter the objects to be tainted according to size range.
// TODO: Also filter the objects according to rank in the allocation sequence.

static bool
check_candidate(size_t size)
{
  if(size >= min_protect_size && size <= max_protect_size) return true;
  return false;
}

// For now we will not taint objects allocated from libraries,
// and we assume that this starts at that address. We should
// read /proc/self/maps and let the user specify which libraries to
// exclude from tainting allocations.

static void *library_start = (void *)0x700000000000;

static bool
check_caller(void *caller)
{
  return caller < library_start;
}

// Common malloc that checks if the object should be tainted

static void*
malloc2(size_t size, void *caller)
{
  void *ret = NULL;
  bool save_active = amon_protect_active;
  amon_protect_active = false;

  if(save_active) {
    if(check_caller(caller)) {
      if(check_candidate(size)) {
        ret = amon_malloc_protect(size);
        amon_protect_active = save_active;
        return ret;
      }
    }
  }

  ret = __libc_malloc(size);

  amon_protect_active = save_active;
  return ret;
}

// Normal malloc, note the caller and call the common malloc

void*
malloc(size_t size)
{
  return malloc2(size, __builtin_return_address(0));
}

static void*
realloc2(void *ptr, size_t size, void *caller)
{
  void *ret = NULL;
  bool save_active = amon_protect_active;
  amon_protect_active = false;

  if(save_active) {
    if(check_caller(caller)) {
      if(check_candidate(size)) {
        ret = amon_realloc_protect(ptr, size);
        amon_protect_active = save_active;   
        return ret;
      }
    }
  }

  ret = __libc_realloc(ptr, size);

  // Check if realloc was successful
  if(ret) {
    if(amon_is_protected(ptr)) objtbl_update_status(ptr, FREED);
  }

  amon_protect_active = save_active;
  return ret;
}

void*
realloc(void *ptr, size_t size)
{
  return realloc2(ptr, size, __builtin_return_address(0));
}

void
free(void *ptr)
{
  bool save_active = amon_protect_active;
  amon_protect_active = false;

  if(amon_is_protected(ptr)) amon_free_protect(ptr);
  else __libc_free(ptr);

  amon_protect_active = save_active;
}

void*
memalign(size_t alignment, size_t size)
{
  void *ret;
  bool save_active = amon_protect_active;
  amon_protect_active = false;

  if(save_active && check_candidate(size)) ret = amon_memalign_protect(alignment, size);
  else ret = __libc_memalign(alignment, size);

  amon_protect_active = save_active;
  return ret;
}

void*
calloc(size_t nmemb, size_t size)
{
  void *ret = malloc2(nmemb * size, __builtin_return_address(0));
  bzero(ret, nmemb * size);
  //dw_log(INFO, "calloc ptr: %p\n", ret);
  return ret;
}

// AMon can also replace realloc with free and malloc.
/*void*
realloc(void *ptr, size_t size)
{
  void *ret = malloc(size);
  int old_size;

  dw_log(INFO, "\t\trealloc of size %zu\n", size);

  if(amon_is_protected(ptr)) old_size = objtbl_size(ptr); //TODO: redundant check inside objtbl_size()
  else {
    // The object was not protected, its size is unknown
    ptr = __libc_realloc(ptr, size);
    old_size = size;
  }

  // Copy from the old object to the new
  memcpy(ret, ptr, old_size < size ? old_size : size);
  free(ptr);
  return ret;
}*/