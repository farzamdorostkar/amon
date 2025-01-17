LLVM_AMON=../llvm-project-17.0.6.src/build/bin

# ------------------------- 
# Runtime library (libamon.so)
# -------------------------
libamon.so: amon-protect.c amon-preload.c amon-log.c amon-wrap-glibc.c
	gcc -O2 -c -Wall -fPIC -g amon-protect.c -o amon-protect.o
	gcc -O2 -c -Wall -fPIC -g amon-preload.c -o amon-preload.o
	gcc -O2 -c -Wall -fPIC -g amon-log.c -o amon-log.o
	gcc -O2 -c -Wall -fPIC -g amon-wrap-glibc.c -o amon-wrap-glibc.o
	gcc -O2 -c -Wall -fPIC -g dw-printf.c -o dw-printf.o
	gcc -O2 -shared -g -o libamon.so amon-protect.o amon-preload.o amon-log.o amon-wrap-glibc.o dw-printf.o

# ------------------------- 
# AMon builds of benchmarks
# -------------------------
test_bo_amon: test_bo.c
	$(LLVM_AMON)/clang -O0 -S -emit-llvm -Xclang -disable-O0-optnone -fno-discard-value-names test_bo.c -o test_bo.ll
	$(LLVM_AMON)/opt -passes='amon' -S test_bo.ll -o test_bo_amon.ll
	$(LLVM_AMON)/clang -O0 test_bo_amon.ll -o test_bo_amon -rdynamic -Wl,--unresolved-symbols=ignore-in-object-files

test_df_amon: test_double_free.c
	$(LLVM_AMON)/clang -O0 -S -emit-llvm -Xclang -disable-O0-optnone -fno-discard-value-names test_double_free.c -o test_double_free.ll
	$(LLVM_AMON)/opt -passes='amon' -S test_double_free.ll -o test_double_free_amon.ll
	$(LLVM_AMON)/clang -O0 test_double_free_amon.ll -o test_df_amon -rdynamic -Wl,--unresolved-symbols=ignore-in-object-files

test_uaf_amon: test_uaf.c
	$(LLVM_AMON)/clang -O0 -S -emit-llvm -Xclang -disable-O0-optnone -fno-discard-value-names test_uaf.c -o test_uaf.ll
	$(LLVM_AMON)/opt -passes='amon' -S test_uaf.ll -o test_uaf_amon.ll
	$(LLVM_AMON)/clang -O0 test_uaf_amon.ll -o test_uaf_amon -rdynamic -Wl,--unresolved-symbols=ignore-in-object-files


test_ml_amon: test_ml.c
	$(LLVM_AMON)/clang -g -O0 -S -emit-llvm -Xclang -disable-O0-optnone -fno-discard-value-names test_ml.c -o test_ml.ll
	$(LLVM_AMON)/opt -passes='amon' -S test_ml.ll -o test_ml_amon.ll
	$(LLVM_AMON)/clang -g -O0 test_ml_amon.ll -o test_ml_amon -rdynamic -Wl,--unresolved-symbols=ignore-in-object-files

# ------------------------- 
# ASan builds of benchmarks
# -------------------------
test_ml_asan: test_ml.c
	$(LLVM_AMON)/clang -fsanitize=address -g -o test_ml_asan test_ml.c

test_bo_asan: test_bo.c
	$(LLVM_AMON)/clang -fsanitize=address -g -o test_bo_asan test_bo.c


test_asan: test.c
	$(LLVM_AMON)/clang -O0 -g -fsanitize=address test.c -o test_asan

test_native: test.c
	$(LLVM_AMON)/clang -O0 -g test.c -o test_native

clean:
	rm -f *.o *.ll libamon.so test_amon test_asan test_native test_bo_amon test_df_amon test_uaf_amon test_ml_amon test_ml_asan test_bo_asan

.PHONY: clean
