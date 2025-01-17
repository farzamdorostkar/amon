# amon
AMon is a dynamic tool designed to detect temporal and spatial memory access violations in C programs at runtime.

1 - Build the specialized LLVM 17 that comes with the project. It is equipped with AMon's compile-time transformation framework, already registered with the `opt` tool.

    cd llvm-project-17.0.6.src
    mkdir build
    cd build
    cmake -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" -DCMAKE_BUILD_TYPE="Release" -DLLVM_BUILD_EXAMPLES=1 -DCLANG_BUILD_EXAMPLES=1 -G "Unix Makefiles" ../llvm
    make

2 - Build AMon's runtime library.

    cd libamon
    make libamon.so

To test the tool, you can use the test program located in the `libamon` directory. For instance,

    make test_bo_amon

Then run the executable, with `libamon.so` preloaded:

    LD_PRELOAD=./libamon.so ./test_bo_amon

AMon will generate a report similar to the following, indicating the detected buffer overflow:

	            AddressMonitor: INFO: Monitoring execution with AMon in on-the-fly mode
    =================================================================
    ERROR: AddressMonitor: heap-buffer-overflow on address 0x593a57d352a4

    >> Violating access: write of size 4 at 0x593a57d352a4
	    #0 ./test_bo_amon(bar+0x32) [0x593a579591d2]
	    #1 ./test_bo_amon(main+0x36) [0x593a57959226]
	    #2 /lib/x86_64-linux-gnu/libc.so.6(+0x29d90) [0x7a01ef429d90]
	    #3 /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0x80) [0x7a01ef429e40]
	    #4 ./test_bo_amon(_start+0x25) [0x593a57959095]

    >> Intended object bounds: 4-byte region [0x593a57d352a0,0x593a57d352a4)
	    #0 ./libamon.so(+0x39e8) [0x7a01ef7099e8]
	    #1 ./libamon.so(amon_malloc_protect+0x29) [0x7a01ef709a79]
	    #2 ./libamon.so(malloc+0x59) [0x7a01ef70a159]
	    #3 ./test_bo_amon(main+0x20) [0x593a57959210]
	    #4 /lib/x86_64-linux-gnu/libc.so.6(+0x29d90) [0x7a01ef429d90]
	    #5 /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0x80) [0x7a01ef429e40]
	    #6 ./test_bo_amon(_start+0x25) [0x593a57959095]
