#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* Stub for memory-mapped file access */
CAMLprim value ocaml_crypto_linter_mmap(value v_filename, value v_offset, value v_length) {
    CAMLparam3(v_filename, v_offset, v_length);
    CAMLlocal1(result);
    
    const char* filename = String_val(v_filename);
    int offset = Int_val(v_offset);
    int length = Int_val(v_length);
    
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        caml_failwith("Cannot open file for mmap");
    }
    
    void* mapped = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);
    close(fd);
    
    if (mapped == MAP_FAILED) {
        caml_failwith("mmap failed");
    }
    
    result = caml_alloc_string(length);
    memcpy(Bytes_val(result), mapped, length);
    munmap(mapped, length);
    
    CAMLreturn(result);
}