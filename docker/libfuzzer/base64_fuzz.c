#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h> 

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FILE *dev_null_fd = fopen("/dev/shm/null", "wb+");
  FILE *stream = fmemopen(data, size, "rb");
  do_decode (stream, dev_null_fd, false);
  if(stream != NULL)
    fclose (stream);
  if(dev_null_fd != NULL)
    fclose(dev_null_fd);
  return 0;
}