#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h> 
#include <unistd.h>

static char *buf_to_file(const char *buf, size_t size) {
  char *name = strdup("/dev/shm/fuzz-XXXXXX");
  int fd = mkstemp(name);
  if (fd < 0) {
    perror("open");
    exit(1);
  }
  size_t pos = 0;
  while (pos < size) {
    int nbytes = write(fd, &buf[pos], size - pos);
    if (nbytes <= 0) {
      perror("write");
      exit(1);
    }
    pos += nbytes;
  }
  if (close(fd) != 0) {
    perror("close");
    exit(1);
  }
  return name;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *file_name = buf_to_file((const char *)data, size);
  who(file_name, 0);
  unlink(file_name);
  free(file_name);
  return 0;
}
