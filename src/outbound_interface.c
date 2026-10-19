#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "outbound_interface.h"

int outbound_interface_bind_socket(int socket_fd, const char *interface_name) {
  if (interface_name == NULL || interface_name[0] == '\0') {
    errno = EINVAL;
    return -1;
  }
  const size_t interface_length = strlen(interface_name);
  if (interface_length >= IFNAMSIZ) {
    errno = ENAMETOOLONG;
    return -1;
  }

#if defined(__linux__) || defined(OUTBOUND_INTERFACE_TEST)
  return setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
                    interface_name, (socklen_t)(interface_length + 1));
#else
  (void)socket_fd;
  errno = ENOTSUP;
  return -1;
#endif
}

int outbound_interface_validate(const char *interface_name) {
  int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    return -1;
  }

  const int result = outbound_interface_bind_socket(socket_fd, interface_name);
  const int saved_errno = errno;
  (void)close(socket_fd);
  errno = saved_errno;
  return result;
}
