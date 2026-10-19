#ifndef _OUTBOUND_INTERFACE_H_
#define _OUTBOUND_INTERFACE_H_

int outbound_interface_bind_socket(int socket_fd, const char *interface_name);
int outbound_interface_validate(const char *interface_name);

#endif
