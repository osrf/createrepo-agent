// Copyright 2025 Open Source Robotics Foundation, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <assuan.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "createrepo-agent/command.h"
#include "createrepo-agent/server.h"

gpg_error_t
try_server(const char * name)
{
  assuan_context_t ctx;
  gpg_error_t rc;

  rc = assuan_new(&ctx);
  if (rc) {
    return rc;
  }

  rc = assuan_socket_connect(ctx, name, ASSUAN_INVALID_PID, 0);

  assuan_release(ctx);

  return rc;
}

assuan_fd_t
create_server_socket(const char * name)
{
  struct sockaddr_un addr_un;
  struct sockaddr * addr = (struct sockaddr *)&addr_un;
  assuan_fd_t fd;
  int r_redirected;

  addr_un.sun_family = AF_UNIX;

  if (assuan_sock_set_sockaddr_un(name, addr, &r_redirected)) {
    return ASSUAN_INVALID_FD;
  }

  fd = assuan_sock_new(addr_un.sun_family, SOCK_STREAM, 0);
  if (fd == ASSUAN_INVALID_FD) {
    return ASSUAN_INVALID_FD;
  }

  if (assuan_sock_bind(fd, addr, sizeof(addr_un))) {
    assuan_sock_close(fd);
    return ASSUAN_INVALID_FD;
  }

  if (listen(fd, SOMAXCONN)) {
    assuan_sock_close(fd);
    return ASSUAN_INVALID_FD;
  }

  return fd;
}
