// Copyright 2022 Open Source Robotics Foundation, Inc.
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
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "createrepo_agent/client.h"
#include "createrepo_agent/command.h"

const char * const sock_name = "/S.createrepo_agent";

const char * const usage =
  "createrepo_agent\n"
  "\n"
  "Usage: %s REPOSITORY_ROOT\n";

static gpg_error_t
try_server(const char * name)
{
  assuan_context_t ctx;
  gpg_error_t rc;

  rc = assuan_new(&ctx);
  if (rc) {
    return rc;
  }

  rc = connect_to_server(ctx, name);

  assuan_release(ctx);

  return rc;
}

static assuan_fd_t
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

void
ignore_sigpipe()
{
  struct sigaction sa;

  sa.sa_handler = SIG_IGN;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGPIPE, &sa, NULL);
}

int
main(int argc, char * argv[])
{
  int fd;
  char * sockpath;
  size_t size;

  if (argc < 2) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }

  size = strlen(argv[1]) + strlen(sock_name) + 1;
  sockpath = malloc(size);
  if (!sockpath) {
    fprintf(stderr, "failed to allocate sock path storage\n");
    return 1;
  }

  snprintf(sockpath, size, "%s%s", argv[1], sock_name);

  gpgrt_check_version(NULL);
  assuan_sock_init();

  fd = create_server_socket(sockpath);
  if (fd == ASSUAN_INVALID_FD && errno == EADDRINUSE) {
    if (try_server(argv[1])) {
      // TODO(cottsay): Better handling of redirected socket
      remove(argv[1]);
      fd = create_server_socket(sockpath);
    } else {
      errno = EADDRINUSE;
    }
  }
  if (fd == ASSUAN_INVALID_FD) {
    fprintf(stderr, "failed to create socket at %s: %s\n", sockpath, strerror(errno));
    free(sockpath);
    return 1;
  }

  free(sockpath);

  // TODO(cottsay): Fork here

  ignore_sigpipe();

  command_handler(fd, argv[1]);

  assuan_sock_close(fd);
  assuan_sock_deinit();

  return 0;
}
