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
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <glib.h>

#include "createrepo-agent/client.h"
#include "createrepo-agent/common.h"

static assuan_fd_t
create_client_socket(const char * name)
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

  if (assuan_sock_connect(fd, addr, sizeof(addr_un))) {
    assuan_sock_close(fd);
    return ASSUAN_INVALID_FD;
  }

  return fd;
}

gpg_error_t
connect_to_server(assuan_context_t ctx, const char * name)
{
  assuan_fd_t fd;
  gpg_error_t rc;

  fd = create_client_socket(name);
  if (ASSUAN_INVALID_FD == fd) {
    return gpg_err_code_from_errno(errno);
  }

  rc = assuan_socket_connect_fd(ctx, fd, 0);

  assuan_sock_close(fd);

  return rc;
}

gpg_error_t
wait_and_connect_to_server(assuan_context_t ctx, const char * name, int timeout)
{
  gpg_error_t rc;
  int timeout_us = timeout * 1000000;
  int current_us = 0;

  while (0 != (rc = connect_to_server(ctx, name))) {
    current_us += 10000;
    if (current_us >= timeout_us) {
      return gpg_error(GPG_ERR_TIMEOUT);
    }
    usleep(10000);
  }

  return rc;
}

gpg_error_t
start_server(const char * name)
{
  pid_t pid;
  gpg_error_t rc = 0;
  int i;
  int status;

  pid = fork();
  if ((pid_t)(-1) == pid) {
    rc = gpg_err_code_from_errno(errno);
    fprintf(stderr, "failed to fork process: %s\n", gpg_strerror(rc));
  } else if ((pid_t)(0) == pid) {
    execlp("createrepo-agent", "createrepo-agent", name, "--daemon", NULL);
    exit(127);
  }

  while ((pid_t)(-1) == (i = waitpid(pid, &status, 0)) && errno == EINTR) {}
  if (!i) {
    fprintf(stderr, "timeout waiting for server to start\n");
    rc = gpg_error(GPG_ERR_TIMEOUT);
  } else if (!WIFEXITED(status)) {
    fprintf(stderr, "error starting server process\n");
    rc = gpg_error(GPG_ERR_GENERAL);
  } else if (WEXITSTATUS(status)) {
    fprintf(stderr, "server process returned %d\n", WEXITSTATUS(status));
    rc = gpg_error(GPG_ERR_GENERAL);
  }

  return rc;
}

gpg_error_t
connect_and_start_server(assuan_context_t ctx, const char * name)
{
  gpg_error_t rc;
  gchar * sockname;

  sockname = g_strconcat(name, "/", SOCK_NAME, NULL);
  if (!sockname) {
    return gpg_error(GPG_ERR_ENOMEM);
  }

  rc = connect_to_server(ctx, sockname);
  if (!rc) {
    g_free(sockname);
    return rc;
  }

  // TODO(cottsay): Begin lock

  rc = start_server(name);
  if (rc) {
    g_free(sockname);
    return rc;
  }

  // TODO(cottsay): End lock

  rc = wait_and_connect_to_server(ctx, sockname, 5);

  g_free(sockname);

  return rc;
}
