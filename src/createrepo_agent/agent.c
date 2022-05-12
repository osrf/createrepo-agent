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

#include <glib.h>

#include "createrepo_agent/agent_options.h"
#include "createrepo_agent/client.h"
#include "createrepo_agent/command.h"
#include "createrepo_agent/common.h"

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
  assuan_fd_t fd;
  gchar * sockpath;
  GError * err = NULL;
  cra_AgentOptions opts = {0};
  pid_t pid;

  GOptionContext * option_ctx = g_option_context_new(NULL);
  g_option_context_set_main_group(option_ctx, cra_get_agent_option_group(&opts));
  if (!g_option_context_parse(option_ctx, &argc, &argv, &err)) {
    fprintf(stderr, "invalid arguments: %s\n", err->message);
    g_error_free(err);
    g_option_context_free(option_ctx);
    return 1;
  }

  sockpath = g_strconcat(opts.path, SOCK_NAME, NULL);
  if (!sockpath) {
    fprintf(stderr, "failed to concatenate repo path\n");
    g_option_context_free(option_ctx);
    return 1;
  }

  gpgrt_check_version(NULL);
  assuan_sock_init();

  if (!opts.daemon && !opts.server) {
    if (try_server(sockpath)) {
      printf("no createrepo-agent running at %s\n", opts.path);
    } else {
      printf("createrepo-agent running and available at %s\n", opts.path);
    }
    assuan_sock_deinit();
    g_free(sockpath);
    g_option_context_free(option_ctx);
    return 0;
  }

  fd = create_server_socket(sockpath);
  if (fd == ASSUAN_INVALID_FD && errno == EADDRINUSE) {
    if (try_server(sockpath)) {
      // TODO(cottsay): Better handling of redirected socket
      remove(sockpath);
      fd = create_server_socket(sockpath);
    } else {
      errno = EADDRINUSE;
    }
  }
  if (fd == ASSUAN_INVALID_FD) {
    fprintf(stderr, "failed to create socket at %s: %s\n", sockpath, strerror(errno));
    assuan_sock_deinit();
    g_free(sockpath);
    g_option_context_free(option_ctx);
    return 1;
  }

  g_free(sockpath);

  if (opts.daemon) {
    fflush(NULL);

    pid = fork();
    if (-1 == pid) {
      fprintf(stderr, "failed to fork daemon process: %s", strerror(errno));
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return 1;
    } else if (pid) {
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return 0;
    }
  }

  ignore_sigpipe();

  command_handler(fd, opts.path);

  assuan_sock_close(fd);
  assuan_sock_deinit();

  g_option_context_free(option_ctx);

  return 0;
}
