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
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <createrepo_c/createrepo_c.h>
#include <glib.h>
#include <gpgme.h>

#include "createrepo-agent/client.h"
#include "createrepo-agent/command.h"
#include "createrepo-agent/common.h"
#include "createrepo-agent/options.h"

static gpg_error_t
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

static gpg_error_t
set_option(assuan_context_t ctx, const char * option_name)
{
  gchar * cmd;
  gpg_error_t rc;

  cmd = g_strjoin(" ", "OPTION", option_name, "1", NULL);
  if (!cmd) {
    return gpg_error(GPG_ERR_ENOMEM);
  }

  rc = assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  g_free(cmd);
  return rc;
}

int
main(int argc, char * argv[])
{
  assuan_fd_t fd;
  assuan_context_t ctx;
  gchar * sockpath;
  GError * err = NULL;
  cra_AgentOptions opts = {0};
  pid_t pid;
  gpg_error_t rc;
  size_t i;
  gchar * cmd;
  gchar * arches = NULL;
  cr_Package * pkg;

  GOptionContext * option_ctx = g_option_context_new(NULL);
  g_option_context_set_main_group(option_ctx, cra_get_option_group(&opts));
  if (!g_option_context_parse(option_ctx, &argc, &argv, &err)) {
    fprintf(stderr, "invalid arguments: %s\n", err->message);
    g_error_free(err);
    g_option_context_free(option_ctx);
    return CRA_EXIT_USAGE;
  }

  if (opts.version) {
    printf("createrepo-agent " CRA_VERSION "\n");
    g_option_context_free(option_ctx);
    return CRA_EXIT_SUCCESS;
  }

  gpgrt_check_version(NULL);
  gpgme_check_version(NULL);
  assuan_sock_init();

  if (opts.import) {
    rc = assuan_new(&ctx);
    if (rc) {
      fprintf(stderr, "client context creation failed: %s\n", gpg_strerror(rc));
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    rc = connect_and_start_server(ctx, opts.path, argv[0]);
    if (rc) {
      fprintf(stderr, "connection to server failed: %s\n", gpg_strerror(rc));
      assuan_release(ctx);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    if (opts.invalidate_family) {
      rc = set_option(ctx, "invalidate_family");
      if (rc) {
        fprintf(stderr, "option set failed for invalidate_family: %s\n", gpg_strerror(rc));
        assuan_release(ctx);
        assuan_sock_deinit();
        g_option_context_free(option_ctx);
        return CRA_EXIT_GENERAL_ERROR;
      }
    }

    if (opts.invalidate_dependants) {
      rc = set_option(ctx, "invalidate_dependants");
      if (rc) {
        fprintf(stderr, "option set failed for invalidate_dependants: %s\n", gpg_strerror(rc));
        assuan_release(ctx);
        assuan_sock_deinit();
        g_option_context_free(option_ctx);
        return CRA_EXIT_GENERAL_ERROR;
      }
    }

    rc = set_option(ctx, "missing_ok");
    if (rc) {
      fprintf(stderr, "option set failed for missing_ok: %s\n", gpg_strerror(rc));
      assuan_release(ctx);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    if (opts.arch && opts.arch[0]) {
      arches = g_strjoinv(" ", opts.arch);
    }

    for (i = 0; opts.import[i]; i++) {
      pkg = cr_package_from_rpm_base(opts.import[i], 0, CR_HDRR_NONE, NULL);
      if (!pkg) {
        fprintf(stderr, "failed to parse header for %s\n", opts.import[i]);
        g_free(arches);
        assuan_release(ctx);
        assuan_sock_deinit();
        g_option_context_free(option_ctx);
        return CRA_EXIT_GENERAL_ERROR;
      }

      cmd = g_strjoin(" ", "REMOVE_NAME", pkg->name, arches, NULL);
      if (!cmd) {
        fprintf(stderr, "failed to concatenate removal command\n");
        g_free(arches);
        assuan_release(ctx);
        assuan_sock_deinit();
        g_option_context_free(option_ctx);
        return CRA_EXIT_GENERAL_ERROR;
      }

      rc = assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
      g_free(cmd);
      if (rc) {
        fprintf(
          stderr, "package remove command failed for %s: %s\n",
          opts.import[i], gpg_strerror(rc));
        g_free(arches);
        assuan_release(ctx);
        assuan_sock_deinit();
        g_option_context_free(option_ctx);
        return CRA_EXIT_GENERAL_ERROR;
      }

      cr_package_free(pkg);
    }

    for (i = 0; opts.import[i]; i++) {
      cmd = g_strjoin(" ", "ADD", opts.import[i], arches, NULL);
      if (!cmd) {
        fprintf(stderr, "failed to concatenate add command\n");
        g_free(arches);
        assuan_release(ctx);
        assuan_sock_deinit();
        g_option_context_free(option_ctx);
        return CRA_EXIT_GENERAL_ERROR;
      }

      rc = assuan_transact(ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
      g_free(cmd);
      if (rc) {
        fprintf(
          stderr, "package add command failed for %s: %s\n",
          opts.import[i], gpg_strerror(rc));
        g_free(arches);
        assuan_release(ctx);
        assuan_sock_deinit();
        g_option_context_free(option_ctx);
        return CRA_EXIT_GENERAL_ERROR;
      }
    }

    g_free(arches);

    rc = assuan_transact(ctx, "COMMIT", NULL, NULL, NULL, NULL, NULL, NULL);
    if (rc) {
      fprintf(
        stderr, "repository commit command failed: %s\n", gpg_strerror(rc));
      assuan_release(ctx);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    assuan_release(ctx);
    assuan_sock_deinit();
    g_option_context_free(option_ctx);
    return CRA_EXIT_SUCCESS;
  }

  sockpath = g_strconcat(opts.path, CRA_SOCK_NAME, NULL);
  if (!sockpath) {
    fprintf(stderr, "failed to concatenate repo path\n");
    assuan_sock_deinit();
    g_option_context_free(option_ctx);
    return CRA_EXIT_GENERAL_ERROR;
  }

  if (!opts.daemon && !opts.server) {
    if (try_server(sockpath)) {
      printf("no createrepo-agent running at %s\n", opts.path);
    } else {
      printf("createrepo-agent running and available at %s\n", opts.path);
    }
    g_free(sockpath);
    assuan_sock_deinit();
    g_option_context_free(option_ctx);
    return CRA_EXIT_SUCCESS;
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
    g_free(sockpath);
    assuan_sock_deinit();
    g_option_context_free(option_ctx);
    return errno == EADDRINUSE ? CRA_EXIT_IN_USE : CRA_EXIT_GENERAL_ERROR;
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
      return CRA_EXIT_GENERAL_ERROR;
    } else if (pid) {
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_SUCCESS;
    }

    if (chdir(opts.path)) {
      fprintf(stderr, "failed to change to repository directory: %s\n", strerror(errno));
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    if (setsid() < 0) {
      fprintf(stderr, "failed to create new session: %s\n", strerror(errno));
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    if (close(STDIN_FILENO) || open("/dev/null", O_RDONLY) != STDIN_FILENO) {
      fprintf(stderr, "failed to reopen STDIN as /dev/null: %s", strerror(errno));
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    if (close(STDOUT_FILENO) || open("/dev/null", O_WRONLY) != STDOUT_FILENO) {
      fprintf(stderr, "failed to reopen STDOUT as /dev/null: %s", strerror(errno));
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }

    if (close(STDERR_FILENO) || open("/dev/null", O_RDWR) != STDERR_FILENO) {
      assuan_sock_close(fd);
      assuan_sock_deinit();
      g_option_context_free(option_ctx);
      return CRA_EXIT_GENERAL_ERROR;
    }
  }

  ignore_sigpipe();

  command_handler(fd, opts.path);

  assuan_sock_deinit();

  g_option_context_free(option_ctx);

  return CRA_EXIT_SUCCESS;
}
