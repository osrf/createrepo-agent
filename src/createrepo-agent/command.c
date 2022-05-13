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
#include <createrepo_c/createrepo_c.h>
#include <string.h>

#include "createrepo-agent/command.h"
#include "createrepo-cache/coordinator.h"

struct command_context
{
  cra_Stage * stage;
  assuan_fd_t listen_fd;
};

static const char * const greeting = "Greetings from creatrepo_c_agent";

static const char * const hlp_add =
  "ADD PACKAGE_PATH [ARCH ...]\n\nAdd an RPM package to the repository cluster";
gpg_error_t
cmd_add(assuan_context_t ctx, char * line)
{
  struct command_context * cmd_ctx;
  char * arch;
  char * pkg_path;
  cr_Package * package;
  int rc;
  const char * name;
  gchar * base;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return gpg_error(GPG_ERR_GENERAL);
  }

  do {
    pkg_path = line;
    while (*line && *line != ' ') {
      line++;
    }
  } while (*line && line - pkg_path < 2);

  if (line - pkg_path < 2) {
    return gpg_error(GPG_ERR_GENERAL);
  }

  name = cr_get_filename(pkg_path);
  base = g_strndup(pkg_path, (gsize)(name - pkg_path));
  package = cr_package_from_rpm(pkg_path, CR_CHECKSUM_SHA256, name, base, -1, NULL, 0, NULL);
  g_free(base);
  if (!package) {
    return gpg_error(GPG_ERR_GENERAL);
  }

  if (!*line) {
    rc = cra_stage_package_add(cmd_ctx->stage, NULL, package);
    if (rc) {
      cr_package_free(package);
      return gpg_error(GPG_ERR_GENERAL);
    }

    return 0;
  }

  *line = '\0';
  line++;

  while (*line) {
    arch = line;

    while (*line && *line != ' ') {
      line++;
    }
    if (*line) {
      *line = '\0';
      line++;
    }

    if (line - arch > 1) {
      rc = cra_stage_package_add(cmd_ctx->stage, arch, cr_package_copy(package));
      if (rc) {
        cr_package_free(package);
        return gpg_error(GPG_ERR_GENERAL);
      }
    }
  }

  cr_package_free(package);

  return 0;
}

static const char * const hlp_commit = "COMMIT\n\nCommit changes to all cached repository metadata";
gpg_error_t
cmd_commit(assuan_context_t ctx, char * line)
{
  (void)line;

  struct command_context * cmd_ctx;
  int rc;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return gpg_error(GPG_ERR_GENERAL);
  }

  rc = cra_stage_commit(cmd_ctx->stage);
  if (rc) {
    return gpg_error(GPG_ERR_GENERAL);
  }

  return 0;
}

static const char * const hlp_shutdown = "SHUTDOWN\n\nShut down the agent process";
gpg_error_t
cmd_shutdown(assuan_context_t ctx, char * line)
{
  (void)line;

  struct command_context * cmd_ctx;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return gpg_error(GPG_ERR_GENERAL);
  }

  assuan_sock_close(cmd_ctx->listen_fd);
  assuan_set_flag(ctx, ASSUAN_FORCE_CLOSE, 1);

  return 0;
}

static const struct
{
  const char * const name;
  const assuan_handler_t handler;
  const char * const help;
} command_table[] = {
  {"ADD", cmd_add, hlp_add},
  {"COMMIT", cmd_commit, hlp_commit},
  {"SHUTDOWN", cmd_shutdown, hlp_shutdown},
  {NULL},
};

static gpg_error_t
register_commands(assuan_context_t ctx)
{
  int i;
  gpg_error_t rc;

  for (i = 0; command_table[i].name; i++) {
    rc = assuan_register_command(
      ctx,
      command_table[i].name,
      command_table[i].handler,
      command_table[i].help);
    if (rc) {
      return rc;
    }
  }

  rc = assuan_set_hello_line(ctx, greeting);
  if (rc) {
    return rc;
  }

  return 0;
}

void
command_handler(int fd, const char * path)
{
  gpg_error_t rc;
  assuan_context_t ctx;
  struct command_context cmd_ctx = {0};
  cra_Coordinator * coordinator;

  rc = assuan_new(&ctx);
  if (rc) {
    fprintf(stderr, "server context creation failed: %s\n", gpg_strerror(rc));
    return;
  }

  assuan_set_pointer(ctx, &cmd_ctx);

  coordinator = cra_coordinator_new(path);
  if (!coordinator) {
    rc = CRE_MEMORY;
    fprintf(stderr, "coordinator init failed\n");
    goto release;
  }

  rc = assuan_init_socket_server(ctx, fd, 0);
  if (rc) {
    fprintf(stderr, "server init failed: %s\n", gpg_strerror(rc));
    goto release;
  }

  rc = register_commands(ctx);
  if (rc) {
    fprintf(stderr, "register failed: %s\n", gpg_strerror(rc));
    goto release;
  }

  cmd_ctx.listen_fd = fd;
  cmd_ctx.stage = cra_stage_new(coordinator);
  if (!cmd_ctx.stage) {
    fprintf(stderr, "stage init failed\n");
    goto release;
  }

  for (;; ) {
    rc = assuan_accept(ctx);
    if (GPG_ERR_EOF == rc) {
      break;
    } else if (rc) {
      fprintf(stderr, "accept problem: %s\n", gpg_strerror(rc));
      goto release;
    }

    rc = assuan_process(ctx);
    if (rc) {
      fprintf(stderr, "processing failed: %s\n", gpg_strerror(rc));
      continue;
    }
  }

  printf("Shutting down...\n");

release:
  cra_stage_free(cmd_ctx.stage);
  cra_coordinator_free(coordinator);
  assuan_release(ctx);
}
