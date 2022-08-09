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
#include <errno.h>
#include <string.h>

#include "createrepo-agent/command.h"
#include "createrepo-agent/common.h"
#include "createrepo-cache/coordinator.h"

#define cmd_error(ctx, err, msg) \
  assuan_process_done(ctx, assuan_set_error(ctx, gpg_error(err), msg))
#define cmd_ok(ctx) assuan_process_done(ctx, 0)

struct command_context
{
  cra_Stage * stage;
  assuan_fd_t listen_fd;
  gboolean invalidate_family;
  gboolean invalidate_dependants;
  gboolean missing_ok;
  GError * err;
  gint * sentinel;
};

static const char * const greeting = "Greetings from creatrepo-agent " CRA_VERSION;

#define HLP_ADD "ADD PACKAGE_PATH [ARCH ...]\n\nAdd an RPM package to the repository cluster"
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
    return cmd_error(ctx, GPG_ERR_ASSUAN_SERVER_FAULT, NULL);
  }

  pkg_path = line;
  while (*line && *line != ' ' && *line != '\t') {
    line++;
  }

  if (pkg_path == line) {
    return cmd_error(ctx, GPG_ERR_MISSING_VALUE, "missing PACKAGE_PATH argument");
  }

  if (*line) {
    *line = '\0';
    line++;
  }

  name = cr_get_filename(pkg_path);
  base = g_strndup(pkg_path, (gsize)(name - pkg_path));
  package = cr_package_from_rpm(
    pkg_path, CR_CHECKSUM_SHA256, name, base, -1, NULL, 0, &cmd_ctx->err);
  g_free(base);
  if (!package) {
    if (cmd_ctx->err && cmd_ctx->err->message) {
      return cmd_error(ctx, GPG_ERR_GENERAL, cmd_ctx->err->message);
    }
    return cmd_error(ctx, GPG_ERR_GENERAL, "failed to parse RPM package");
  }

  while (*line == ' ' || *line == '\t') {
    line++;
  }

  if (!*line) {
    rc = cra_stage_package_add(cmd_ctx->stage, NULL, package);
    if (rc) {
      cr_package_free(package);
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    return cmd_ok(ctx);
  }

  while (*line) {
    arch = line;
    while (*line && *line != ' ' && *line != '\t') {
      line++;
    }
    if (*line) {
      *line = '\0';
      line++;
    }

    rc = cra_stage_package_add(cmd_ctx->stage, arch, cr_package_copy(package));
    if (rc) {
      cr_package_free(package);
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    while (*line == ' ' || *line == '\t') {
      line++;
    }
  }

  cr_package_free(package);

  return cmd_ok(ctx);
}

#define HLP_COMMIT "COMMIT\n\nCommit changes to all cached repository metadata"
gpg_error_t
cmd_commit(assuan_context_t ctx, char * line)
{
  (void)line;

  struct command_context * cmd_ctx;
  int rc;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return cmd_error(ctx, GPG_ERR_ASSUAN_SERVER_FAULT, NULL);
  }

  rc = cra_stage_commit(cmd_ctx->stage);
  if (rc) {
    return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
  }

  return cmd_ok(ctx);
}

#define HLP_REMOVE_NAME "REMOVE_NAME NAME [ARCH ...]\n\nRemove RPM packages with a given name"
gpg_error_t
cmd_remove_name(assuan_context_t ctx, char * line)
{
  struct command_context * cmd_ctx;
  char * arch;
  char * name;
  int rc;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return cmd_error(ctx, GPG_ERR_ASSUAN_SERVER_FAULT, NULL);
  }

  name = line;
  while (*line && *line != ' ' && *line != '\t') {
    line++;
  }

  if (name == line) {
    return cmd_error(ctx, GPG_ERR_MISSING_VALUE, "missing NAME argument");
  }

  if (*line) {
    *line = '\0';
    line++;
  }

  while (*line == ' ' || *line == '\t') {
    line++;
  }

  if (!*line) {
    rc = cra_stage_name_remove(
      cmd_ctx->stage, NULL, name,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants, cmd_ctx->missing_ok);
    if (rc) {
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    return cmd_ok(ctx);
  }

  while (*line) {
    arch = line;
    while (*line && *line != ' ' && *line != '\t') {
      line++;
    }
    if (*line) {
      *line = '\0';
      line++;
    }

    rc = cra_stage_name_remove(
      cmd_ctx->stage, arch, name,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants, cmd_ctx->missing_ok);
    if (rc) {
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    while (*line == ' ' || *line == '\t') {
      line++;
    }
  }

  return cmd_ok(ctx);
}

#define HLP_REMOVE_PATTERN \
  "REMOVE_PATTERN REGEX [ARCH ...]\n\nRemove RPM packages which match a regular expression"
gpg_error_t
cmd_remove_pattern(assuan_context_t ctx, char * line)
{
  struct command_context * cmd_ctx;
  char * arch;
  char * raw_pattern;
  GRegex * pattern;
  int rc;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return cmd_error(ctx, GPG_ERR_ASSUAN_SERVER_FAULT, NULL);
  }

  raw_pattern = line;
  while (*line && *line != ' ' && *line != '\t') {
    line++;
  }

  if (raw_pattern == line) {
    return cmd_error(ctx, GPG_ERR_MISSING_VALUE, "missing REGEX argument");
  }

  if (*line) {
    *line = '\0';
    line++;
  }

  pattern = g_regex_new(
    raw_pattern, G_REGEX_ANCHORED | G_REGEX_OPTIMIZE, G_REGEX_MATCH_ANCHORED, &cmd_ctx->err);
  if (!pattern) {
    if (cmd_ctx->err && cmd_ctx->err->message) {
      return cmd_error(ctx, GPG_ERR_ASS_PARAMETER, cmd_ctx->err->message);
    }
    return cmd_error(ctx, GPG_ERR_ASS_PARAMETER, "invalid regular expression");
  }

  while (*line == ' ' || *line == '\t') {
    line++;
  }

  if (!*line) {
    rc = cra_stage_pattern_remove(
      cmd_ctx->stage, NULL, pattern,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants, cmd_ctx->missing_ok);
    if (rc) {
      g_regex_unref(pattern);
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    g_regex_unref(pattern);

    return cmd_ok(ctx);
  }

  while (*line) {
    arch = line;
    while (*line && *line != ' ' && *line != '\t') {
      line++;
    }
    if (*line) {
      *line = '\0';
      line++;
    }

    rc = cra_stage_pattern_remove(
      cmd_ctx->stage, arch, pattern,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants, cmd_ctx->missing_ok);
    if (rc) {
      g_regex_unref(pattern);
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    while (*line == ' ' || *line == '\t') {
      line++;
    }
  }

  g_regex_unref(pattern);

  return cmd_ok(ctx);
}

#define HLP_SHUTDOWN "SHUTDOWN\n\nShut down the agent process"
gpg_error_t
cmd_shutdown(assuan_context_t ctx, char * line)
{
  (void)line;

  struct command_context * cmd_ctx;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return cmd_error(ctx, GPG_ERR_ASSUAN_SERVER_FAULT, NULL);
  }

  g_atomic_int_set(cmd_ctx->sentinel, 1);
  shutdown(cmd_ctx->listen_fd, SHUT_RD);
  assuan_set_flag(ctx, ASSUAN_FORCE_CLOSE, 1);

  return cmd_ok(ctx);
}

static int
do_sync(
  cra_Stage * stage, const char * base_url, const char * arch_name, GRegex * pattern,
  gboolean invalidate_family, gboolean invalidate_dependants)
{
  cr_Metadata * md;
  cr_Metadata * md_debug = NULL;
  cr_Package * package;
  GHashTable * packages;
  GHashTable * packages_debug = NULL;
  GHashTable * packages_source;
  GHashTableIter iter;
  GString * url;
  GError * err = NULL;
  int rc;

  md = cr_metadata_new(CR_HT_KEY_FILENAME, 0, NULL);
  if (!md) {
    return CRE_MEMORY;
  }

  url = g_string_new(base_url);
  if (!url) {
    cr_metadata_free(md);
    return CRE_MEMORY;
  }
  if (url->len && url->str[url->len - 1] != '/') {
    g_string_append(url, "/");
  }

  if (!g_string_replace(url, "$basearch", arch_name ? arch_name : "SRPMS", 0)) {
    g_string_append(url, arch_name ? arch_name : "SRPMS");
    g_string_append(url, "/");
  }

  rc = cr_metadata_locate_and_load_xml(md, url->str, NULL);
  if (rc) {
    g_string_free(url, TRUE);
    cr_metadata_free(md);
    return rc;
  }

  packages = cr_metadata_hashtable(md);

  if (pattern) {
    g_hash_table_iter_init(&iter, packages);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
      if (!g_regex_match(pattern, package->name, 0, NULL)) {
        g_hash_table_iter_remove(&iter);
      }
    }
  }

  if (!g_hash_table_size(packages)) {
    g_string_free(url, TRUE);
    cr_metadata_free(md);
    return CRE_OK;
  }

  g_hash_table_iter_init(&iter, packages);
  while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
    package->location_base = g_string_chunk_insert(package->chunk, url->str);
  }

  // Look for a debug sub-repository
  if (arch_name && g_strcmp0(arch_name, "SRPMS")) {
    g_string_append(url, "debug/");

    md_debug = cr_metadata_new(CR_HT_KEY_FILENAME, 0, NULL);
    if (!md_debug) {
      g_string_free(url, TRUE);
      cr_metadata_free(md);
      return CRE_MEMORY;
    }

    rc = cr_metadata_locate_and_load_xml(md_debug, url->str, &err);
    if (rc) {
      if (!g_str_has_prefix(err->message, "Metadata not found at ")) {
        cr_metadata_free(md_debug);
        g_string_free(url, TRUE);
        cr_metadata_free(md);
        return rc;
      }
      g_info("Continuing sync despite missing debu sub-repository at %s", url->str);
    } else {
      // Enumerate the set of source package names from the arch repo
      packages_source = g_hash_table_new(g_str_hash, g_str_equal);
      if (!packages_source) {
        cr_metadata_free(md_debug);
        g_string_free(url, TRUE);
        cr_metadata_free(md);
        return CRE_MEMORY;
      }

      g_hash_table_iter_init(&iter, packages);
      while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
        if (package->rpm_sourcerpm && package->rpm_sourcerpm[0]) {
          g_hash_table_add(packages_source, package->rpm_sourcerpm);
        }
      }

      packages_debug = cr_metadata_hashtable(md_debug);

      g_hash_table_iter_init(&iter, packages_debug);
      while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
        if (!package->rpm_sourcerpm ||
          !package->rpm_sourcerpm[0] ||
          !g_hash_table_contains(packages_source, package->rpm_sourcerpm))
        {
          g_hash_table_iter_remove(&iter);
        }
      }

      g_hash_table_unref(packages_source);

      if (g_hash_table_size(packages_debug)) {
        g_hash_table_iter_init(&iter, packages_debug);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
          package->location_base = g_string_chunk_insert(package->chunk, url->str);
        }
      } else {
        packages_debug = NULL;
      }
    }
  }

  g_string_free(url, TRUE);

  if (pattern) {
    rc = cra_stage_pattern_remove(
      stage, arch_name, pattern,
      invalidate_family, invalidate_dependants, TRUE);
    if (rc) {
      cr_metadata_free(md_debug);
      cr_metadata_free(md);
      return rc;
    }
  } else {
    g_hash_table_iter_init(&iter, packages);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
      rc = cra_stage_name_remove(
        stage, arch_name, package->name,
        invalidate_family, invalidate_dependants, TRUE);
      if (rc) {
        cr_metadata_free(md_debug);
        cr_metadata_free(md);
        return rc;
      }
    }
  }

  rc = cra_stage_packages_add(stage, arch_name, packages);
  cr_metadata_free(md);

  if (!rc && packages_debug) {
    g_hash_table_iter_init(&iter, packages_debug);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
      rc = cra_stage_name_remove(
        stage, arch_name, package->name,
        FALSE, FALSE, TRUE);
      if (rc) {
        cr_metadata_free(md_debug);
        return rc;
      }
    }
    rc = cra_stage_packages_add(stage, arch_name, packages_debug);
  }
  cr_metadata_free(md_debug);

  return rc;
}

#define HLP_SYNC \
  "SYNC BASE_URL [ARCH ...]\n\nAdd RPM packages from another repository"
gpg_error_t
cmd_sync(assuan_context_t ctx, char * line)
{
  struct command_context * cmd_ctx;
  char * arch;
  char * base_url;
  int rc;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return cmd_error(ctx, GPG_ERR_ASSUAN_SERVER_FAULT, NULL);
  }

  base_url = line;
  while (*line && *line != ' ' && *line != '\t') {
    line++;
  }

  if (base_url == line) {
    return cmd_error(ctx, GPG_ERR_MISSING_VALUE, "missing BASE_URL argument");
  }

  if (*line) {
    *line = '\0';
    line++;
  }

  while (*line == ' ' || *line == '\t') {
    line++;
  }

  if (!*line) {
    rc = do_sync(
      cmd_ctx->stage, base_url, NULL, NULL,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants);
    if (rc) {
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    return cmd_ok(ctx);
  }

  while (*line) {
    arch = line;
    while (*line && *line != ' ' && *line != '\t') {
      line++;
    }
    if (*line) {
      *line = '\0';
      line++;
    }

    rc = do_sync(
      cmd_ctx->stage, base_url, arch, NULL,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants);
    if (rc) {
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    while (*line == ' ' || *line == '\t') {
      line++;
    }
  }

  return cmd_ok(ctx);
}

#define HLP_SYNC_PATTERN \
  "SYNC BASE_URL PATTERN [ARCH ...]\n\nAdd matching RPM packages from another repository"
gpg_error_t
cmd_sync_pattern(assuan_context_t ctx, char * line)
{
  struct command_context * cmd_ctx;
  char * arch;
  char * base_url;
  char * raw_pattern;
  GRegex * pattern;
  int rc;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return cmd_error(ctx, GPG_ERR_ASSUAN_SERVER_FAULT, NULL);
  }

  base_url = line;
  while (*line && *line != ' ' && *line != '\t') {
    line++;
  }

  if (base_url == line) {
    return cmd_error(ctx, GPG_ERR_MISSING_VALUE, "missing BASE_URL argument");
  }

  if (*line) {
    *line = '\0';
    line++;
  }

  raw_pattern = line;
  while (*line && *line != ' ' && *line != '\t') {
    line++;
  }

  if (raw_pattern == line) {
    return cmd_error(ctx, GPG_ERR_MISSING_VALUE, "missing PATTERN argument");
  }

  if (*line) {
    *line = '\0';
    line++;
  }

  pattern = g_regex_new(
    raw_pattern, G_REGEX_ANCHORED | G_REGEX_OPTIMIZE, G_REGEX_MATCH_ANCHORED, &cmd_ctx->err);
  if (!pattern) {
    if (cmd_ctx->err && cmd_ctx->err->message) {
      return cmd_error(ctx, GPG_ERR_ASS_PARAMETER, cmd_ctx->err->message);
    }
    return cmd_error(ctx, GPG_ERR_ASS_PARAMETER, "invalid regular expression");
  }

  while (*line == ' ' || *line == '\t') {
    line++;
  }

  if (!*line) {
    rc = do_sync(
      cmd_ctx->stage, base_url, NULL, pattern,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants);
    if (rc) {
      g_regex_unref(pattern);
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    g_regex_unref(pattern);
    return cmd_ok(ctx);
  }

  while (*line) {
    arch = line;
    while (*line && *line != ' ' && *line != '\t') {
      line++;
    }
    if (*line) {
      *line = '\0';
      line++;
    }

    rc = do_sync(
      cmd_ctx->stage, base_url, arch, pattern,
      cmd_ctx->invalidate_family, cmd_ctx->invalidate_dependants);
    if (rc) {
      g_regex_unref(pattern);
      return cmd_error(ctx, GPG_ERR_GENERAL, cr_strerror(rc));
    }

    while (*line == ' ' || *line == '\t') {
      line++;
    }
  }

  g_regex_unref(pattern);

  return cmd_ok(ctx);
}

static const struct
{
  const char * const name;
  const assuan_handler_t handler;
  const char * const help;
} command_table[] = {
  {"ADD", cmd_add, HLP_ADD},
  {"COMMIT", cmd_commit, HLP_COMMIT},
  {"REMOVE_NAME", cmd_remove_name, HLP_REMOVE_NAME},
  {"REMOVE_PATTERN", cmd_remove_pattern, HLP_REMOVE_PATTERN},
  {"SHUTDOWN", cmd_shutdown, HLP_SHUTDOWN},
  {"SYNC", cmd_sync, HLP_SYNC},
  {"SYNC_PATTERN", cmd_sync_pattern, HLP_SYNC_PATTERN},
  {NULL},
};

static gpg_error_t
option_handler(assuan_context_t ctx, const char * name, const char * value)
{
  struct command_context * cmd_ctx;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (!cmd_ctx) {
    return gpg_error(GPG_ERR_ASSUAN_SERVER_FAULT);
  }

  if (g_str_equal(name, "invalidate_family")) {
    cmd_ctx->invalidate_family = *value ? !!atoi(value) : 1;
  } else if (g_str_equal(name, "invalidate_dependants")) {
    cmd_ctx->invalidate_dependants = *value ? !!atoi(value) : 1;
  } else if (g_str_equal(name, "missing_ok")) {
    cmd_ctx->missing_ok = *value ? !!atoi(value) : 1;
  } else {
    return gpg_error(GPG_ERR_UNKNOWN_OPTION);
  }

  return 0;
}

static void
post_cmd_notify(assuan_context_t ctx, gpg_error_t err)
{
  (void)err;

  struct command_context * cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);

  if (cmd_ctx && cmd_ctx->err) {
    assuan_set_error(ctx, 0, NULL);
    g_error_free(cmd_ctx->err);
    cmd_ctx->err = NULL;
  }
}

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

static void
client_worker_free(assuan_context_t ctx)
{
  struct command_context * cmd_ctx;

  if (!ctx) {
    return;
  }

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  assuan_release(ctx);
  if (!cmd_ctx) {
    return;
  }

  cra_stage_free(cmd_ctx->stage);
  free(cmd_ctx);
}

static void
client_worker(assuan_context_t ctx, gpointer unused)
{
  (void)unused;

  struct command_context * cmd_ctx;
  int done = 0;
  gpg_error_t rc;

  cmd_ctx = (struct command_context *)assuan_get_pointer(ctx);
  if (cmd_ctx) {
    while (!done && !g_atomic_int_get(cmd_ctx->sentinel)) {
      rc = assuan_process_next(ctx, &done);
      if (rc) {
        break;
      }
    }
  }

  client_worker_free(ctx);
}

void
command_handler(int fd, const char * path)
{
  gpg_error_t rc;
  assuan_context_t ctx;
  struct command_context * cmd_ctx;
  cra_Coordinator * coordinator;
  GThreadPool * pool;
  gint sentinel = 0;

  coordinator = cra_coordinator_new(path);
  if (!coordinator) {
    rc = CRE_MEMORY;
    fprintf(stderr, "coordinator init failed\n");
    return;
  }

  pool = g_thread_pool_new((GFunc)client_worker, NULL, -1, FALSE, NULL);
  if (!pool) {
    fprintf(stderr, "client worker pool init failed\n");
    cra_coordinator_free(coordinator);
    return;
  }

  do {
    rc = assuan_new(&ctx);
    if (rc) {
      fprintf(stderr, "server context creation failed: %s\n", gpg_strerror(rc));
      break;
    }

    cmd_ctx = calloc(sizeof(*cmd_ctx), 1);
    if (!cmd_ctx) {
      fprintf(stderr, "failed to allocate new client context\n");
      client_worker_free(ctx);
      break;
    }

    cmd_ctx->listen_fd = fd;
    cmd_ctx->sentinel = &sentinel;
    cmd_ctx->stage = cra_stage_new(coordinator);
    if (!cmd_ctx->stage) {
      fprintf(stderr, "stage init failed\n");
      client_worker_free(ctx);
      break;
    }

    assuan_set_pointer(ctx, cmd_ctx);

    rc = assuan_register_post_cmd_notify(ctx, post_cmd_notify);
    if (rc) {
      fprintf(stderr, "post-command notify register failed: %s\n", gpg_strerror(rc));
      client_worker_free(ctx);
      break;
    }

    rc = register_commands(ctx);
    if (rc) {
      fprintf(stderr, "command register failed: %s\n", gpg_strerror(rc));
      client_worker_free(ctx);
      break;
    }

    rc = assuan_register_option_handler(ctx, option_handler);
    if (rc) {
      fprintf(stderr, "option register failed: %s\n", gpg_strerror(rc));
      client_worker_free(ctx);
      break;
    }

    rc = assuan_init_socket_server(ctx, fd, 0);
    if (rc) {
      fprintf(stderr, "server init failed: %s\n", gpg_strerror(rc));
      client_worker_free(ctx);
      break;
    }

    rc = assuan_accept(ctx);
    if (rc) {
      if (!g_atomic_int_get(cmd_ctx->sentinel) ||
        gpg_err_code(rc) != gpg_err_code_from_errno(EINVAL))
      {
        fprintf(stderr, "accept failed: %s\n", gpg_strerror(rc));
      }
      client_worker_free(ctx);
      break;
    }

    if (!g_thread_pool_push(pool, ctx, NULL)) {
      fprintf(stderr, "failed to push client task\n");
      client_worker_free(ctx);
      break;
    }
  } while (!g_atomic_int_get(&sentinel));

  assuan_sock_close(fd);
  g_thread_pool_free(pool, FALSE, TRUE);
  cra_coordinator_free(coordinator);
}
