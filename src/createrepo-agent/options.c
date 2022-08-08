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

#include <glib.h>

#include "createrepo-agent/options.h"

#define POS_ARG_NAME "REPO_CLUSTER_DIR"

static gchar *
resolve_path(const gchar * path)
{
  gchar * res;
  gchar * cwd = g_path_is_absolute(path) ? NULL : g_get_current_dir();
  res = g_strconcat(
    cwd ? cwd : "",
    cwd && !g_str_has_suffix(cwd, "/") ? "/" : "",
    path,
    g_str_has_suffix(path, "/") ? NULL : "/",
    NULL);
  g_free(cwd);
  return res;
}

static void
cra_options_fini(cra_AgentOptions * opts)
{
  g_strfreev(opts->arch);
  g_strfreev(opts->import);
  opts->import = NULL;
  g_free(opts->path);
  opts->path = NULL;
}

static gboolean
cra_options_path_cb(
  const gchar * option_name, const gchar * value, cra_AgentOptions * opts,
  GError ** err)
{
  (void)option_name;

  if (opts->path) {
    g_set_error(
      err, G_OPTION_ERROR, G_OPTION_ERROR_UNKNOWN_OPTION,
      "Unknown argument %s", value);
    return FALSE;
  }

  opts->path = resolve_path(value);

  return TRUE;
}

static inline void *
as_void(GOptionArgFunc func)
{
  // Hack to get around non-ISO conformance in glib
  union {
    GOptionArgFunc func;
    void * ptr;
  } val = {func};

  return val.ptr;
}

static gboolean
cra_options_post_hook(
  GOptionContext * context, GOptionGroup * group, cra_AgentOptions * opts,
  GError ** err)
{
  (void)context;
  (void)group;

  if (opts->import && !opts->import[0]) {
    g_strfreev(opts->import);
    opts->import = NULL;
  }

  if (opts->arch && !opts->arch[0]) {
    g_strfreev(opts->arch);
    opts->arch = NULL;
  }

  int commands = (opts->version ? 1 : 0) +
    (opts->daemon ? 1 : 0) +
    (opts->server ? 1 : 0) +
    (NULL != opts->import ? 1 : 0);
  if (commands > 1) {
    g_set_error(
      err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
      "Cannot specify more than one command");
    return FALSE;
  }

  if (!opts->version && opts->path == NULL) {
    g_set_error(
      err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
      "Missing required argument " POS_ARG_NAME);
    return FALSE;
  }

  if ((opts->invalidate_family || opts->invalidate_dependants) &&
    !opts->import)
  {
    g_set_error(
      err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
      "Invalidation options are only valid with --import");
    return FALSE;
  }

  return TRUE;
}

GOptionGroup *
cra_get_option_group(cra_AgentOptions * opts)
{
  GOptionGroup * group = g_option_group_new(
    NULL, NULL, NULL, opts, (GDestroyNotify)cra_options_fini);
  if (!group) {
    return NULL;
  }

  GOptionEntry entries[] = {
    {
      "version", 0, 0, G_OPTION_ARG_NONE, &opts->version,
      "show createrepo-agent version number and exit", NULL
    },
    {
      "daemon", 0, 0, G_OPTION_ARG_NONE, &opts->daemon,
      "run in daemon mode (background)", NULL
    },
    {
      "server", 0, 0, G_OPTION_ARG_NONE, &opts->server,
      "run in server mode (foreground)", NULL
    },
    {
      "import", 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &opts->import,
      "import packages into the repository cluster", "RPM_FILE"
    },
    {
      "arch", 0, 0, G_OPTION_ARG_STRING_ARRAY, &opts->arch,
      "when importing, add packages for these architectures", "ARCH_NAME"
    },
    {
      "invalidate-family", 0, 0, G_OPTION_ARG_NONE, &opts->invalidate_family,
      "when importing, remove existing packages related to new ones", NULL
    },
    {
      "invalidate-dependants", 0, 0, G_OPTION_ARG_NONE,
      &opts->invalidate_dependants,
      "when importing, remove existing packages which depend on new ones", NULL
    },
    {
      G_OPTION_REMAINING, 0, G_OPTION_FLAG_FILENAME, G_OPTION_ARG_CALLBACK,
      as_void((GOptionArgFunc)cra_options_path_cb), NULL, POS_ARG_NAME
    },
    {NULL},
  };

  g_option_group_add_entries(group, entries);
  g_option_group_set_parse_hooks(
    group, NULL, (GOptionParseFunc)cra_options_post_hook);

  return group;
}
