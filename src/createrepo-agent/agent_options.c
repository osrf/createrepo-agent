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

#include <createrepo_c/createrepo_c.h>

#include "createrepo-agent/agent_options.h"

#define POS_ARG_NAME "REPO_CLUSTER_DIR"

static void
cra_agent_options_fini(cra_AgentOptions * opts)
{
  g_free(opts->path);
  opts->path = NULL;
}

static gboolean
cra_agent_options_path_cb(
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

  opts->path = cr_normalize_dir_path(value);

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
cra_agent_options_post_hook(
  GOptionContext * context, GOptionGroup * group, cra_AgentOptions * opts,
  GError ** err)
{
  (void)context;
  (void)group;

  if (opts->path == NULL) {
    g_set_error(
      err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
      "Missing required argument " POS_ARG_NAME);
    return FALSE;
  }

  if (opts->daemon && opts->server) {
    g_set_error(
      err, G_OPTION_ERROR, G_OPTION_ERROR_FAILED,
      "Cannot specify more than one command");
    return FALSE;
  }

  return TRUE;
}

GOptionGroup *
cra_get_agent_option_group(cra_AgentOptions * opts)
{
  GOptionGroup * group = g_option_group_new(
    NULL, NULL, NULL, opts, (GDestroyNotify)cra_agent_options_fini);
  if (!group) {
    return NULL;
  }

  GOptionEntry entries[] = {
    {
      "daemon", 0, 0, G_OPTION_ARG_NONE, &opts->daemon,
      "run in daemon mode (background)", NULL
    },
    {
      "server", 0, 0, G_OPTION_ARG_NONE, &opts->server,
      "run in server mode (foreground)", NULL
    },
    {
      G_OPTION_REMAINING, 0, G_OPTION_FLAG_FILENAME, G_OPTION_ARG_CALLBACK,
      as_void((GOptionArgFunc)cra_agent_options_path_cb), NULL, POS_ARG_NAME
    },
    {NULL},
  };

  g_option_group_add_entries(group, entries);
  g_option_group_set_parse_hooks(
    group, NULL, (GOptionParseFunc)cra_agent_options_post_hook);

  return group;
}
