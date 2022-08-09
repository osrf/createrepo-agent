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

#ifndef CREATEREPO_CACHE__COORDINATOR_PRIV_H_
#define CREATEREPO_CACHE__COORDINATOR_PRIV_H_

#include <createrepo_c/createrepo_c.h>
#include <glib.h>

#include "createrepo-cache/coordinator.h"
#include "createrepo-cache/repo_cache.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
  gchar * arch_name;
  cr_Package * add_package;
  GHashTable * add_packages;
  gchar * remove_name;
  GRegex * remove_pattern;
  gboolean remove_family;
  gboolean remove_dependants;
  gboolean remove_missing_ok;
} cra_StageOperation;

struct _cra_Coordinator
{
  cra_Cache * cache;
  GAsyncQueue * pending;
  GMutex lock;
};

struct _cra_Stage
{
  cra_Coordinator * coordinator;
  GQueue * operations;
  int rc;
};

int
cra_stage_prepare(cra_Stage * stage);

#ifdef __cplusplus
}
#endif

#endif  // CREATEREPO_CACHE__COORDINATOR_PRIV_H_
