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

#include "createrepo-cache/coordinator.h"
#include "createrepo-cache/repo_cache.h"

typedef struct
{
  gchar * arch_name;
  cr_Package * add_package;
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

void
cra_stage_operation_free(cra_StageOperation * op)
{
  if (!op) {
    return;
  }

  if (op->remove_pattern) {
    g_regex_unref(op->remove_pattern);
  }

  g_free(op->remove_name);
  cr_package_free(op->add_package);
  g_free(op->arch_name);
  g_free(op);
}

void
cra_stage_free(cra_Stage * stage)
{
  if (!stage) {
    return;
  }

  g_queue_free_full(stage->operations, (GDestroyNotify)cra_stage_operation_free);
  g_free(stage);
}

void
cra_coordinator_free(cra_Coordinator * coordinator)
{
  if (!coordinator) {
    return;
  }

  g_mutex_clear(&coordinator->lock);
  g_async_queue_unref(coordinator->pending);
  cra_cache_free(coordinator->cache);
  g_free(coordinator);
}

cra_Coordinator *
cra_coordinator_new(const char * path)
{
  cra_Coordinator * coordinator;

  coordinator = g_new0(cra_Coordinator, 1);
  if (!coordinator) {
    return NULL;
  }

  coordinator->cache = cra_cache_new(path);
  if (!coordinator->cache) {
    cra_coordinator_free(coordinator);
    return NULL;
  }

  coordinator->pending = g_async_queue_new();
  if (!coordinator->pending) {
    cra_coordinator_free(coordinator);
    return NULL;
  }

  g_mutex_init(&coordinator->lock);

  return coordinator;
}

cra_Stage *
cra_stage_new(cra_Coordinator * coordinator)
{
  cra_Stage * stage;

  stage = g_new0(cra_Stage, 1);
  if (!stage) {
    return NULL;
  }

  stage->coordinator = coordinator;
  stage->operations = g_queue_new();
  if (!stage->operations) {
    cra_stage_free(stage);
    return NULL;
  }

  return stage;
}

cra_StageOperation *
cra_stage_operation_new(const char * arch_name)
{
  cra_StageOperation * op;

  op = g_new0(cra_StageOperation, 1);
  if (!op) {
    return NULL;
  }

  if (arch_name) {
    op->arch_name = g_strdup(arch_name);
    if (!op->arch_name) {
      cra_stage_operation_free(op);
      return NULL;
    }
  }

  return op;
}

void
cra_coordinator_commit(cra_Coordinator * coordinator)
{
  cra_Stage * stage;
  cra_StageOperation * op;
  GSList * done = NULL;
  int rc = CRE_OK;

  while (!rc && (stage = g_async_queue_try_pop(coordinator->pending))) {
    while (!rc && (op = g_queue_pop_head(stage->operations))) {
      rc = cra_cache_realize(coordinator->cache, op->arch_name);

      if (!rc && op->remove_name) {
        rc = cra_cache_name_remove(
          coordinator->cache, op->arch_name, op->remove_name,
          op->remove_family, op->remove_dependants);
        if (CRE_NOFILE == rc && op->remove_missing_ok) {
          rc = CRE_OK;
        }
      }

      if (!rc && op->remove_pattern) {
        rc = cra_cache_pattern_remove(
          coordinator->cache, op->arch_name, op->remove_pattern,
          op->remove_family, op->remove_dependants);
        if (CRE_NOFILE == rc && op->remove_missing_ok) {
          rc = CRE_OK;
        }
      }

      if (!rc && op->add_package) {
        rc = cra_cache_package_add(
          coordinator->cache, op->arch_name, op->add_package);
      }
    }

    done = g_slist_prepend(done, stage);
  }

  if (rc) {
    cra_cache_clear(coordinator->cache);
  } else {
    rc = cra_cache_flush(coordinator->cache);
  }

  for (; NULL != done; done = g_slist_next(done)) {
    stage = done->data;
    stage->rc = rc;
  }
}

int
cra_stage_commit(cra_Stage * stage)
{
  int rc;
  cra_Coordinator * coordinator = stage->coordinator;

  if (g_queue_is_empty(stage->operations)) {
    return CRE_OK;
  }

  stage->rc = CRE_ASSERT;

  g_async_queue_push(coordinator->pending, stage);

  g_mutex_lock(&coordinator->lock);

  if (stage->rc == CRE_ASSERT) {
    cra_coordinator_commit(coordinator);
  }

  g_mutex_unlock(&coordinator->lock);

  rc = stage->rc;

  return rc;
}

int
cra_stage_package_add(cra_Stage * stage, const char * arch_name, cr_Package * pkg)
{
  cra_StageOperation * op;

  op = cra_stage_operation_new(arch_name);
  if (!op) {
    return CRE_MEMORY;
  }

  op->add_package = pkg;

  g_queue_push_tail(stage->operations, op);

  return CRE_OK;
}

int
cra_stage_name_remove(
  cra_Stage * stage, const char * arch_name, const char * name,
  gboolean family, gboolean dependants, gboolean missing_ok)
{
  cra_StageOperation * op;

  op = cra_stage_operation_new(arch_name);
  if (!op) {
    return CRE_MEMORY;
  }

  op->remove_name = g_strdup(name);
  if (!op->remove_name) {
    cra_stage_operation_free(op);
    return CRE_MEMORY;
  }
  op->remove_family = family;
  op->remove_dependants = dependants;
  op->remove_missing_ok = missing_ok;

  g_queue_push_tail(stage->operations, op);

  return CRE_OK;
}

int
cra_stage_pattern_remove(
  cra_Stage * stage, const char * arch_name, GRegex * pattern,
  gboolean family, gboolean dependants, gboolean missing_ok)
{
  cra_StageOperation * op;

  op = cra_stage_operation_new(arch_name);
  if (!op) {
    return CRE_MEMORY;
  }

  op->remove_pattern = g_regex_ref(pattern);
  op->remove_family = family;
  op->remove_dependants = dependants;
  op->remove_missing_ok = missing_ok;

  g_queue_push_tail(stage->operations, op);

  return CRE_OK;
}
