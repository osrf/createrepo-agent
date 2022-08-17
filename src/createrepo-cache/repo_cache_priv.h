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

#ifndef CREATEREPO_CACHE__REPO_CACHE_PRIV_H_
#define CREATEREPO_CACHE__REPO_CACHE_PRIV_H_

#include <createrepo_c/createrepo_c.h>
#include <glib.h>
#include <gpgme.h>

#include "createrepo-cache/repo_cache.h"

#ifdef __cplusplus
extern "C"
{
#endif

// TODO(cottsay): Re-structure so that this circular reference isn't necessary.
typedef struct _cra_RepoCache cra_RepoCache;

typedef enum
{
  CRA_REPO_LOADED = (1 << 0),
  CRA_REPO_DIRTY = (1 << 1),
  CRA_REPO_MASK = CRA_REPO_LOADED | CRA_REPO_DIRTY,
} cra_RepoFlags;

typedef struct
{
  gchar * source;
  cra_CopyMode mode;
} cra_CopyOperation;

typedef struct
{
  gchar * path;
  gchar * type_name;
  cra_RepoCache * repo;
  cr_XmlFileType type;
  cr_RepomdRecord * record;
  int rc;
} cra_XmlFlushTask;

typedef struct
{
  cr_Package * package;
  gchar * path;
  gchar * chunk[CR_XMLFILE_SENTINEL];
  GHashTable * family;
} cra_PackageCache;

typedef struct
{
  gchar * repomd_path;
  gchar * repomd_asc_path;
  cr_Repomd * repomd;

  cra_RepoCache * repo;
  cra_XmlFlushTask xml[CR_XMLFILE_SENTINEL];

  gchar * copy_tmp;

  int rc;
} cra_RepoFlushTask;

struct _cra_RepoCache
{
  gchar * path;
  gchar * repodata_path;
  gchar * repomd_path;
  gchar * repomd_old_path;
  gchar * repomd_asc_path;
  GList * packages;
  cra_RepoFlags flags;
  cr_Repomd * repomd;
  cr_Repomd * repomd_old;
  gpgme_key_t key;

  // Cache tables
  GHashTable * hrefs;
  GHashTable * names;
  GHashTable * families;
  GHashTable * depends;

  GHashTable * pending_adds;
  GHashTable * pending_rems;

  cra_RepoFlushTask flush_task;
};

typedef struct
{
  cra_RepoCache * arch_repo;
  cra_RepoCache * debug_repo;
} cra_ArchCache;

struct _cra_Cache
{
  gchar * path;
  cra_RepoCache * source_repo;
  GHashTable * arches;
  gpgme_ctx_t gpgme;
};

void
cra_copy_operation_free(cra_CopyOperation * cop);

cra_ArchCache *
cra_arch_cache_get_or_create(cra_Cache * cache, const char * arch_name);

int
cra_repo_cache_packages_add(cra_RepoCache * repo, GHashTable * packages, cra_CopyMode mode);

int
cra_copy_file(const cra_CopyOperation * cop, const char * dst, const char * tmp);

#ifdef __cplusplus
}
#endif

#endif  // CREATEREPO_CACHE__REPO_CACHE_PRIV_H_
