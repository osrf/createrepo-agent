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

#ifndef CREATEREPO_CACHE__REPO_CACHE_H_
#define CREATEREPO_CACHE__REPO_CACHE_H_

#include <createrepo_c/createrepo_c.h>
#include <glib.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _cra_Cache cra_Cache;

typedef enum
{
  CRA_COPYMODE_NOTHING = 0,
  CRA_COPYMODE_COPY,
  CRA_COPYMODE_MOVE,
  CRA_COPYMODE_LINK,
} cra_CopyMode;

typedef struct
{
  size_t repo_count;
  size_t pkg_count;
} cra_CacheStats;

cra_Cache *
cra_cache_new(const char * path);

void
cra_cache_clear(cra_Cache * cache);

void
cra_cache_free(cra_Cache * cache);

int
cra_cache_realize(cra_Cache * cache, const char * arch_name);

int
cra_cache_package_add(
  cra_Cache * cache, const char * arch_name, cr_Package * package, cra_CopyMode mode);

int
cra_cache_packages_add(
  cra_Cache * cache, const char * arch_name, GHashTable * packages, cra_CopyMode mode);

int
cra_cache_name_remove(
  cra_Cache * cache, const char * arch_name, const char * name,
  gboolean family, gboolean dependants);

int
cra_cache_pattern_remove(
  cra_Cache * cache, const char * arch_name, const GRegex * pattern,
  gboolean family, gboolean dependants);

int
cra_cache_flush(cra_Cache * cache);

cra_CacheStats
cra_cache_stats(cra_Cache * cache);

#ifdef __cplusplus
}
#endif

#endif  // CREATEREPO_CACHE__REPO_CACHE_H_
