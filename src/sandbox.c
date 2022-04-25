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

#include <stdio.h>

#include <createrepo_c/createrepo_c.h>
#include <glib.h>

#include "createrepo_cache/repo_cache.h"

int
remove_pkg(cra_Cache * cache, const char * arch_name, const char * pattern)
{
  GRegex * regex;
  int rc;

  printf("Removing '%s' from %s\n", pattern, arch_name ? arch_name : "SRPMS");

  regex = g_regex_new(
    pattern, G_REGEX_ANCHORED | G_REGEX_OPTIMIZE, G_REGEX_MATCH_ANCHORED, NULL);
  if (!regex) {
    return CRE_ASSERT;
  }

  rc = cra_cache_pattern_remove(cache, arch_name, regex, FALSE, FALSE);
  g_regex_unref(regex);
  return rc;
}

int
add_pkg(cra_Cache * cache, const char * arch_name, const char * path)
{
  int rc;
  cr_Package * package;
  const char * name = cr_get_filename(path);
  gchar * base = g_strndup(path, (gsize)(name - path));

  // TODO(cottsay): What is a good changelog limit?
  package = cr_package_from_rpm(path, CR_CHECKSUM_SHA256, name, base, -1, NULL, 0, NULL);
  if (!package) {
    g_free(base);
    fprintf(stderr, "Failed to read info about package '%s'\n", path);
    return CRE_ASSERT;
  }

  printf("Adding '%s' from '%s' to %s\n", name, base, arch_name ? arch_name : "SRPMS");

  rc = cra_cache_package_add(cache, arch_name, package);
  if (rc) {
    cr_package_free(package);
  }

  g_free(base);

  return rc;
}

int
main(int argc, char * argv[])
{
  cra_Cache * cache;
  cra_CacheStats stats;
  int rc;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s REPO_ROOT_PATH\n", argv[0]);
    return CRE_ERROR;
  }

  cr_xml_dump_init();

  cache = cra_cache_new(argv[1]);
  if (!cache) {
    fprintf(stderr, "Failed to create cache instance\n");
    return CRE_MEMORY;
  }

  rc = cra_cache_realize(cache, NULL);
  if (rc) {
    fprintf(stderr, "Failed to realize SRPMS: %s\n", cr_strerror(rc));
    goto exit;
  }

  rc = cra_cache_realize(cache, "x86_64");
  if (rc) {
    fprintf(stderr, "Failed to realize x86_64: %s\n", cr_strerror(rc));
    goto exit;
  }

  rc = cra_cache_realize(cache, "i386");
  if (rc) {
    fprintf(stderr, "Failed to realize x86_64: %s\n", cr_strerror(rc));
    goto exit;
  }

  rc = cra_cache_realize(cache, "arm64");
  if (rc) {
    fprintf(stderr, "Failed to realize x86_64: %s\n", cr_strerror(rc));
    goto exit;
  }

  rc = remove_pkg(cache, "x86_64", "ros-galactic-rqt.*");
  if (rc) {
    fprintf(stderr, "Failed to remove packages prior to reload: %s\n", cr_strerror(rc));
    goto exit;
  }

  rc = cra_cache_reload(cache);
  if (rc) {
    fprintf(stderr, "Failed to reload: %s\n", cr_strerror(rc));
    goto exit;
  }

  stats = cra_cache_stats(cache);
  printf("Repositories: %lu\nPackages: %lu\n", stats.repo_count, stats.pkg_count);

  /*
  rc = add_pkg(cache, NULL, "ros-rolling-desktop-0.9.3-2.el8.src.rpm");
  if (rc) {
    fprintf(stderr, "Failed to add: %s\n", cr_strerror(rc));
    goto exit;
  }
  */

  printf("Flushing...\n");

  rc = cra_cache_touch(cache, NULL);
  if (rc) {
    fprintf(stderr, "Failed to touch SRPMS: %s\n", cr_strerror(rc));
    goto exit;
  }

  rc = cra_cache_touch(cache, "x86_64");
  if (rc) {
    fprintf(stderr, "Failed to touch x86_64: %s\n", cr_strerror(rc));
    goto exit;
  }

  rc = cra_cache_flush(cache);
  if (rc) {
    fprintf(stderr, "Failed to flush the cache: %s\n", cr_strerror(rc));
    goto exit;
  }

exit:
  printf("Cleaning up... (%d)\n", rc);

  cra_cache_free(cache);

  cr_xml_dump_cleanup();

  return rc;
}
