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
#include <gtest/gtest.h>

#include "createrepo-cache/repo_cache.h"
#include "createrepo-cache/repo_cache_priv.h"
#include "utils.hpp"

class repo_cache_modify : public TempDir {};

TEST_F(repo_cache_modify, add_in_place) {
  auto cache = create_new_cache(temp_dir);

  auto pkg = create_new_fake_package(temp_dir);
  ASSERT_CRE_OK(cra_cache_package_add(cache.get(), NULL, pkg.get(), CRA_COPYMODE_MOVE));
  pkg.release();

  EXPECT_EQ(1u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));

  // Add another package with the same name
  pkg = create_new_fake_package(temp_dir);
  ASSERT_EQ(CRE_EXISTS, cra_cache_package_add(cache.get(), NULL, pkg.get(), CRA_COPYMODE_MOVE));

  EXPECT_EQ(1u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));
}

TEST_F(repo_cache_modify, add_with_move) {
  auto cache = create_new_cache(temp_dir);

  auto pkg = create_new_fake_package(temp_dir / "stage");
  ASSERT_CRE_OK(cra_cache_package_add(cache.get(), NULL, pkg.get(), CRA_COPYMODE_MOVE));
  pkg.release();

  EXPECT_EQ(1u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));

  // Add another package with the same name
  pkg = create_new_fake_package(temp_dir / "stage2");
  ASSERT_EQ(CRE_EXISTS, cra_cache_package_add(cache.get(), NULL, pkg.get(), CRA_COPYMODE_MOVE));

  EXPECT_EQ(1u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));
}

TEST_F(repo_cache_modify, add_and_remove) {
  auto cache = create_new_cache(temp_dir);

  auto pkg = create_new_fake_package(temp_dir / "stage");
  ASSERT_CRE_OK(cra_cache_package_add(cache.get(), NULL, pkg.get(), CRA_COPYMODE_MOVE));
  pkg.release();

  EXPECT_EQ(1u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));

  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));

  EXPECT_EQ(0u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));
}

TEST_F(repo_cache_modify, remove_name) {
  auto cache = create_and_populate_cache(temp_dir);

  // Try removing a pattern that has no matches
  EXPECT_EQ(CRE_NOFILE, cra_cache_name_remove(cache.get(), NULL, "no-such-package", FALSE, FALSE));

  EXPECT_EQ(3u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));

  // Try removing one package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));

  // Try removing it again to ensure it is no longer found
  EXPECT_EQ(CRE_NOFILE, cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));
}

TEST_F(repo_cache_modify, remove_pattern) {
  auto cache = create_and_populate_cache(temp_dir);

  // Try removing a pattern that has no matches
  auto regex = create_new_regex("^no-such-package$");
  EXPECT_EQ(CRE_NOFILE, cra_cache_pattern_remove(cache.get(), NULL, regex.get(), FALSE, FALSE));

  EXPECT_EQ(3u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));

  // Try removing one package
  regex = create_new_regex("^package-name$");
  EXPECT_CRE_OK(cra_cache_pattern_remove(cache.get(), NULL, regex.get(), FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));

  // Try removing it again to ensure it is no longer found
  regex = create_new_regex("^package-name$");
  EXPECT_EQ(CRE_NOFILE, cra_cache_pattern_remove(cache.get(), NULL, regex.get(), FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));
}

TEST_F(repo_cache_modify, remove_and_add_similar) {
  auto cache = create_and_populate_cache(temp_dir);

  // Try removing one package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));

  // Re-add a nearly identical package
  auto pkg = create_new_fake_package(
    temp_dir / "stage", "", "package-name", "package-name", {"something-different"});
  EXPECT_CRE_OK(cra_cache_package_add(cache.get(), NULL, pkg.get(), CRA_COPYMODE_MOVE));
  pkg.release();

  EXPECT_EQ(3u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));
}

TEST_F(repo_cache_modify, remove_and_add_identical) {
  auto cache = create_and_populate_cache(temp_dir);

  // Try removing one package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));

  // Re-add the exact same package
  auto pkg = create_new_fake_package(temp_dir / "stage");
  EXPECT_CRE_OK(cra_cache_package_add(cache.get(), NULL, pkg.get(), CRA_COPYMODE_MOVE));
  pkg.release();

  EXPECT_EQ(3u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));
}

TEST_F(repo_cache_modify, remove_and_populate_similar) {
  auto cache = create_and_populate_cache(temp_dir);

  // Try removing one package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));

  // Re-add a nearly identical package
  std::unique_ptr<GHashTable, decltype(&g_hash_table_unref)> ht {
    g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)cr_package_free),
    &g_hash_table_unref
  };
  g_hash_table_add(
    ht.get(),
    create_new_fake_package(
      temp_dir / "stage",
      "",
      "package-name",
      "package-name",
      {"something-different"}).release());
  EXPECT_CRE_OK(cra_repo_cache_populate(cache->source_repo, ht.get()));

  EXPECT_EQ(3u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));
  EXPECT_EQ(0u, g_hash_table_size(ht.get()));
}

TEST_F(repo_cache_modify, remove_and_populate_identical) {
  auto cache = create_and_populate_cache(temp_dir);

  // Try removing one package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));

  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));

  // Re-add the exact same package
  std::unique_ptr<GHashTable, decltype(&g_hash_table_unref)> ht {
    g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)cr_package_free),
    &g_hash_table_unref
  };
  g_hash_table_add(
    ht.get(),
    create_new_fake_package(temp_dir / "stage").release());
  EXPECT_CRE_OK(cra_repo_cache_populate(cache->source_repo, ht.get()));

  EXPECT_EQ(3u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_rems));
  EXPECT_EQ(0u, g_hash_table_size(ht.get()));
}

TEST_F(repo_cache_modify, remove_and_multiple) {
  auto cache = create_and_populate_cache(temp_dir);

  // Try removing some packages
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "package-name", FALSE, FALSE));
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), NULL, "another-package", FALSE, FALSE));

  EXPECT_EQ(1u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(2u, g_hash_table_size(cache->source_repo->pending_rems));

  // Re-add the packages
  std::unique_ptr<GHashTable, decltype(&g_hash_table_unref)> ht {
    g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)cr_package_free),
    &g_hash_table_unref
  };
  g_hash_table_add(
    ht.get(),
    create_new_fake_package(temp_dir / "stage").release());
  g_hash_table_add(
    ht.get(),
    create_new_fake_package(
      temp_dir / "stage",
      "",
      "another-package",
      "another-package").release());
  EXPECT_CRE_OK(cra_cache_packages_add(cache.get(), NULL, ht.get(), CRA_COPYMODE_MOVE));

  EXPECT_EQ(3u, g_list_length(cache->source_repo->packages));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(cache->source_repo->pending_rems));
  EXPECT_EQ(0u, g_hash_table_size(ht.get()));
}
