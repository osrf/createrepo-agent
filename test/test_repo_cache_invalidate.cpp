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

class repo_cache_invalidate : public TempDir {};

TEST_F(repo_cache_invalidate, family) {
  auto cache = create_and_populate_cache(temp_dir);
  auto arch = reinterpret_cast<cra_ArchCache *>(g_hash_table_lookup(cache->arches, "x86_64"));

  ASSERT_EQ(4u, g_list_length(arch->arch_repo->packages));
  ASSERT_EQ(1u, g_list_length(arch->debug_repo->packages));
  ASSERT_EQ(3u, g_hash_table_size(arch->arch_repo->families));

  // Try removing the only package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), "x86_64", "package-name", TRUE, FALSE));

  EXPECT_EQ(2u, g_list_length(arch->arch_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(arch->arch_repo->pending_adds));
  EXPECT_EQ(2u, g_hash_table_size(arch->arch_repo->pending_rems));
  EXPECT_EQ(2u, g_hash_table_size(arch->arch_repo->families));

  EXPECT_EQ(0u, g_list_length(arch->debug_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(arch->debug_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(arch->debug_repo->pending_rems));
  EXPECT_EQ(0u, g_hash_table_size(arch->debug_repo->families));
}

TEST_F(repo_cache_invalidate, depends) {
  auto cache = create_and_populate_cache(temp_dir);
  auto arch = reinterpret_cast<cra_ArchCache *>(g_hash_table_lookup(cache->arches, "x86_64"));

  ASSERT_EQ(4u, g_list_length(arch->arch_repo->packages));
  ASSERT_EQ(1u, g_list_length(arch->debug_repo->packages));
  ASSERT_EQ(3u, g_hash_table_size(arch->arch_repo->families));

  // Try removing the only package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), "x86_64", "package-name", FALSE, TRUE));

  EXPECT_EQ(2u, g_list_length(arch->arch_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(arch->arch_repo->pending_adds));
  EXPECT_EQ(2u, g_hash_table_size(arch->arch_repo->pending_rems));
  EXPECT_EQ(2u, g_hash_table_size(arch->arch_repo->families));

  EXPECT_EQ(1u, g_list_length(arch->debug_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(arch->debug_repo->pending_adds));
  EXPECT_EQ(0u, g_hash_table_size(arch->debug_repo->pending_rems));
  EXPECT_EQ(1u, g_hash_table_size(arch->debug_repo->families));
}

TEST_F(repo_cache_invalidate, family_and_depends) {
  auto cache = create_and_populate_cache(temp_dir);
  auto arch = reinterpret_cast<cra_ArchCache *>(g_hash_table_lookup(cache->arches, "x86_64"));

  ASSERT_EQ(4u, g_list_length(arch->arch_repo->packages));
  ASSERT_EQ(1u, g_list_length(arch->debug_repo->packages));
  ASSERT_EQ(3u, g_hash_table_size(arch->arch_repo->families));

  // Try removing the only package
  EXPECT_CRE_OK(cra_cache_name_remove(cache.get(), "x86_64", "package-name", TRUE, TRUE));

  EXPECT_EQ(1u, g_list_length(arch->arch_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(arch->arch_repo->pending_adds));
  EXPECT_EQ(3u, g_hash_table_size(arch->arch_repo->pending_rems));
  EXPECT_EQ(1u, g_hash_table_size(arch->arch_repo->families));

  EXPECT_EQ(0u, g_list_length(arch->debug_repo->packages));
  EXPECT_EQ(0u, g_hash_table_size(arch->debug_repo->pending_adds));
  EXPECT_EQ(1u, g_hash_table_size(arch->debug_repo->pending_rems));
  EXPECT_EQ(0u, g_hash_table_size(arch->debug_repo->families));
}
