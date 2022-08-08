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

#include "createrepo-cache/coordinator.h"
#include "createrepo-cache/coordinator_priv.h"
#include "utils.hpp"

class coordinator : public TempDir {};

TEST_F(coordinator, add) {
  auto coordinator = create_new_coordinator(temp_dir);
  auto stage = create_new_stage(coordinator.get());
  auto cache = coordinator->cache;

  auto pkg = create_new_fake_package(temp_dir / "stage");
  ASSERT_CRE_OK(cra_stage_package_add(stage.get(), NULL, pkg.get()));
  pkg.release();
  EXPECT_EQ(1u, g_queue_get_length(stage->operations));
  EXPECT_EQ(0u, g_list_length(cache->source_repo->packages));

  ASSERT_CRE_OK(cra_stage_commit(stage.get()));
  EXPECT_EQ(0u, g_queue_get_length(stage->operations));
  EXPECT_EQ(1u, g_list_length(cache->source_repo->packages));
}

TEST_F(coordinator, add_and_remove) {
  auto coordinator = create_new_coordinator(temp_dir);
  auto stage = create_new_stage(coordinator.get());
  auto cache = coordinator->cache;

  auto pkg = create_new_fake_package(temp_dir / "stage");
  ASSERT_CRE_OK(cra_stage_package_add(stage.get(), NULL, pkg.get()));
  pkg.release();
  EXPECT_EQ(1u, g_queue_get_length(stage->operations));
  EXPECT_EQ(0u, g_list_length(cache->source_repo->packages));

  ASSERT_CRE_OK(cra_stage_name_remove(stage.get(), NULL, "package-name", FALSE, FALSE, FALSE));
  EXPECT_EQ(2u, g_queue_get_length(stage->operations));
  EXPECT_EQ(0u, g_list_length(cache->source_repo->packages));

  ASSERT_CRE_OK(cra_stage_commit(stage.get()));
  EXPECT_EQ(0u, g_queue_get_length(stage->operations));
  EXPECT_EQ(0u, g_list_length(cache->source_repo->packages));
}

TEST_F(coordinator, remove) {
  auto coordinator = create_new_coordinator(temp_dir);
  auto stage = create_new_stage(coordinator.get());
  auto cache = coordinator->cache;
  populate_cache(cache);

  ASSERT_CRE_OK(cra_stage_name_remove(stage.get(), NULL, "no-such-package", FALSE, FALSE, TRUE));
  EXPECT_EQ(1u, g_queue_get_length(stage->operations));

  ASSERT_CRE_OK(cra_stage_name_remove(stage.get(), NULL, "package-name", FALSE, FALSE, FALSE));
  EXPECT_EQ(2u, g_queue_get_length(stage->operations));

  ASSERT_CRE_OK(cra_stage_commit(stage.get()));
  EXPECT_EQ(0u, g_queue_get_length(stage->operations));
  EXPECT_EQ(2u, g_list_length(cache->source_repo->packages));
}
