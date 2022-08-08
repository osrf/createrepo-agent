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

#include <gtest/gtest.h>

#include "createrepo-cache/repo_cache.h"
#include "createrepo-cache/repo_cache_priv.h"
#include "utils.hpp"

class repo_cache_flush : public TempDir {};

TEST_F(repo_cache_flush, no_sub_repos) {
  auto cache = create_new_cache(temp_dir);

  EXPECT_CRE_OK(cra_cache_flush(cache.get()));
}

TEST_F(repo_cache_flush, ephemeral_repo) {
  auto cache = create_new_cache(temp_dir);

  EXPECT_CRE_OK(cra_cache_realize(cache.get(), NULL));
  EXPECT_CRE_OK(cra_cache_flush(cache.get()));
}

TEST_F(repo_cache_flush, empty_repo) {
  auto cache = create_new_cache(temp_dir);

  cache->source_repo->flags = (cra_RepoFlags)(cache->source_repo->flags | CRA_REPO_DIRTY);
  EXPECT_CRE_OK(cra_cache_flush(cache.get()));
}

TEST_F(repo_cache_flush, single_pkg) {
  auto cache = create_and_populate_cache(temp_dir);

  cache->source_repo->flags = (cra_RepoFlags)(cache->source_repo->flags | CRA_REPO_DIRTY);
  EXPECT_CRE_OK(cra_cache_flush(cache.get()));
}
