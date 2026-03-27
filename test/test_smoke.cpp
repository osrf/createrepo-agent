// Copyright 2025 Open Source Robotics Foundation, Inc.
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

#include "integration_utils.hpp"

namespace fs = std::filesystem;

class smoke : public CRATempServer {};

TEST_P(smoke, commit) {
  gpg_error_t rc = assuan_transact(client, "COMMIT", NULL, NULL, NULL, NULL, NULL, NULL);
  EXPECT_FALSE(rc);
}

TEST_P(smoke, touch) {
  gpg_error_t rc = assuan_transact(
    client, "TOUCH aarch64 x86_64", NULL, NULL, NULL, NULL, NULL, NULL);
  EXPECT_FALSE(rc);
  rc = assuan_transact(client, "COMMIT", NULL, NULL, NULL, NULL, NULL, NULL);
  EXPECT_FALSE(rc);

  fs::path srpm_path = temp_dir / "SRPMS";
  fs::path repomd_path = srpm_path / "repodata" / "repomd.xml";

  EXPECT_TRUE(fs::exists(repomd_path));

  for (const auto & arch : {"aarch64", "x86_64"}) {
    fs::path arch_path = temp_dir / arch;
    repomd_path = arch_path / "repodata" / "repomd.xml";

    EXPECT_TRUE(fs::exists(repomd_path));

    repomd_path = arch_path / "debug" / "repodata" / "repomd.xml";

    EXPECT_TRUE(fs::exists(repomd_path));
  }
}

INSTANTIATE_TEST_CASE_P(
  smoke, smoke, testing::Values("bare", "empty", "populated"), smoke::PrintParamName);
