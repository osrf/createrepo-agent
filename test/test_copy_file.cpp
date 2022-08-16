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

#include <filesystem>
#include <fstream>

#include "createrepo-cache/repo_cache.h"
#include "createrepo-cache/repo_cache_priv.h"
#include "utils.hpp"

namespace fs = std::filesystem;

class copy_file : public TempDir {};

std::unique_ptr<cra_CopyOperation, decltype(& cra_copy_operation_free)>
create_new_copy_operation(const std::string & source, cra_CopyMode mode)
{
  std::unique_ptr<cra_CopyOperation, decltype(&cra_copy_operation_free)> cop {
    g_new0(cra_CopyOperation, 1),
    &cra_copy_operation_free
  };

  cop->source = g_strdup(source.c_str());
  if (!cop->source) {
    throw std::bad_alloc();
  }
  cop->mode = mode;

  return cop;
}

TEST_F(copy_file, nothing) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_NOTHING);

  std::ofstream(src).close();

  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), nullptr));

  EXPECT_TRUE(fs::is_regular_file(src));
  EXPECT_FALSE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));
}

TEST_F(copy_file, link) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_LINK);

  std::ofstream(src).close();

  EXPECT_EQ(CRE_BADARG, cra_copy_file(cop.get(), dst.c_str(), nullptr));
  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_TRUE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));

  EXPECT_TRUE(are_same_file(src, dst));
}

TEST_F(copy_file, link_overwrite) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_LINK);

  std::ofstream(src).close();
  std::ofstream(dst).close();

  EXPECT_EQ(CRE_BADARG, cra_copy_file(cop.get(), dst.c_str(), nullptr));
  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_TRUE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));

  EXPECT_TRUE(are_same_file(src, dst));
}

TEST_F(copy_file, link_make_parent) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "missing_parent" / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_LINK);

  std::ofstream(src).close();

  EXPECT_EQ(CRE_BADARG, cra_copy_file(cop.get(), dst.c_str(), nullptr));
  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_TRUE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));

  EXPECT_TRUE(are_same_file(src, dst));
}

TEST_F(copy_file, move) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_MOVE);

  std::ofstream(src).close();

  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_FALSE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));
}

TEST_F(copy_file, move_overwrite) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_MOVE);

  std::ofstream(src).close();
  std::ofstream(dst).close();

  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_FALSE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));
}

TEST_F(copy_file, move_make_parent) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "missing_parent" / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_MOVE);

  std::ofstream(src).close();

  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_FALSE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));
}

TEST_F(copy_file, copy) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_COPY);

  std::ofstream(src).close();

  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_TRUE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));

  EXPECT_FALSE(are_same_file(src, dst));
}

TEST_F(copy_file, copy_overwrite) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_COPY);

  std::ofstream(src).close();
  std::ofstream(dst).close();

  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_TRUE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));

  EXPECT_FALSE(are_same_file(src, dst));
}

TEST_F(copy_file, copy_make_parent) {
  auto src = temp_dir / "src.txt";
  auto dst = temp_dir / "missing_parent" / "dst.txt";
  auto tmp = temp_dir / "tmp.txt";
  auto cop = create_new_copy_operation(src, CRA_COPYMODE_COPY);

  std::ofstream(src).close();

  ASSERT_CRE_OK(cra_copy_file(cop.get(), dst.c_str(), tmp.c_str()));

  EXPECT_TRUE(fs::is_regular_file(src));
  EXPECT_TRUE(fs::is_regular_file(dst));
  EXPECT_FALSE(fs::is_regular_file(tmp));

  EXPECT_FALSE(are_same_file(src, dst));
}
