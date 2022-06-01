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

#include <createrepo_c/createrepo_c.h>
#include <glib.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "createrepo-cache/priv.h"
#include "createrepo-cache/repo_cache.h"

#ifndef UTILS_HPP_
#define UTILS_HPP_

#define ASSERT_CRE_OK(rc) \
  ASSERT_EQ(CRE_OK, rc) << "Operation failed: " << cr_strerror((cr_Error)rc)

#define EXPECT_CRE_OK(rc) \
  EXPECT_EQ(CRE_OK, rc) << "Operation failed: " << cr_strerror((cr_Error)rc)

namespace fs = std::filesystem;

class TempDir : public ::testing::Test
{
protected:
  void
  SetUp() override
  {
    temp_dir = make_temp_dir("createrepo-agent.test.XXXXXX");
  }

  void
  TearDown() override
  {
    fs::remove_all(temp_dir);
  }

  fs::path temp_dir;

private:
  static fs::path
  make_temp_dir(std::string_view name_template)
  {
    std::unique_ptr<char, decltype(&std::free)> path {
      strdup((fs::temp_directory_path() / name_template).c_str()),
      &std::free
    };
    mkdtemp(path.get());
    return fs::path(path.get());
  }
};

inline std::unique_ptr<cra_Cache, decltype(& cra_cache_free)>
create_new_cache(const fs::path & path)
{
  return {
    cra_cache_new(path.c_str()),
    &cra_cache_free
  };
}

std::unique_ptr<cr_Package, decltype(& cr_package_free)>
create_new_fake_package(
  const fs::path & repo_base,
  const std::string & arch_name = "",
  const std::string & name = "package-name",
  const std::string & source_name = "package-name",
  const std::vector<std::string> & dependencies = {})
{
  auto pkg_arch = arch_name.empty() ? "src" : arch_name;
  auto pkg_file = name + "." + pkg_arch + ".rpm";
  auto location_base = repo_base / (arch_name.empty() ? "SRPMS" : arch_name);
  auto location_href = fs::path("Packages") / name.substr(0, 1) / pkg_file;
  auto location_full = location_base / location_href;

  std::unique_ptr<cr_Package, decltype(&cr_package_free)> pkg {
    cr_package_new(),
    &cr_package_free
  };

  pkg->name = g_string_chunk_insert(pkg->chunk, name.c_str());
  pkg->arch = g_string_chunk_insert(pkg->chunk, pkg_arch.c_str());
  pkg->location_base = g_string_chunk_insert(pkg->chunk, location_base.c_str());
  pkg->location_href = g_string_chunk_insert(pkg->chunk, location_href.c_str());

  if (!arch_name.empty()) {
    pkg->rpm_sourcerpm = g_string_chunk_insert(pkg->chunk, (source_name + ".src.rpm").c_str());
  }

  for (auto & dep_name : dependencies) {
    cr_Dependency * dep = cr_dependency_new();
    dep->name = g_string_chunk_insert(pkg->chunk, dep_name.c_str());
    pkg->requires = g_slist_append(pkg->requires, dep);
  }

  fs::create_directories(location_full.parent_path());
  std::ofstream(location_full).close();

  return pkg;
}

inline std::unique_ptr<GRegex, decltype(& g_regex_unref)>
create_new_regex(
  const std::string & pattern,
  GRegexCompileFlags compile_options = static_cast<GRegexCompileFlags>(0),
  GRegexMatchFlags match_options = static_cast<GRegexMatchFlags>(0))
{
  return {
    g_regex_new(pattern.c_str(), compile_options, match_options, nullptr),
    &g_regex_unref
  };
}

void
populate_cache(
  std::unique_ptr<cra_Cache, decltype(&cra_cache_free)> & cache,
  std::vector<std::unique_ptr<cr_Package, decltype(&cr_package_free)>> & pkgs,
  const std::string & arch_name = "",
  bool debug = false)
{
  std::unique_ptr<GHashTable, decltype(&g_hash_table_unref)> ht {
    g_hash_table_new_full(NULL, NULL, NULL, (GDestroyNotify)cr_package_free),
    &g_hash_table_unref
  };

  for (auto & pkg : pkgs) {
    g_hash_table_add(ht.get(), pkg.release());
  }

  cra_RepoCache * repo;

  if (arch_name.empty()) {
    repo = cache->source_repo;
  } else {
    cra_ArchCache * arch = cra_arch_cache_get_or_create(cache.get(), arch_name.c_str());
    if (!arch) {
      abort();
    }
    repo = debug ? arch->debug_repo : arch->arch_repo;
  }

  if (cra_repo_cache_populate(repo, ht.get())) {
    abort();
  }
}

void
populate_cache(
  std::unique_ptr<cra_Cache, decltype(&cra_cache_free)> & cache,
  std::unique_ptr<cr_Package, decltype(&cr_package_free)> & pkg)
{
  std::vector<std::unique_ptr<cr_Package, decltype(&cr_package_free)>> pkgs;
  pkgs.push_back(std::move(pkg));

  populate_cache(cache, pkgs);
}

std::unique_ptr<cra_Cache, decltype(& cra_cache_free)>
create_and_populate_cache(const fs::path & path)
{
  auto cache = create_new_cache(path);
  std::vector<std::unique_ptr<cr_Package, decltype(&cr_package_free)>> pkgs;

  // Source package
  pkgs.push_back(create_new_fake_package(path));
  pkgs.push_back(create_new_fake_package(path, "", "another-package"));
  pkgs.push_back(create_new_fake_package(path, "", "yet-another", "", {"another-package"}));
  populate_cache(cache, pkgs);
  pkgs.clear();

  // Binary packages
  pkgs.push_back(create_new_fake_package(path, "x86_64"));
  pkgs.push_back(create_new_fake_package(path, "x86_64", "package-name-docs"));
  pkgs.push_back(
    create_new_fake_package(
      path, "x86_64", "another-package", "another-package", {"package-name"}));
  pkgs.push_back(create_new_fake_package(path, "x86_64", "yet-another", "yet-another"));
  populate_cache(cache, pkgs, "x86_64");
  pkgs.clear();

  // Debug packages
  pkgs.push_back(create_new_fake_package(path, "x86_64", "package-name-debuginfo"));
  populate_cache(cache, pkgs, "x86_64", true);
  pkgs.clear();

  return cache;
}

#endif  // UTILS_HPP_
