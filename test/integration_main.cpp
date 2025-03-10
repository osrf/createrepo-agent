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

#include <assuan.h>
#include <gpgme.h>
#include <gtest/gtest.h>

int main(int argc, char * argv[])
{
  int ret;

  gpgrt_check_version(NULL);
  gpgme_check_version(NULL);
  assuan_sock_init();
  ::testing::InitGoogleTest(&argc, argv);
  ret = RUN_ALL_TESTS();
  assuan_sock_deinit();
  return ret;
}
