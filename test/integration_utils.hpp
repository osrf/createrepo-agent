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
#include <algorithm>
#include <chrono>
#include <string>
#include <thread>

#include "createrepo-agent/command.h"
#include "createrepo-agent/common.h"
#include "createrepo-agent/server.h"
#include "utils.hpp"

#ifndef INTEGRATION_UTILS_HPP_
#define INTEGRATION_UTILS_HPP_

namespace fs = std::filesystem;

class TempRepo : public TempDir, public testing::WithParamInterface<std::string_view>
{
public:
  static
  std::string
  PrintParamName(const testing::TestParamInfo<ParamType> & info)
  {
    return std::string(info.param);
  }

protected:
  void
  SetUp() override
  {
    fs::path fixture = fs::absolute("fixtures") / GetParam();
    ASSERT_TRUE(fs::is_directory(fixture));

    TempDir::SetUp();

    fs::copy(fixture, temp_dir);
  }
};

class CRATempServer : public TempRepo
{
protected:
  void
  SetUp() override
  {
    TempRepo::SetUp();
    ASSERT_FALSE(assuan_new(&client));

    sock_path = temp_dir / CRA_SOCK_NAME;

    server_fd = create_server_socket(sock_path.c_str());
    ASSERT_NE(server_fd, ASSUAN_INVALID_FD);

    /* Start the server thread */
    handler_thread = std::thread(command_handler, server_fd, temp_dir.c_str(), nullptr);

    /* Wait for client to connect */
    for (int i = 0; assuan_socket_connect(client, sock_path.c_str(), ASSUAN_INVALID_PID, 0); i++) {
      ASSERT_LT(i, 10);
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  void
  TearDown() override
  {
    if (!::testing::Test::HasFailure()) {
      EXPECT_FALSE(assuan_transact(client, "SHUTDOWN", NULL, NULL, NULL, NULL, NULL, NULL));
      assuan_release(client);
    }

    if (::testing::Test::HasFailure()) {
      /* Something has already failed. Detach the server thread and let it
       * die independently so that we don't clobber the real failure */
      handler_thread.detach();
    } else {
      handler_thread.join();
      assuan_sock_close(server_fd);
      server_fd = ASSUAN_INVALID_FD;
    }

    TempRepo::TearDown();
  }

  fs::path sock_path;
  assuan_context_t client;

private:
  assuan_fd_t server_fd = ASSUAN_INVALID_FD;
  std::thread handler_thread;
};

#endif  // INTEGRATION_UTILS_HPP_
