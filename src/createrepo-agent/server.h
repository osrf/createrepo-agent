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

#ifndef CREATEREPO_AGENT__SERVER_H_
#define CREATEREPO_AGENT__SERVER_H_

#include <assuan.h>

#ifdef __cplusplus
extern "C"
{
#endif

gpg_error_t
try_server(const char * name);

assuan_fd_t
create_server_socket(const char * name);

#ifdef __cplusplus
}
#endif

#endif  // CREATEREPO_AGENT__SERVER_H_
