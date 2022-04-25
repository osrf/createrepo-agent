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

#include <stdio.h>

#include "createrepo_agent/client.h"

const char * const usage =
  "createrepo_c_connect_agent\n"
  "\n"
  "Usage: %s SOCKET_FILE\n";

int
main(int argc, char * argv[])
{
  assuan_context_t ctx;
  gpg_error_t rc;

  if (argc < 2) {
    fprintf(stderr, usage, argv[0]);
    return 1;
  }

  gpgrt_check_version(NULL);
  assuan_sock_init();

  rc = assuan_new(&ctx);
  if (rc) {
    fprintf(stderr, "client context creation failed: %s\n", gpg_strerror(rc));
    return 1;
  }

  rc = connect_and_start_server(ctx, argv[1]);
  if (rc) {
    fprintf(stderr, "connection to server failed: %s\n", gpg_strerror(rc));
    return 1;
  }

  printf("Connected to server at '%s'\n", argv[1]);

  assuan_release(ctx);

  return 0;
}
