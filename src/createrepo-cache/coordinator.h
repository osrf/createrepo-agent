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

#ifndef CREATEREPO_CACHE__COORDINATOR_H_
#define CREATEREPO_CACHE__COORDINATOR_H_

#include <createrepo_c/createrepo_c.h>
#include <glib.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _cra_Coordinator cra_Coordinator;

typedef struct _cra_Stage cra_Stage;

cra_Coordinator *
cra_coordinator_new(const char * path);

cra_Stage *
cra_stage_new(cra_Coordinator * coordinator);

void
cra_coordinator_free(cra_Coordinator * coordinator);

void
cra_stage_free(cra_Stage * stage);

int
cra_stage_commit(cra_Stage * stage);

int
cra_stage_package_add(cra_Stage * stage, const char * arch_name, cr_Package * package);

int
cra_stage_packages_add(cra_Stage * stage, const char * arch_name, GHashTable * packages);

int
cra_stage_name_remove(
  cra_Stage * stage, const char * arch_name, const char * name,
  gboolean family, gboolean dependants, gboolean missing_ok);

int
cra_stage_pattern_remove(
  cra_Stage * stage, const char * arch_name, GRegex * pattern,
  gboolean family, gboolean dependants, gboolean missing_ok);

#ifdef __cplusplus
}
#endif

#endif  // CREATEREPO_CACHE__COORDINATOR_H_
