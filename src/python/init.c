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
#include <Python.h>

#include "createrepo-agent/common.h"
#include "python/client.h"
#include "python/server.h"

void free_createrepo_agent(void *self)
{
  (void)self;

  assuan_sock_deinit();
}

static struct PyModuleDef createrepo_agent_module_def = {
  PyModuleDef_HEAD_INIT,
  "createrepo_agent",
  NULL,
  0,
  NULL,
  NULL,
  NULL,
  NULL,
  free_createrepo_agent,
};

PyObject *
PyInit_createrepo_agent(void)
{
  PyObject *m = PyModule_Create(&createrepo_agent_module_def);
  if (!m) {
    return NULL;
  }

  gpgrt_check_version(NULL);
  gpgme_check_version(NULL);
  assuan_sock_init();

  if (PyType_Ready(&Client_Type) < 0) {
    return NULL;
  }
  Py_INCREF(&Client_Type);
  PyModule_AddObject(m, "Client", (PyObject *)&Client_Type);

  if (PyType_Ready(&Server_Type) < 0) {
    return NULL;
  }
  Py_INCREF(&Server_Type);
  PyModule_AddObject(m, "Server", (PyObject *)&Server_Type);

  PyModule_AddStringConstant(m, "__version__", CRA_VERSION);
  PyModule_AddStringConstant(m, "SOCK_NAME", CRA_SOCK_NAME);

  PyModule_AddIntConstant(m, "EXIT_SUCCESS", CRA_EXIT_SUCCESS);
  PyModule_AddIntConstant(m, "EXIT_GENERAL_ERROR", CRA_EXIT_GENERAL_ERROR);
  PyModule_AddIntConstant(m, "EXIT_USAGE", CRA_EXIT_USAGE);
  PyModule_AddIntConstant(m, "EXIT_IN_USE", CRA_EXIT_IN_USE);

  return m;
}
