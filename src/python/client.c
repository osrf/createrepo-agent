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
#include <createrepo-agent/common.h>
#include <glib.h>
#include <Python.h>

#include "python/client.h"

typedef struct
{
  PyObject_HEAD
  gchar * name;
  assuan_context_t ctx;
} ClientObject;

static PyObject *
client_disconnect(ClientObject *self, PyObject *args);

static PyObject *
client_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  (void)args;
  (void)kwds;

  ClientObject *self = (ClientObject *)type->tp_alloc(type, 0);
  if (self) {
    self->ctx = NULL;
    self->name = NULL;
  }
  return (PyObject *)self;
}

static int
client_init(ClientObject *self, PyObject *args, PyObject *kwds)
{
  static char * keywords[] = {
    "name",
    NULL,
  };

  char *name = NULL;

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", keywords, &name)) {
    return -1;
  }

  if (NULL != self->name) {
    g_free(self->name);
  }

  self->name = g_strdup(name);
  if (NULL == self->name) {
    PyErr_NoMemory();
    return -1;
  }

  return 0;
}
static void
client_dealloc(ClientObject *self)
{
  Py_XDECREF(client_disconnect(self, NULL));

  if (NULL != self->name) {
    g_free(self->name);
  }

  Py_TYPE(self)->tp_free(self);
}

static PyObject *
client_repr(ClientObject *self)
{
  return PyUnicode_FromFormat(
    "<createrepo_agent.Client name='%s'>", self->name);
}

static PyObject *
execute_transaction(ClientObject *self, const char * cmd)
{
  gpg_error_t rc;

  rc = assuan_transact(self->ctx, cmd, NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc) {
    PyErr_Format(PyExc_RuntimeError, "Transaction failed: %s", gpg_strerror(rc));
    return NULL;
  }

  Py_RETURN_NONE;
}

static const gchar **
sequence_to_str_array(PyObject *sequence)
{
  Py_ssize_t len = PySequence_Length(sequence);
  assert(len >= 0);

  const gchar **res = g_new0(const gchar *, (unsigned)len + 1);
  if (NULL == res) {
    PyErr_NoMemory();
    return NULL;
  }

  for (Py_ssize_t i = 0; i < len; i++) {
    PyObject *item = PySequence_Fast_GET_ITEM(sequence, i);
    res[i] = PyUnicode_AsUTF8(item);
    if (NULL == res[i]) {
      PyErr_Format(PyExc_TypeError, "arches contains non-string at index %u", i);
      g_free(res);
      return NULL;
    }
  }

  return res;
}

static PyObject *
client_add(ClientObject *self, PyObject *args)
{
  char *package = NULL;
  PyObject *arches = NULL;
  gchar *arch_list = NULL;
  gchar *cmd;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "s|O", &package, &arches)) {
    return NULL;
  }

  if (arches != NULL && arches != Py_None) {
    if (1 != PySequence_Check(arches)) {
      PyErr_SetString(PyExc_TypeError, "arches must be an iterable");
      return NULL;
    }

    const gchar **arch_array = sequence_to_str_array(arches);
    if (NULL == arch_array) {
      return NULL;
    }

    arch_list = g_strjoinv(" ", (gchar **)arch_array);
    g_free(arch_array);
  }

  cmd = g_strjoin(" ", "ADD", package, arch_list, NULL);
  g_free(arch_list);
  if (!cmd) {
    return PyErr_NoMemory();
  }

  ret = execute_transaction(self, cmd);
  g_free(cmd);
  return ret;
}

static PyObject *
client_commit(ClientObject *self, PyObject *args)
{
  (void)args;

  return execute_transaction(self, "COMMIT");
}

static PyObject *
client_connect(ClientObject *self, PyObject *args)
{
  (void)args;

  gpg_error_t rc;

  gchar *cwd = g_path_is_absolute(self->name) ? NULL : g_get_current_dir();
  gchar *sockpath = g_strconcat(
    cwd ? cwd : "",
    cwd && !g_str_has_suffix(cwd, "/") ? "/" : "",
    self->name,
    g_str_has_suffix(self->name, "/") ? "" : "/",
    CRA_SOCK_NAME,
    NULL);
  g_free(cwd);
  if (NULL == sockpath) {
    return PyErr_NoMemory();
  }

  assuan_release(self->ctx);
  rc = assuan_new(&self->ctx);
  if (rc) {
    PyErr_Format(PyExc_RuntimeError, "Failed to initialize Assuan context: %s", gpg_strerror(rc));
    g_free(sockpath);
    return NULL;
  }

  rc = assuan_socket_connect(self->ctx, sockpath, ASSUAN_INVALID_PID, 0);
  g_free(sockpath);
  if (rc) {
    PyErr_Format(PyExc_RuntimeError, "Failed to connect to server: %s", gpg_strerror(rc));
    return NULL;
  }

  Py_RETURN_NONE;
}

static PyObject *
client_disconnect(ClientObject *self, PyObject *args)
{
  (void)args;

  assuan_release(self->ctx);
  self->ctx = NULL;

  Py_RETURN_NONE;
}

static PyObject *
set_option(ClientObject *self, const char * option_name, int value)
{
  gchar * cmd;
  PyObject *res;

  cmd = g_strjoin(
    " ",
    "OPTION",
    option_name,
    value ? "1" : "0",
    NULL);
  if (!cmd) {
    return PyErr_NoMemory();
  }

  res = execute_transaction(self, cmd);
  g_free(cmd);
  return res;
}

static PyObject *
client_set_invalidate_dependants(ClientObject *self, PyObject *args)
{
  int invalidate_dependants;

  if (!PyArg_ParseTuple(args, "p", &invalidate_dependants)) {
    return NULL;
  }

  return set_option(self, "invalidate_dependants", invalidate_dependants);
}

static PyObject *
client_set_invalidate_family(ClientObject *self, PyObject *args)
{
  int invalidate_family;

  if (!PyArg_ParseTuple(args, "p", &invalidate_family)) {
    return NULL;
  }

  return set_option(self, "invalidate_family", invalidate_family);
}

static PyObject *
client_enter(ClientObject *self, PyObject *args)
{
  (void)args;

  PyObject *res = client_connect(self, NULL);
  if (NULL == res) {
    return NULL;
  }
  Py_DECREF(res);

  Py_INCREF(self);

  return (PyObject *)self;
}

static PyObject *
client_get_name(ClientObject *self, void *closure)
{
  (void)closure;

  return PyUnicode_FromString(self->name);
}

static struct PyMethodDef client_methods[] = {
  {"add", (PyCFunction)client_add, METH_VARARGS, NULL},
  {"commit", (PyCFunction)client_commit, METH_NOARGS, NULL},
  {"connect", (PyCFunction)client_connect, METH_NOARGS, NULL},
  {"disconnect", (PyCFunction)client_disconnect, METH_NOARGS, NULL},
  {"set_invalidate_dependants", (PyCFunction)client_set_invalidate_dependants, METH_VARARGS, NULL},
  {"set_invalidate_family", (PyCFunction)client_set_invalidate_family, METH_VARARGS, NULL},
  {"__enter__", (PyCFunction)client_enter, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction)client_disconnect, METH_VARARGS, NULL},
  {NULL, NULL, 0, NULL}
};

static struct PyGetSetDef client_properties[] = {
  {"name", (getter)client_get_name, NULL, NULL, NULL},
  {NULL, NULL, NULL, NULL, NULL}
};

PyTypeObject Client_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "createrepo_agent.Client",
  .tp_basicsize = sizeof(ClientObject),
  .tp_new = client_new,
  .tp_dealloc = (destructor)client_dealloc,
  .tp_init = (initproc)client_init,
  .tp_repr = (reprfunc)client_repr,
  .tp_methods = client_methods,
  .tp_getset = client_properties,
};
