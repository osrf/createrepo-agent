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

#include <signal.h>

#include <assuan.h>
#include <createrepo-agent/command.h>
#include <createrepo-agent/common.h>
#include <createrepo-agent/server.h>
#include <glib.h>
#include <Python.h>

#include "python/server.h"

typedef struct
{
  PyObject_HEAD
  assuan_fd_t fd;
  gchar * name;
  volatile sig_atomic_t sentinel;
  GThread * thread;
  GRWLock lock;
} ServerObject;

static PyObject *
server_shutdown_thread(ServerObject *self, PyObject *args);

static void * server_thread(ServerObject *self)
{
  g_rw_lock_reader_lock(&self->lock);

  if (0 == self->sentinel && ASSUAN_INVALID_FD != self->fd) {
    command_handler(self->fd, self->name, &self->sentinel);
  }

  g_rw_lock_reader_unlock(&self->lock);

  return NULL;
}

static PyObject *
server_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  (void)args;
  (void)kwds;

  ServerObject *self = (ServerObject *)type->tp_alloc(type, 0);
  if (self) {
    self->fd = ASSUAN_INVALID_FD;
    self->name = NULL;
    self->sentinel = 0;
    self->thread = NULL;
    g_rw_lock_init(&self->lock);
  }
  return (PyObject *)self;
}

static int
server_init(ServerObject *self, PyObject *args, PyObject *kwds)
{
  static char * keywords[] = {
    "name",
    NULL,
  };

  char *name = NULL;

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", keywords, &name)) {
    return -1;
  }

  g_rw_lock_reader_lock(&self->lock);

  if (ASSUAN_INVALID_FD != self->fd) {
    PyErr_SetString(PyExc_RuntimeError, "Server is already active");
    g_rw_lock_reader_unlock(&self->lock);
    return -1;
  }

  g_rw_lock_reader_unlock(&self->lock);

  g_rw_lock_writer_lock(&self->lock);

  if (NULL != self->name) {
    g_free(self->name);
  }

  self->name = g_strdup(name);
  if (NULL == self->name) {
    g_rw_lock_writer_unlock(&self->lock);
    PyErr_NoMemory();
    return -1;
  }

  g_rw_lock_writer_unlock(&self->lock);

  return 0;
}

static void
server_dealloc(ServerObject *self)
{
  Py_XDECREF(server_shutdown_thread(self, NULL));

  g_rw_lock_clear(&self->lock);
  if (NULL != self->name) {
    g_free(self->name);
  }

  Py_TYPE(self)->tp_free(self);
}

static PyObject *
server_repr(ServerObject *self)
{
  g_rw_lock_reader_lock(&self->lock);

  PyObject *res = PyUnicode_FromFormat(
    "<createrepo_agent.Server name='%s'>", self->name);

  g_rw_lock_reader_unlock(&self->lock);

  return res;
}

static PyObject *
server_shutdown_thread(ServerObject *self, PyObject *args)
{
  (void)args;

  g_rw_lock_reader_lock(&self->lock);

  if (ASSUAN_INVALID_FD == self->fd && NULL == self->thread) {
    g_rw_lock_reader_unlock(&self->lock);
    Py_RETURN_NONE;
  }

  self->sentinel = 1;

  if (ASSUAN_INVALID_FD != self->fd) {
    shutdown(self->fd, SHUT_RD);
  }

  Py_BEGIN_ALLOW_THREADS

  if (NULL != self->thread) {
    g_thread_ref(self->thread);
    g_thread_join(self->thread);
  }

  g_rw_lock_reader_unlock(&self->lock);

  g_rw_lock_writer_lock(&self->lock);

  if (ASSUAN_INVALID_FD != self->fd) {
    shutdown(self->fd, SHUT_RD);
    self->fd = ASSUAN_INVALID_FD;
  }

  if (NULL != self->thread) {
    g_thread_join(self->thread);
    self->thread = NULL;
  }

  self->sentinel = 0;

  g_rw_lock_writer_unlock(&self->lock);

  Py_END_ALLOW_THREADS

  Py_RETURN_NONE;
}

static PyObject *
server_start_thread(ServerObject *self, PyObject *args)
{
  (void)args;

  g_rw_lock_reader_lock(&self->lock);

  if (ASSUAN_INVALID_FD != self->fd) {
    PyErr_SetString(PyExc_RuntimeError, "Server is already active");
    g_rw_lock_reader_unlock(&self->lock);
    return NULL;
  }

  gchar *cwd = g_path_is_absolute(self->name) ? NULL : g_get_current_dir();
  gchar *sockpath = g_strconcat(
    cwd ? cwd : "",
    cwd && !g_str_has_suffix(cwd, "/") ? "/" : "",
    self->name,
    g_str_has_suffix(self->name, "/") ? "" : "/",
    CRA_SOCK_NAME,
    NULL);
  g_rw_lock_reader_unlock(&self->lock);
  g_free(cwd);
  if (NULL == sockpath) {
    return PyErr_NoMemory();
  }

  Py_BEGIN_ALLOW_THREADS

  g_rw_lock_writer_lock(&self->lock);

  self->fd = create_server_socket(sockpath);
  if (self->fd == ASSUAN_INVALID_FD && errno == EADDRINUSE) {
    gpg_error_t res = try_server(sockpath);
    if (res) {
      // TODO(cottsay): Better handling of redirected socket
      remove(sockpath);
      self->fd = create_server_socket(sockpath);
    } else {
      errno = EADDRINUSE;
    }
  }

  Py_END_ALLOW_THREADS

  if (ASSUAN_INVALID_FD == self->fd) {
    g_rw_lock_writer_unlock(&self->lock);
    PyErr_SetFromErrnoWithFilename(PyExc_OSError, sockpath);
    g_free(sockpath);
    return NULL;
  }
  g_free(sockpath);

  self->sentinel = 0;
  self->thread = g_thread_new(NULL, (GThreadFunc) & server_thread, self);
  if (!self->thread) {
    assuan_sock_close(self->fd);
    self->fd = ASSUAN_INVALID_FD;
    g_rw_lock_writer_unlock(&self->lock);
    PyErr_SetString(PyExc_RuntimeError, "Failed to start thread");
    return NULL;
  }

  g_rw_lock_writer_unlock(&self->lock);

  Py_RETURN_NONE;
}

static PyObject *
server_enter(ServerObject *self, PyObject *args)
{
  (void)args;

  PyObject *res = server_start_thread(self, NULL);
  if (NULL == res) {
    return NULL;
  }
  Py_DECREF(res);

  Py_INCREF(self);

  return (PyObject *)self;
}

static PyObject *
server_get_name(ServerObject *self, void *closure)
{
  (void)closure;

  g_rw_lock_reader_lock(&self->lock);

  PyObject *res = PyUnicode_FromString(self->name);

  g_rw_lock_reader_unlock(&self->lock);

  return res;
}

static struct PyMethodDef server_methods[] = {
  {"shutdown_thread", (PyCFunction)server_shutdown_thread, METH_NOARGS, NULL},
  {"start_thread", (PyCFunction)server_start_thread, METH_NOARGS, NULL},
  {"__enter__", (PyCFunction)server_enter, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction)server_shutdown_thread, METH_VARARGS, NULL},
  {NULL, NULL, 0, NULL}
};

static struct PyGetSetDef server_properties[] = {
  {"name", (getter)server_get_name, NULL, NULL, NULL},
  {NULL, NULL, NULL, NULL, NULL}
};

PyTypeObject Server_Type = {
  PyVarObject_HEAD_INIT(NULL, 0)
  .tp_name = "createrepo_agent.Server",
  .tp_basicsize = sizeof(ServerObject),
  .tp_new = server_new,
  .tp_dealloc = (destructor)server_dealloc,
  .tp_init = (initproc)server_init,
  .tp_repr = (reprfunc)server_repr,
  .tp_methods = server_methods,
  .tp_getset = server_properties,
};
