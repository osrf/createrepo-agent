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
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <gpgme.h>

#include "createrepo-cache/priv.h"
#include "createrepo-cache/repo_cache.h"

static const char package_dir[] = {
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
  'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '#', '#', '#', '#', '#',
  '#', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
  'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
  '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#', '#',
};

static void
cra_hash_table_union(GHashTable * hash_table, GHashTable * other)
{
  GHashTableIter iter;
  gpointer key;
  gpointer value;

  g_hash_table_iter_init(&iter, other);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    g_hash_table_replace(hash_table, key, value);
  }
}

static GHashTable *
cra_get_or_create_nested_set(GHashTable * hash_table, const gchar * key)
{
  GHashTable * nested_set;
  gchar * new_key;

  nested_set = g_hash_table_lookup(hash_table, key);
  if (!nested_set) {
    new_key = g_strdup(key);
    if (!new_key) {
      return NULL;
    }

    nested_set = g_hash_table_new(NULL, NULL);
    if (!nested_set) {
      g_free(new_key);
      return NULL;
    }

    g_hash_table_replace(hash_table, new_key, nested_set);
  }

  return nested_set;
}

static void
cra_package_cache_free(cra_PackageCache * pkg)
{
  size_t i;

  if (!pkg) {
    return;
  }

  for (i = 0; i < CR_XMLFILE_SENTINEL; i++) {
    g_free(pkg->chunk[i]);
  }

  g_free(pkg->path);
  cr_package_free(pkg->package);
  g_free(pkg);
}

static void
cra_xml_flush_task_clear(cra_XmlFlushTask * task)
{
  cr_repomd_record_free(task->record);
  task->record = NULL;

  task->rc = CRE_ERROR;
}

void
cra_repo_flush_task_clear(cra_RepoFlushTask * task)
{
  cr_repomd_free(task->repomd);
  task->repomd = NULL;

  cra_xml_flush_task_clear(&task->xml[CR_XMLFILE_OTHER]);
  cra_xml_flush_task_clear(&task->xml[CR_XMLFILE_FILELISTS]);
  cra_xml_flush_task_clear(&task->xml[CR_XMLFILE_PRIMARY]);

  task->rc = CRE_ERROR;
}

static void
cra_repo_cache_clear(cra_RepoCache * repo)
{
  cra_repo_flush_task_clear(&repo->flush_task);

  repo->flags = 0;

  g_hash_table_remove_all(repo->pending_rems);
  g_hash_table_remove_all(repo->pending_adds);
  g_hash_table_remove_all(repo->depends);
  g_hash_table_remove_all(repo->families);
  g_hash_table_remove_all(repo->names);
  g_hash_table_remove_all(repo->hrefs);
  g_list_free_full(repo->packages, (GDestroyNotify)cra_package_cache_free);
  repo->packages = NULL;

  cr_repomd_free(repo->repomd);
  repo->repomd = NULL;

  cr_repomd_free(repo->repomd_old);
  repo->repomd_old = NULL;
}

static void
cra_repo_cache_free(cra_RepoCache * repo)
{
  size_t i;

  if (!repo) {
    return;
  }

  cra_repo_cache_clear(repo);

  for (i = 0; i < CR_XMLFILE_SENTINEL; i++) {
    g_free(repo->flush_task.xml[i].type_name);
    g_free(repo->flush_task.xml[i].path);
  }

  g_hash_table_destroy(repo->pending_rems);
  g_hash_table_destroy(repo->pending_adds);
  g_hash_table_destroy(repo->depends);
  g_hash_table_destroy(repo->families);
  g_hash_table_destroy(repo->names);
  g_hash_table_destroy(repo->hrefs);
  g_free(repo->flush_task.repomd_asc_path);
  g_free(repo->flush_task.repomd_path);
  gpgme_key_unref(repo->key);
  g_free(repo->repomd_asc_path);
  g_free(repo->repomd_old_path);
  g_free(repo->repomd_path);
  g_free(repo->repodata_path);
  g_free(repo->path);
  g_free(repo);
}

static void
cra_arch_cache_clear(cra_ArchCache * arch)
{
  cra_repo_cache_clear(arch->debug_repo);
  cra_repo_cache_clear(arch->arch_repo);
}

static void
cra_arch_cache_free(cra_ArchCache * arch)
{
  if (!arch) {
    return;
  }

  cra_arch_cache_clear(arch);

  cra_repo_cache_free(arch->debug_repo);
  cra_repo_cache_free(arch->arch_repo);
  g_free(arch);
}

void
cra_cache_clear(cra_Cache * cache)
{
  GHashTableIter iter;
  cra_ArchCache * arch;

  g_hash_table_iter_init(&iter, cache->arches);
  while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&arch)) {
    cra_arch_cache_clear(arch);
  }

  cra_repo_cache_clear(cache->source_repo);
}

void
cra_cache_free(cra_Cache * cache)
{
  if (!cache) {
    return;
  }

  cra_cache_clear(cache);

  gpgme_release(cache->gpgme);

  g_hash_table_destroy(cache->arches);
  cra_repo_cache_free(cache->source_repo);
  g_free(cache->path);
  g_free(cache);
}

static cra_PackageCache *
cra_package_cache_new(cr_Package * package)
{
  cra_PackageCache * pkg;

  pkg = g_new0(cra_PackageCache, 1);
  if (!pkg) {
    return NULL;
  }

  pkg->package = package;

  return pkg;
}

cra_RepoCache *
cra_repo_cache_new(const char * path, const char * subdir)
{
  cra_RepoCache * repo;

  repo = g_new0(cra_RepoCache, 1);
  if (!repo) {
    return NULL;
  }

  repo->path = g_strconcat(path, subdir, "/", NULL);
  if (!repo->path) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->repodata_path = g_strconcat(repo->path, "repodata/", NULL);
  if (!repo->repodata_path) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->repomd_path = g_strconcat(repo->repodata_path, "repomd.xml", NULL);
  if (!repo->repomd_path) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->repomd_old_path = g_strconcat(repo->repodata_path, "repomd.old.xml", NULL);
  if (!repo->repomd_old_path) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->repomd_asc_path = g_strconcat(repo->repomd_path, ".asc", NULL);
  if (!repo->repomd_asc_path) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->flush_task.repo = repo;

  repo->flush_task.repomd_path = g_strconcat(repo->repodata_path, "repomd.new.xml", NULL);
  if (!repo->flush_task.repomd_path) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->flush_task.repomd_asc_path = g_strconcat(repo->flush_task.repomd_path, ".asc", NULL);
  if (!repo->flush_task.repomd_asc_path) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->hrefs = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
  if (!repo->hrefs) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->names = g_hash_table_new_full(
    g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_hash_table_destroy);
  if (!repo->names) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->families = g_hash_table_new_full(
    g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_hash_table_destroy);
  if (!repo->families) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->depends = g_hash_table_new_full(
    g_str_hash, g_str_equal, g_free, (GDestroyNotify)g_hash_table_destroy);
  if (!repo->depends) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->pending_adds = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  if (!repo->pending_adds) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  repo->pending_rems = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  if (!repo->pending_rems) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  #define _CRA_XML_FLUSH_TASK_INIT(_type, _name) ( \
    repo->flush_task.xml[_type].rc = CRE_ERROR, \
    repo->flush_task.xml[_type].repo = repo, \
    repo->flush_task.xml[_type].type = _type, \
    repo->flush_task.xml[_type].type_name = g_strdup(_name), \
    repo->flush_task.xml[_type].path = g_strconcat( \
      repo->path, "repodata/", _name, ".xml.gz", NULL), \
    repo->flush_task.xml[_type].type_name && repo->flush_task.xml[_type].path)

  if (!_CRA_XML_FLUSH_TASK_INIT(CR_XMLFILE_PRIMARY, "primary")) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  if (!_CRA_XML_FLUSH_TASK_INIT(CR_XMLFILE_FILELISTS, "filelists")) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  if (!_CRA_XML_FLUSH_TASK_INIT(CR_XMLFILE_OTHER, "other")) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  if (!_CRA_XML_FLUSH_TASK_INIT(CR_XMLFILE_PRESTODELTA, "prestodelta")) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  if (!_CRA_XML_FLUSH_TASK_INIT(CR_XMLFILE_UPDATEINFO, "updateinfo")) {
    cra_repo_cache_free(repo);
    return NULL;
  }

  return repo;
}

cra_Cache *
cra_cache_new(const char * path)
{
  cra_Cache * cache;
  gpgme_error_t rc;

  cache = g_new0(cra_Cache, 1);
  if (!cache) {
    return NULL;
  }

  cache->path = cr_normalize_dir_path(path);
  if (!cache->path) {
    cra_cache_free(cache);
    return NULL;
  }

  cache->source_repo = cra_repo_cache_new(cache->path, "SRPMS");
  if (!cache->source_repo) {
    cra_cache_free(cache);
    return NULL;
  }

  cache->arches = g_hash_table_new_full(
    g_str_hash, g_str_equal, g_free, (GDestroyNotify)cra_arch_cache_free);
  if (!cache->arches) {
    cra_cache_free(cache);
    return NULL;
  }

  rc = gpgme_new(&cache->gpgme);
  if (rc) {
    cra_cache_free(cache);
    return NULL;
  }

  rc = gpgme_set_protocol(cache->gpgme, GPGME_PROTOCOL_OpenPGP);
  if (rc) {
    cra_cache_free(cache);
    return NULL;
  }

  gpgme_set_armor(cache->gpgme, 1);

  return cache;
}

static int
cra_package_cache_node_cmp(cra_PackageCache * a, cra_PackageCache * b)
{
  return g_strcmp0(a->package->location_href, b->package->location_href);
}

static void
cra_package_cache_worker(cra_PackageCache * pkg, void * user_data)
{
  (void)user_data;

  pkg->chunk[CR_XMLFILE_PRIMARY] = cr_xml_dump_primary(pkg->package, NULL);
  pkg->chunk[CR_XMLFILE_FILELISTS] = cr_xml_dump_filelists(pkg->package, NULL);
  pkg->chunk[CR_XMLFILE_OTHER] = cr_xml_dump_other(pkg->package, NULL);
}

static void
cra_repo_cache_package_remove(cra_RepoCache * repo, GList * node)
{
  gchar * fullpath;
  cra_PackageCache * pkg = (cra_PackageCache *)node->data;
  GSList * dnode;
  cr_Dependency * dep;
  GHashTable * dset;
  GHashTable * names;

  // Steal the full path from the package object
  fullpath = pkg->path;
  pkg->path = NULL;

  g_debug("Removing package at %s", fullpath);

  for (dnode = pkg->package->requires; dnode; dnode = g_slist_next(dnode)) {
    dep = (cr_Dependency *)dnode->data;
    dset = g_hash_table_lookup(repo->depends, dep->name);
    if (dset) {
      if (g_hash_table_remove(dset, node) && !g_hash_table_size(dset)) {
        g_hash_table_remove(repo->depends, dep->name);
      }
    }
  }

  if (pkg->family && g_hash_table_remove(pkg->family, node) && !g_hash_table_size(pkg->family)) {
    g_hash_table_remove(repo->families, pkg->package->rpm_sourcerpm);
  }

  if (g_hash_table_lookup_extended(repo->names, pkg->package->name, NULL, (gpointer *)&names) &&
    g_hash_table_remove(names, node) && !g_hash_table_size(names))
  {
    g_hash_table_remove(repo->names, pkg->package->name);
  }

  g_hash_table_remove(repo->hrefs, pkg->package->location_href);

  repo->packages = g_list_remove_link(repo->packages, node);
  g_list_free_full(node, (GDestroyNotify)cra_package_cache_free);

  g_hash_table_remove(repo->pending_adds, fullpath);
  g_hash_table_add(repo->pending_rems, fullpath);
}

static cra_PackageCache *
cra_repo_cache_package_add(cra_RepoCache * repo, cr_Package * package)
{
  GList * node;
  GSList * dnode;
  cr_Dependency * dep;
  GHashTable * dset;
  GHashTable * names;
  gchar * dname;
  cra_PackageCache * pkg;

  pkg = cra_package_cache_new(package);
  if (!pkg) {
    return NULL;
  }

  pkg->path = g_strconcat(repo->path, package->location_href, NULL);
  if (!pkg->path) {
    cra_package_cache_free(pkg);
    return NULL;
  }

  node = g_list_alloc();
  if (!node) {
    cra_package_cache_free(pkg);
    return NULL;
  }

  node->data = pkg;

  g_hash_table_insert(repo->hrefs, package->location_href, node);

  names = cra_get_or_create_nested_set(repo->names, package->name);
  if (!names) {
    // TODO(cottsay): Handle rollback
    abort();
  }
  g_hash_table_add(names, node);

  if (package->rpm_sourcerpm && '\0' != package->rpm_sourcerpm[0]) {
    pkg->family = cra_get_or_create_nested_set(repo->families, package->rpm_sourcerpm);
    if (!pkg->family) {
      // TODO(cottsay): Handle rollback
      abort();
    }

    g_hash_table_add(pkg->family, node);
  }

  for (dnode = package->requires; dnode; dnode = g_slist_next(dnode)) {
    dep = (cr_Dependency *)dnode->data;
    dset = g_hash_table_lookup(repo->depends, dep->name);
    if (!dset) {
      dset = g_hash_table_new(NULL, NULL);
      if (!dset) {
        // TODO(cottsay): Handle rollback
        abort();
      }
      dname = g_strdup(dep->name);
      if (!dname) {
        // TODO(cottsay): Handle rollback
        abort();
      }
      g_hash_table_replace(repo->depends, dname, dset);
    }

    g_hash_table_add(dset, node);
  }

  if (repo->packages) {
    node->next = repo->packages;
    repo->packages->prev = node;
  }
  repo->packages = node;

  return pkg;
}

int
cra_repo_cache_populate(cra_RepoCache * repo, GHashTable * ht)
{
  GThreadPool * pool;
  GHashTableIter iter;
  GList * node;
  cr_Package * package;
  cra_PackageCache * pkg;

  pool = g_thread_pool_new(
    (GFunc)cra_package_cache_worker, NULL, (gint)g_get_num_processors(), TRUE, NULL);
  if (!pool) {
    return CRE_ERROR;
  }

  g_hash_table_iter_init(&iter, ht);
  while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&package)) {
    if (g_hash_table_contains(repo->hrefs, package->location_href)) {
      g_thread_pool_free(pool, TRUE, TRUE);
      cra_repo_cache_clear(repo);
      return CRE_EXISTS;
    }

    pkg = cra_repo_cache_package_add(repo, package);
    if (!pkg) {
      g_thread_pool_free(pool, TRUE, TRUE);
      cra_repo_cache_clear(repo);
      return CRE_MEMORY;
    }

    // The cra_RepoCache now owns the cr_Package
    g_hash_table_iter_steal(&iter);

    // Push to the XML generation pool
    g_thread_pool_push(pool, pkg, NULL);
  }

  g_thread_pool_free(pool, FALSE, TRUE);

  for (node = repo->packages; node; node = g_list_next(node)) {
    pkg = (cra_PackageCache *)node->data;
    if (
      NULL == pkg->chunk[CR_XMLFILE_PRIMARY] ||
      NULL == pkg->chunk[CR_XMLFILE_FILELISTS] ||
      NULL == pkg->chunk[CR_XMLFILE_OTHER])
    {
      cra_repo_cache_clear(repo);
      return CRE_ERROR;
    }
  }

  repo->packages = g_list_sort(repo->packages, (GCompareFunc)cra_package_cache_node_cmp);

  return CRE_OK;
}

static int
cra_repo_cache_load(cra_RepoCache * repo, gpgme_ctx_t gpgme)
{
  (void)gpgme;

  int rc;
  cr_Metadata * md;
  struct cr_MetadataLocation * ml;
  gpgme_data_t repomd_asc;
  gpgme_data_t repomd_xml;
  gpgme_error_t gpg_rc;
  gpgme_verify_result_t gpg_res;
  gpgme_signature_t gpg_sig;


  ml = cr_parse_repomd(repo->repomd_path, repo->path, 1);
  if (!ml) {
    return CRE_IO;
  }

  // TODO(cottsay): There is a small TOCTOU here. There isn't a compatible API between GPGME and
  //                createrepo_c that would allow me to check the data which was actually used.
  if (g_file_test(repo->repomd_asc_path, G_FILE_TEST_IS_REGULAR)) {
    gpg_rc = gpgme_data_new_from_file(&repomd_asc, repo->repomd_asc_path, 1);
    if (gpg_rc) {
      cr_metadatalocation_free(ml);
      return CRE_BADXMLREPOMD;
    }

    gpg_rc = gpgme_data_new_from_file(&repomd_xml, repo->repomd_path, 1);
    if (gpg_rc) {
      gpgme_data_release(repomd_asc);
      cr_metadatalocation_free(ml);
      return CRE_BADXMLREPOMD;
    }

    gpg_rc = gpgme_op_verify(gpgme, repomd_asc, repomd_xml, NULL);
    gpgme_data_release(repomd_xml);
    gpgme_data_release(repomd_asc);
    if (gpg_rc) {
      g_warning(
        "Failed to verify metadata signature '%s': %s",
        repo->repomd_asc_path, gpgme_strerror(gpg_rc));
      cr_metadatalocation_free(ml);
      return CRE_BADXMLREPOMD;
    }

    gpg_res = gpgme_op_verify_result(gpgme);
    gpg_sig = gpg_res->signatures;
    while (gpg_sig) {
      if (!gpg_sig->status) {
        break;
      }
      gpg_sig = gpg_sig->next;
    }

    if (!gpg_sig) {
      g_warning("No signatures could be verified in '%s'", repo->repomd_asc_path);
      cr_metadatalocation_free(ml);
      return CRE_BADXMLREPOMD;
    }

    if (gpg_sig->key) {
      gpgme_key_ref(gpg_sig->key);
      repo->key = gpg_sig->key;
    } else {
      gpg_rc = gpgme_get_key(gpgme, gpg_sig->fpr, &repo->key, 0);
      if (gpg_rc) {
        // This is curious. The signature was successfully verified, but we can't find the
        // public key that was used.
        g_warning("Failed to find key '%s': %s", gpg_sig->fpr, gpgme_strerror(gpg_rc));
      }
    }

    g_debug("Successfully verified '%s' with key '%s'", repo->repomd_path, gpg_sig->fpr);
  }

  md = cr_metadata_new(CR_HT_KEY_FILENAME, 0, NULL);
  if (!md) {
    cr_metadatalocation_free(ml);
    return CRE_MEMORY;
  }

  rc = cr_metadata_load_xml(md, ml, NULL);
  if (rc) {
    cr_metadata_free(md);
    cr_metadatalocation_free(ml);
    return rc;
  }

#if CR_VERSION_MAJOR > 0 || CR_VERSION_MINOR >= 18
  repo->repomd = cr_repomd_copy(ml->repomd_data);
#else
  repo->repomd = cr_repomd_new();
  if (repo->repomd) {
    rc = cr_xml_parse_repomd(repo->repomd_path, repo->repomd, NULL, NULL, NULL);
    if (rc) {
      cr_metadata_free(md);
      cr_metadatalocation_free(ml);
      return rc;
    }
  }
#endif
  cr_metadatalocation_free(ml);
  if (!repo->repomd) {
    cr_metadata_free(md);
    return CRE_MEMORY;
  }

  repo->repomd_old = cr_repomd_new();
  if (!repo->repomd_old) {
    cr_metadata_free(md);
    cra_repo_cache_clear(repo);
    return CRE_MEMORY;
  }

  // It's OK if this fails - it probably means that there isn't any
  // old metadata to keep track of.
  cr_xml_parse_repomd(repo->repomd_old_path, repo->repomd_old, NULL, NULL, NULL);

  rc = cra_repo_cache_populate(repo, cr_metadata_hashtable(md));
  cr_metadata_free(md);
  if (rc) {
    return rc;
  }

  repo->flags |= CRA_REPO_LOADED;

  g_debug("Successfully loaded metadata from %s", repo->path);

  return CRE_OK;
}

static int
cra_repo_cache_realize(cra_RepoCache * repo, gpgme_ctx_t gpgme)
{
  if (repo->flags & CRA_REPO_LOADED) {
    return CRE_OK;
  }

  // If the repo doesn't exist, that's OK. We'll create it if necessary.
  if (!g_file_test(repo->repomd_path, G_FILE_TEST_IS_REGULAR)) {
    return CRE_OK;
  }

  return cra_repo_cache_load(repo, gpgme);
}

cra_ArchCache *
cra_arch_cache_get_or_create(cra_Cache * cache, const char * arch_name)
{
  cra_ArchCache * arch;
  gchar * key;

  arch = g_hash_table_lookup(cache->arches, arch_name);
  if (arch) {
    return arch;
  }

  arch = g_new0(cra_ArchCache, 1);
  if (!arch) {
    return NULL;
  }

  arch->arch_repo = cra_repo_cache_new(cache->path, arch_name);
  if (!arch->arch_repo) {
    cra_arch_cache_free(arch);
    return NULL;
  }

  key = g_strconcat(arch_name, "/debug", NULL);
  if (!key) {
    cra_arch_cache_free(arch);
    return NULL;
  }

  arch->debug_repo = cra_repo_cache_new(cache->path, key);
  g_free(key);
  if (!arch->debug_repo) {
    cra_arch_cache_free(arch);
    return NULL;
  }

  key = g_strdup(arch_name);
  if (!key) {
    cra_arch_cache_free(arch);
    return NULL;
  }

  g_hash_table_insert(cache->arches, key, arch);

  return arch;
}

int
cra_cache_realize(cra_Cache * cache, const char * arch_name)
{
  cra_ArchCache * arch;
  int rc;

  if (NULL == arch_name) {
    return cra_repo_cache_realize(cache->source_repo, cache->gpgme);
  }

  arch = cra_arch_cache_get_or_create(cache, arch_name);
  if (!arch) {
    return CRE_MEMORY;
  }

  rc = cra_repo_cache_realize(arch->arch_repo, cache->gpgme);
  if (rc) {
    return rc;
  }

  return cra_repo_cache_realize(arch->debug_repo, cache->gpgme);
}

int
cra_cache_touch(cra_Cache * cache, const char * arch_name)
{
  cra_ArchCache * arch;

  if (NULL == arch_name) {
    cache->source_repo->flags |= CRA_REPO_DIRTY;
    return CRE_OK;
  }

  arch = g_hash_table_lookup(cache->arches, arch_name);
  if (!arch) {
    return CRE_NOFILE;
  }

  arch->arch_repo->flags |= CRA_REPO_DIRTY;
  arch->debug_repo->flags |= CRA_REPO_DIRTY;

  return CRE_OK;
}

static int
cra_repo_cache_reload(cra_RepoCache * repo, gpgme_ctx_t gpgme)
{
  if (!(repo->flags & CRA_REPO_LOADED)) {
    return CRE_OK;
  }

  cra_repo_cache_clear(repo);

  return cra_repo_cache_load(repo, gpgme);
}

int
cra_cache_reload(cra_Cache * cache)
{
  int rc;
  GHashTableIter iter;
  cra_ArchCache * arch;

  rc = cra_repo_cache_reload(cache->source_repo, cache->gpgme);
  if (rc) {
    return rc;
  }

  g_hash_table_iter_init(&iter, cache->arches);
  while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&arch)) {
    rc = cra_repo_cache_reload(arch->arch_repo, cache->gpgme);
    if (rc) {
      return rc;
    }

    rc = cra_repo_cache_reload(arch->debug_repo, cache->gpgme);
    if (rc) {
      return rc;
    }
  }

  return CRE_OK;
}

static gboolean
cra_package_is_debug(const cr_Package * pkg)
{
  return g_str_has_suffix(pkg->name, "-debuginfo") || g_str_has_suffix(pkg->name, "-debugsource");
}

int
cra_cache_package_add(cra_Cache * cache, const char * arch_name, cr_Package * package)
{
  cra_ArchCache * arch;
  cra_RepoCache * repo;
  cra_PackageCache * pkg;
  gchar * chunk_primary;
  gchar * chunk_filelists;
  gchar * chunk_other;
  gchar * fullpath_old;
  gchar * fullpath_new;
  gchar * href_old;
  gchar * href_new;
  gchar * base_old;

  if (NULL == arch_name) {
    if (g_strcmp0("src", package->arch)) {
      return CRE_BADARG;
    }
    repo = cache->source_repo;
  } else if (!g_strcmp0("src", package->arch)) {
    return CRE_BADARG;
  } else {
    arch = g_hash_table_lookup(cache->arches, arch_name);
    if (!arch) {
      return CRE_BADARG;
    }

    if (cra_package_is_debug(package)) {
      repo = arch->debug_repo;
    } else {
      repo = arch->arch_repo;
    }
  }

  if (!package->location_base || !package->location_href) {
    return CRE_BADARG;
  }

  fullpath_old = g_build_path(
    G_DIR_SEPARATOR_S, package->location_base, package->location_href, NULL);
  if (!fullpath_old) {
    return CRE_MEMORY;
  }
  if (!g_file_test(fullpath_old, G_FILE_TEST_IS_REGULAR)) {
    g_free(fullpath_old);
    return CRE_NOFILE;
  }

  href_new = g_strconcat("Packages///", cr_get_filename(fullpath_old), NULL);
  if (!href_new) {
    g_free(fullpath_old);
    return CRE_MEMORY;
  }
  href_new[9] = package_dir[(unsigned char)href_new[11]];

  if (g_hash_table_contains(repo->hrefs, href_new)) {
    g_free(href_new);
    g_free(fullpath_old);
    return CRE_EXISTS;
  }

  fullpath_new = g_strconcat(repo->path, href_new, NULL);
  if (!fullpath_new) {
    g_free(href_new);
    g_free(fullpath_old);
    return CRE_MEMORY;
  }

  href_old = package->location_href;
  if (g_strcmp0(href_old, href_new)) {
    package->location_href = g_string_chunk_insert(package->chunk, href_new);
    if (!package->location_href) {
      package->location_href = href_old;
      g_free(fullpath_new);
      g_free(href_new);
      g_free(fullpath_old);
      return CRE_MEMORY;
    }
  }
  g_free(href_new);

  base_old = package->location_base;
  package->location_base = NULL;

  chunk_primary = cr_xml_dump_primary(package, NULL);
  chunk_filelists = cr_xml_dump_filelists(package, NULL);
  chunk_other = cr_xml_dump_other(package, NULL);
  if (!chunk_primary || !chunk_filelists || !chunk_other) {
    package->location_base = base_old;
    package->location_href = href_old;
    g_free(chunk_other);
    g_free(chunk_filelists);
    g_free(chunk_primary);
    g_free(fullpath_new);
    g_free(fullpath_old);
    return CRE_MEMORY;
  }

  pkg = cra_repo_cache_package_add(repo, package);
  if (!pkg) {
    package->location_base = base_old;
    package->location_href = href_old;
    g_free(chunk_other);
    g_free(chunk_filelists);
    g_free(chunk_primary);
    g_free(fullpath_new);
    g_free(fullpath_old);
    return CRE_MEMORY;
  }

  // The cache now owns the package

  pkg->chunk[CR_XMLFILE_PRIMARY] = chunk_primary;
  pkg->chunk[CR_XMLFILE_FILELISTS] = chunk_filelists;
  pkg->chunk[CR_XMLFILE_OTHER] = chunk_other;

  g_hash_table_remove(repo->pending_rems, fullpath_new);

  if (g_strcmp0(fullpath_new, fullpath_old)) {
    g_hash_table_replace(repo->pending_adds, fullpath_new, fullpath_old);
  } else {
    g_free(fullpath_new);
    g_free(fullpath_old);
  }

  repo->packages = g_list_sort(
    repo->packages, (GCompareFunc)cra_package_cache_node_cmp);

  repo->flags |= CRA_REPO_DIRTY;

  g_debug(
    "Added package '%s' for arch '%s'", package->name, arch_name ? arch_name : "SRPMS");

  return CRE_OK;
}

static gboolean
cra_expand_node_list_by_family(
  cra_RepoCache * repo, GHashTable * in, GHashTable * out, GHashTable * tmp)
{
  GHashTableIter iter;
  GList * node;
  cra_PackageCache * pkg;
  guint out_size;
  GHashTable * family_set;

  if (0 == g_hash_table_size(in)) {
    return FALSE;
  }

  g_hash_table_iter_init(&iter, in);
  while (g_hash_table_iter_next(&iter, (gpointer *)&node, NULL)) {
    pkg = (cra_PackageCache *)node->data;
    if (pkg->family && g_hash_table_lookup_extended(
        repo->families, pkg->package->rpm_sourcerpm, NULL, (gpointer *)&family_set))
    {
      g_hash_table_add(tmp, family_set);
    }
  }

  out_size = g_hash_table_size(out);
  g_hash_table_iter_init(&iter, tmp);
  while (g_hash_table_iter_next(&iter, (gpointer *)&family_set, NULL)) {
    cra_hash_table_union(out, family_set);
  }

  g_hash_table_remove_all(tmp);

  return g_hash_table_size(out) > out_size ? TRUE : FALSE;
}

static gboolean
cra_expand_node_list_by_depends(
  cra_RepoCache * repo, GHashTable * in, GHashTable * out, GHashTable * tmp)
{
  GHashTableIter iter;
  GList * node;
  cra_PackageCache * pkg;
  guint out_size;
  gpointer deps;
  gpointer name;

  if (0 == g_hash_table_size(in)) {
    return FALSE;
  }

  g_hash_table_iter_init(&iter, in);
  while (g_hash_table_iter_next(&iter, (gpointer *)&node, NULL)) {
    pkg = (cra_PackageCache *)node->data;
    g_hash_table_add(tmp, pkg->package->name);
  }

  out_size = g_hash_table_size(out);
  g_hash_table_iter_init(&iter, tmp);
  while (g_hash_table_iter_next(&iter, &name, NULL)) {
    if (g_hash_table_lookup_extended(repo->depends, name, NULL, &deps)) {
      cra_hash_table_union(out, deps);
    }
  }

  g_hash_table_remove_all(tmp);

  return g_hash_table_size(out) > out_size ? TRUE : FALSE;
}

static int
cra_cache_invalidate_and_remove(
  cra_Cache * cache, cra_ArchCache * arch, GHashTable * to_remove,
  gboolean family, gboolean dependants)
{
  cra_RepoCache * repo = NULL == arch ? cache->source_repo : arch->arch_repo;
  cra_RepoCache * debug_repo = NULL == arch ? NULL : arch->debug_repo;
  GHashTable * tmp = NULL;
  GHashTable * to_remove_debug = NULL;
  GList * node;
  GHashTableIter iter;

  if (!g_hash_table_size(to_remove)) {
    return CRE_NOFILE;
  }

  if (arch && (family || dependants)) {
    tmp = g_hash_table_new(NULL, NULL);
    if (!tmp) {
      return CRE_MEMORY;
    }

    if (family) {
      if (debug_repo) {
        to_remove_debug = g_hash_table_new(NULL, NULL);
        if (!to_remove_debug) {
          g_hash_table_destroy(tmp);
          return CRE_MEMORY;
        }
      }

      cra_expand_node_list_by_family(repo, to_remove, to_remove, tmp);
    }

    while (dependants) {
      dependants &= cra_expand_node_list_by_depends(repo, to_remove, to_remove, tmp);
      if (dependants && family) {
        cra_expand_node_list_by_family(repo, to_remove, to_remove, tmp);
      }
    }

    if (to_remove_debug) {
      if (cra_expand_node_list_by_family(debug_repo, to_remove, to_remove_debug, tmp)) {
        debug_repo->flags |= CRA_REPO_DIRTY;

        g_hash_table_iter_init(&iter, to_remove_debug);
        while (g_hash_table_iter_next(&iter, (gpointer *)&node, NULL)) {
          cra_repo_cache_package_remove(debug_repo, node);
        }
      }

      g_hash_table_destroy(to_remove_debug);
    }

    g_hash_table_destroy(tmp);
  }

  repo->flags |= CRA_REPO_DIRTY;

  g_hash_table_iter_init(&iter, to_remove);
  while (g_hash_table_iter_next(&iter, (gpointer *)&node, NULL)) {
    cra_repo_cache_package_remove(repo, node);
  }

  return CRE_OK;
}

int
cra_cache_name_remove(
  cra_Cache * cache, const char * arch_name, const char * name,
  gboolean family, gboolean dependants)
{
  cra_RepoCache * repo;
  cra_ArchCache * arch = NULL;
  GHashTable * to_remove;
  GHashTable * names;
  int rc;

  if (!arch_name) {
    repo = cache->source_repo;
  } else {
    arch = g_hash_table_lookup(cache->arches, arch_name);
    if (!arch) {
      return CRE_BADARG;
    }
    repo = arch->arch_repo;
  }

  names = g_hash_table_lookup(repo->names, name);
  if (!names) {
    return CRE_NOFILE;
  }

  to_remove = g_hash_table_new(NULL, NULL);
  if (!to_remove) {
    return CRE_MEMORY;
  }

  cra_hash_table_union(to_remove, names);

  rc = cra_cache_invalidate_and_remove(cache, arch, to_remove, family, dependants);

  g_hash_table_destroy(to_remove);

  return rc;
}

int
cra_cache_pattern_remove(
  cra_Cache * cache, const char * arch_name, const GRegex * pattern,
  gboolean family, gboolean dependants)
{
  cra_RepoCache * repo;
  cra_ArchCache * arch = NULL;
  GHashTable * to_remove;
  GList * node;
  cra_PackageCache * pkg;
  int rc;

  if (!arch_name) {
    repo = cache->source_repo;
  } else {
    arch = g_hash_table_lookup(cache->arches, arch_name);
    if (!arch) {
      return CRE_BADARG;
    }
    repo = arch->arch_repo;
  }

  to_remove = g_hash_table_new(NULL, NULL);
  if (!to_remove) {
    return CRE_MEMORY;
  }

  for (node = repo->packages; node; node = g_list_next(node)) {
    pkg = (cra_PackageCache *)node->data;
    if (g_regex_match(pattern, pkg->package->name, 0, NULL)) {
      g_hash_table_add(to_remove, node);
    }
  }

  rc = cra_cache_invalidate_and_remove(cache, arch, to_remove, family, dependants);

  g_hash_table_destroy(to_remove);

  return rc;
}

static void
cra_xml_flush_worker(cra_XmlFlushTask * task, void * user_data)
{
  (void)user_data;

  cr_XmlFile * f;
  cr_XmlFileType type = task->type;
  cr_ContentStat * stat;
  GList * node = task->repo->packages;
  int rc = CRE_OK;

  /*
   * Step 1.1: Write the XML file
   */

  rc = g_mkdir_with_parents(task->repo->repodata_path, 0755);
  if (0 != rc) {
    task->rc = CRE_IO;
    return;
  }

  stat = cr_contentstat_new(CR_CHECKSUM_SHA256, NULL);
  if (!stat) {
    task->rc = CRE_MEMORY;
    return;
  }

  f = cr_xmlfile_sopen(task->path, task->type, CR_CW_GZ_COMPRESSION, stat, NULL);
  if (!f) {
    cr_contentstat_free(stat, NULL);
    task->rc = CRE_IO;
    return;
  }

  rc = cr_xmlfile_set_num_of_pkgs(f, g_list_length(node), NULL);

  for (; node && !rc; node = g_list_next(node)) {
    cra_PackageCache * package = (cra_PackageCache *)node->data;
    rc = cr_xmlfile_add_chunk(f, package->chunk[type], NULL);
  }

  task->rc = cr_xmlfile_close(f, NULL);
  if (task->rc) {
    cr_contentstat_free(stat, NULL);
    return;
  }

  if (rc) {
    cr_contentstat_free(stat, NULL);
    task->rc = rc;
    return;
  }

  /*
   * Step 1.2: Create and fill the repomd record
   */

  task->record = cr_repomd_record_new(task->type_name, task->path);
  if (!task->record) {
    cr_contentstat_free(stat, NULL);
    task->rc = CRE_MEMORY;
    return;
  }

  cr_repomd_record_load_contentstat(task->record, stat);
  cr_contentstat_free(stat, NULL);
  task->rc = cr_repomd_record_fill(task->record, CR_CHECKSUM_SHA256, NULL);
  if (task->rc) {
    return;
  }

  /*
   * Step 1.3: Rename the XML file to include the hash
   */

  task->rc = cr_repomd_record_rename_file(task->record, NULL);
}

static int
cra_xml_write_repomd(cr_Repomd * repomd, const char * path)
{
  char * data;
  FILE * f;

  data = cr_xml_dump_repomd(repomd, NULL);
  if (!data) {
    return CRE_ERROR;
  }

  f = fopen(path, "w");
  if (!f) {
    g_free(data);
    return CRE_IO;
  }

  fputs(data, f);
  fclose(f);
  g_free(data);

  return CRE_OK;
}

static void
cra_repomd_flush_worker(cra_RepoFlushTask * task, gpointer user_data)
{
  (void)user_data;

  /*
   * Step 2.0: Check previous step for success
   */

  if (task->xml[CR_XMLFILE_PRIMARY].rc) {
    task->rc = task->xml[CR_XMLFILE_PRIMARY].rc;
    return;
  }
  if (task->xml[CR_XMLFILE_FILELISTS].rc) {
    task->rc = task->xml[CR_XMLFILE_FILELISTS].rc;
    return;
  }
  if (task->xml[CR_XMLFILE_OTHER].rc) {
    task->rc = task->xml[CR_XMLFILE_OTHER].rc;
    return;
  }

  /*
   * Step 2.1: Generate the new repomd
   */

  task->repomd = cr_repomd_new();
  if (!task->repomd) {
    task->rc = CRE_MEMORY;
    return;
  }

  // The repomd claims ownership of the records. Reset the xml flush tasks
  // for next time.
  cr_repomd_set_record(task->repomd, task->xml[CR_XMLFILE_PRIMARY].record);
  task->xml[CR_XMLFILE_PRIMARY].record = NULL;
  task->xml[CR_XMLFILE_PRIMARY].rc = CRE_ERROR;
  cr_repomd_set_record(task->repomd, task->xml[CR_XMLFILE_FILELISTS].record);
  task->xml[CR_XMLFILE_FILELISTS].record = NULL;
  task->xml[CR_XMLFILE_FILELISTS].rc = CRE_ERROR;
  cr_repomd_set_record(task->repomd, task->xml[CR_XMLFILE_OTHER].record);
  task->xml[CR_XMLFILE_OTHER].record = NULL;
  task->xml[CR_XMLFILE_OTHER].rc = CRE_ERROR;

  cr_repomd_sort_records(task->repomd);

  /*
   * Step 2.2: Write the repomd file to disk
   */
  task->rc = cra_xml_write_repomd(task->repomd, task->repomd_path);
}

static void
cra_repomd_record_steal(cr_Repomd * src, cr_Repomd * dst, const char * type)
{
  cr_RepomdRecord * record;

  record = cr_repomd_get_record(src, type);
  if (!record) {
    return;
  }

  cr_repomd_detach_record(src, record);
  record->type = record->location_href;
  cr_repomd_set_record(dst, record);
}

static int
cra_repomd_record_stamp_cmp(cr_RepomdRecord * a, cr_RepomdRecord * b)
{
  if (a->timestamp < b->timestamp) {
    return 1;
  } else if (a->timestamp > b->timestamp) {
    return -1;
  }

  return 0;
}

static int
move_file(const char * src, const char * dst)
{
  int rc;
  gchar * parent;

  rc = rename(src, dst);
  if (!rc) {
    return rc;
  }

  if (errno == EEXIST && (rc = remove(dst))) {
    return rc;
  } else if (errno == ENOENT) {
    parent = g_path_get_dirname(dst);
    if (!parent) {
      errno = ENOMEM;
      return -1;
    }
    rc = g_mkdir_with_parents(parent, 0755);
    g_free(parent);
    if (rc) {
      return rc;
    }
  }

  return rename(src, dst);
}

static int
cra_curate_old_repomd(cr_Repomd * repomd, gchar * path, gint64 expired)
{
  GSList * curr;
  gchar * location_real;
  cr_RepomdRecord * record;
  uint8_t have_primary = 0;
  uint8_t have_filelists = 0;
  uint8_t have_other = 0;

  // Sort by timestamp (oldest last)
  repomd->records = g_slist_sort(repomd->records, (GCompareFunc)cra_repomd_record_stamp_cmp);

  curr = repomd->records;
  while (curr) {
    record = (cr_RepomdRecord *)curr->data;
    if (record->timestamp < expired) {
      if (strstr(record->type, "primary")) {
        if (have_primary) {
          record->timestamp = 0;
        } else {
          have_primary = 1;
        }
      } else if (strstr(record->type, "filelists")) {
        if (have_filelists) {
          record->timestamp = 0;
        } else {
          have_filelists = 1;
        }
      } else if (strstr(record->type, "other")) {
        if (have_other) {
          record->timestamp = 0;
        } else {
          have_other = 1;
        }
      }

      if (!record->timestamp) {
        curr = g_slist_next(curr);
        location_real = g_strconcat(path, record->location_href, NULL);
        if (!location_real) {
          return CRE_MEMORY;
        }
        if (remove(location_real)) {
          g_free(location_real);
          return CRE_IO;
        }
        g_free(location_real);
        cr_repomd_remove_record(repomd, record->type);
        continue;
      }
    }
    curr = g_slist_next(curr);
  }

  return CRE_OK;
}

static void
cra_repo_commit_worker(cra_RepoFlushTask * task, void * user_data)
{
  (void)user_data;

  gint64 expired;
  cr_RepomdRecord * record;
  GHashTableIter iter;
  int rc;
  char * src;
  char * dst;

  /*
   * Step 4.1: Mark existing metadata as 'old'
   */

  cra_repomd_record_steal(task->repo->repomd, task->repo->repomd_old, "primary");
  cra_repomd_record_steal(task->repo->repomd, task->repo->repomd_old, "filelists");
  cra_repomd_record_steal(task->repo->repomd, task->repo->repomd_old, "other");
  // Un-mark any of the new files just in case we flip-flop'd or no-op'd
  record = cr_repomd_get_record(task->repomd, "primary");
  if (record) {
    cr_repomd_remove_record(task->repo->repomd_old, record->location_href);
  }
  record = cr_repomd_get_record(task->repomd, "filelists");
  if (record) {
    cr_repomd_remove_record(task->repo->repomd_old, record->location_href);
  }
  record = cr_repomd_get_record(task->repomd, "other");
  if (record) {
    cr_repomd_remove_record(task->repo->repomd_old, record->location_href);
  }
  cr_repomd_free(task->repo->repomd);
  task->repo->repomd = task->repomd;
  task->repomd = NULL;

  /*
   * Step 4.2: Move new package files into place
   */

  g_hash_table_iter_init(&iter, task->repo->pending_adds);
  while (g_hash_table_iter_next(&iter, (gpointer *)&dst, (gpointer *)&src)) {
    if (move_file(src, dst)) {
      g_warning("Failed to move file %s => %s (%d): %s", src, dst, errno, strerror(errno));
      task->rc = CRE_IO;
      return;
    }
    g_hash_table_iter_remove(&iter);
  }

  /*
   * Step 4.3: Move new repomd file into place
   */

  if (move_file(task->repomd_path, task->repo->repomd_path)) {
    task->rc = CRE_IO;
    return;
  }

  if (task->repo->key && move_file(task->repomd_asc_path, task->repo->repomd_asc_path)) {
    task->rc = CRE_IO;
    return;
  }

  /*
   * Step 4.4: Delete removed packages
   */

  g_hash_table_iter_init(&iter, task->repo->pending_rems);
  while (g_hash_table_iter_next(&iter, (gpointer *)&dst, NULL)) {
    if ((rc = remove(dst))) {
      g_warning("Failed to remove file %s (%d): %s", dst, rc, strerror(rc));
      task->rc = CRE_IO;
      return;
    }
    g_hash_table_iter_remove(&iter);
  }

  /*
   * Step 4.5: Record and delete old metadata
   *
   * We keep 1 entry of each type older than 2 minutes and discard the rest.
   */

  // If there is no old repodata, skip
  if (!task->repo->repomd_old) {
    task->rc = CRE_OK;
    return;
  }

  // Base the expiration stamp off from the new primary.xml
  record = cr_repomd_get_record(task->repo->repomd, "primary");
  if (!record) {
    task->rc = CRE_ASSERT;
    return;
  }
  expired = record->timestamp - 120;

  task->rc = cra_curate_old_repomd(task->repo->repomd_old, task->repo->path, expired);
  if (task->rc) {
    return;
  }

  task->rc = cra_xml_write_repomd(task->repo->repomd_old, task->repo->repomd_old_path);
}

static gpg_error_t
cra_sign_repomd(
  gpgme_ctx_t gpgme, gpgme_key_t key, const char * repomd_path, const char * repomd_asc_path)
{
  FILE * f;
  gpg_error_t rc;
  gpgme_data_t repomd_asc;
  gpgme_data_t repomd_xml;

  rc = gpgme_signers_add(gpgme, key);
  if (rc) {
    return rc;
  }

  f = fopen(repomd_asc_path, "wb");
  if (!f) {
    rc = gpg_error(gpg_err_code_from_errno(errno));
    g_warning("Failed to open %s: %s", repomd_asc_path, gpg_strerror(rc));
    gpgme_signers_clear(gpgme);
    return rc;
  }

  rc = gpgme_data_new_from_stream(&repomd_asc, f);
  if (rc) {
    g_warning("Failed to open repomd.xml.asc file: %s", gpgme_strerror(rc));
    fclose(f);
    gpgme_signers_clear(gpgme);
    return rc;
  }

  rc = gpgme_data_new_from_file(&repomd_xml, repomd_path, 1);
  if (rc) {
    g_warning("Failed to open %s: %s", repomd_path, gpgme_strerror(rc));
    gpgme_data_release(repomd_asc);
    fclose(f);
    gpgme_signers_clear(gpgme);
    return rc;
  }

  rc = gpgme_op_sign(gpgme, repomd_xml, repomd_asc, GPGME_SIG_MODE_DETACH);
  gpgme_data_release(repomd_asc);
  gpgme_data_release(repomd_xml);
  fclose(f);
  gpgme_signers_clear(gpgme);
  if (rc) {
    g_warning("Failed to sign metadata: %s", gpgme_strerror(rc));
    return rc;
  }

  gpgme_signers_clear(gpgme);

  return 0;
}

int
cra_cache_flush(cra_Cache * cache)
{
  int rc;
  const char * arch_name;
  cra_ArchCache * arch;
  cra_RepoFlushTask * task;
  GHashTableIter iter;
  GThreadPool * pool;
  GSList * dirty = NULL;
  GSList * curr;

  /*
   * Step 0: Determine which repositories need to be flushed.
   */

  if (cache->source_repo->flags & CRA_REPO_DIRTY) {
    dirty = g_slist_prepend(dirty, &cache->source_repo->flush_task);
    g_debug("Starting flush for 'SRPMS'");
  }

  g_hash_table_iter_init(&iter, cache->arches);
  while (g_hash_table_iter_next(&iter, (gpointer *)&arch_name, (gpointer *)&arch)) {
    if (arch->arch_repo->flags & CRA_REPO_DIRTY) {
      dirty = g_slist_prepend(dirty, &arch->arch_repo->flush_task);
      g_debug("Starting flush for '%s'", arch_name);
    }
    if (arch->debug_repo->flags & CRA_REPO_DIRTY) {
      dirty = g_slist_prepend(dirty, &arch->debug_repo->flush_task);
      g_debug("Starting flush for '%s' (debug)", arch_name);
    }
  }

  // Nothing to do?
  if (NULL == dirty) {
    return CRE_OK;
  }

  /*
   * Step 1: Write the metadata XML files
   */

  pool = g_thread_pool_new(
    (GFunc)cra_xml_flush_worker, NULL, (gint)g_get_num_processors(), FALSE, NULL);
  if (!pool) {
    g_slist_free(dirty);
    return CRE_ERROR;
  }

  for (curr = dirty; curr; curr = g_slist_next(curr)) {
    task = (cra_RepoFlushTask *)curr->data;
    g_thread_pool_push(pool, &task->xml[CR_XMLFILE_PRIMARY], NULL);
    g_thread_pool_push(pool, &task->xml[CR_XMLFILE_FILELISTS], NULL);
    g_thread_pool_push(pool, &task->xml[CR_XMLFILE_OTHER], NULL);
  }

  g_thread_pool_free(pool, FALSE, TRUE);

  /*
   * Step 2: Write the repomd files
   */

  pool = g_thread_pool_new(
    (GFunc)cra_repomd_flush_worker, NULL, (gint)g_get_num_processors(), FALSE, NULL);
  if (!pool) {
    g_slist_free_full(dirty, (GDestroyNotify)cra_repo_flush_task_clear);
    return CRE_ERROR;
  }

  for (curr = dirty; curr; curr = g_slist_next(curr)) {
    g_thread_pool_push(pool, curr->data, NULL);
  }

  g_thread_pool_free(pool, FALSE, TRUE);

  /*
   * Step 3: Sanity check and signing
   */

  for (curr = dirty; curr; curr = g_slist_next(curr)) {
    task = (cra_RepoFlushTask *)curr->data;
    if (task->rc) {
      rc = task->rc;
      g_slist_free_full(dirty, (GDestroyNotify)cra_repo_flush_task_clear);
      return rc;
    }
    if (task->repo->key) {
      if (cra_sign_repomd(
          cache->gpgme, task->repo->key, task->repomd_path, task->repomd_asc_path))
      {
        rc = CRE_BADXMLREPOMD;
        g_slist_free_full(dirty, (GDestroyNotify)cra_repo_flush_task_clear);
        return rc;
      }

      g_debug("Successfully signed metadata: %s", task->repo->repomd_asc_path);
    }
    task->rc = CRE_ERROR;
  }

  /*
   * Step 4: Commit results
   */

  pool = g_thread_pool_new(
    (GFunc)cra_repo_commit_worker, NULL, (gint)g_get_num_processors(), FALSE, NULL);
  if (!pool) {
    g_slist_free_full(dirty, (GDestroyNotify)cra_repo_flush_task_clear);
    return CRE_ERROR;
  }

  for (curr = dirty; curr; curr = g_slist_next(curr)) {
    g_thread_pool_push(pool, curr->data, NULL);
  }

  g_thread_pool_free(pool, FALSE, TRUE);

  /*
   * Verify success
   */

  for (curr = dirty; curr; curr = g_slist_next(curr)) {
    task = (cra_RepoFlushTask *)curr->data;
    if (task->rc) {
      rc = task->rc;
      g_slist_free_full(dirty, (GDestroyNotify)cra_repo_flush_task_clear);
      g_warning(
        "Failed to write repository metadata to %s (%d): %s",
        task->repo->path, rc, cr_strerror(rc));
      return rc;
    }
    task->rc = CRE_ERROR;
    task->repo->flags ^= CRA_REPO_DIRTY;
  }

  g_slist_free(dirty);

  return CRE_OK;
}

cra_CacheStats
cra_cache_stats(cra_Cache * cache)
{
  cra_CacheStats stats;
  GHashTableIter iter;
  cra_ArchCache * arch;

  stats.repo_count = 0;
  stats.pkg_count = 0;

  if (cache->source_repo->flags & CRA_REPO_LOADED) {
    stats.repo_count += 1;
    stats.pkg_count += g_list_length(cache->source_repo->packages);
  }

  g_hash_table_iter_init(&iter, cache->arches);
  while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&arch)) {
    if (arch->arch_repo->flags & CRA_REPO_LOADED) {
      stats.repo_count += 1;
      stats.pkg_count += g_list_length(arch->arch_repo->packages);
    }

    if (arch->debug_repo->flags & CRA_REPO_LOADED) {
      stats.repo_count += 1;
      stats.pkg_count += g_list_length(arch->debug_repo->packages);
    }
  }

  return stats;
}
