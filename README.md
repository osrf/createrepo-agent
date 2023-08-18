createrepo-agent
================

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/osrf/createrepo-agent/ci.yaml?branch=main&event=push)](https://github.com/osrf/createrepo-agent/actions/workflows/ci.yaml?query=branch%3Amain+event%3Apush)
[![Codecov branch](https://img.shields.io/codecov/c/gh/osrf/createrepo-agent/main)](https://app.codecov.io/gh/osrf/createrepo-agent/tree/main)

*Rapidly and repeatedly generate RPM repository metadata*

**createrepo-agent** is a tool for rapidly iterating on clusters of associated RPM repositories. It leverages Assuan IPC to create a daemon process which caches the metadata for each sub-repository in the cluster so that it doesn't need to be re-loaded and parsed each time a change is made. The most notable implementation of the Assuan protocol is **gpg-agent**, which gives **createrepo-agent** its name.
