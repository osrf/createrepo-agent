# Copyright 2025 Open Source Robotics Foundation, Inc.
# Licensed under the Apache License, Version 2.0

from pathlib import Path

import createrepo_agent
import pytest

FIXTURES_DIR = Path(__file__).parent / 'fixtures'
POPULATED_REPO = FIXTURES_DIR / 'populated'
POPULATED_RPM = Path(
    POPULATED_REPO,
    'x86_64',
    'Packages',
    'r',
    'ros-dev-tools-1.0.1-1.el9.noarch.rpm',
)


def test_version():
    assert createrepo_agent.__version__


def test_add(tmp_path):
    rpm_path = str(POPULATED_RPM)

    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            with pytest.raises(TypeError):
                c.add(None)
            with pytest.raises(TypeError):
                c.add(rpm_path, 1)
            with pytest.raises(TypeError):
                c.add(rpm_path, (1,))
            c.set_invalidate_dependants(True)
            c.set_invalidate_family(True)
            c.add(rpm_path, ('x86_64',))
            c.commit()

    arch_path = tmp_path / 'x86_64'
    repomd_path = arch_path / 'repodata' / 'repomd.xml'

    assert repomd_path.is_file()
    assert (arch_path / 'Packages' / 'r' / POPULATED_RPM.name).is_file()


def test_commit_nothing(tmp_path):
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            c.commit()


def test_server_socket_collision(tmp_path):
    with createrepo_agent.Server(str(tmp_path)):
        pass

    with createrepo_agent.Server(str(tmp_path)):
        with pytest.raises(OSError):
            with createrepo_agent.Server(str(tmp_path)):
                pass


def test_sync_all(tmp_path):
    base_url = POPULATED_REPO.as_uri()
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            with pytest.raises(TypeError):
                c.sync(None)
            with pytest.raises(TypeError):
                c.sync(base_url, arches=1)
            with pytest.raises(TypeError):
                c.sync(base_url, arches=(1,))
            c.sync(base_url, arches=('x86_64',))
            c.commit()

    arch_path = tmp_path / 'x86_64'
    repomd_path = arch_path / 'repodata' / 'repomd.xml'

    assert repomd_path.is_file()
    assert (arch_path / 'Packages' / 'r' / POPULATED_RPM.name).is_file()

    # Performing the same operation again results in no changes, so CRA shouldn't
    # make any changes to the metadata at all.

    old_repomd_contents = repomd_path.read_text()

    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            c.sync(base_url, arches=('x86_64',))
            c.commit()

    assert old_repomd_contents == repomd_path.read_text()


def test_sync_pattern_hit(tmp_path):
    base_url = POPULATED_REPO.as_uri()
    pattern = POPULATED_RPM.name[:3] + '.*'
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            c.sync(base_url, pattern, ('x86_64',))
            c.commit()

    arch_path = tmp_path / 'x86_64'
    repomd_path = arch_path / 'repodata' / 'repomd.xml'

    assert repomd_path.is_file()
    assert (arch_path / 'Packages' / 'r' / POPULATED_RPM.name).is_file()


def test_sync_pattern_miss(tmp_path):
    base_url = POPULATED_REPO.as_uri()
    pattern = 'does-not-match'
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            c.sync(base_url, pattern, ('x86_64',))
            c.commit()

    arch_path = tmp_path / 'x86_64'

    assert not (arch_path / 'Packages' / 'r' / POPULATED_RPM.name).is_file()
