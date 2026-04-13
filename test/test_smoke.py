# Copyright 2025 Open Source Robotics Foundation, Inc.
# Licensed under the Apache License, Version 2.0

from pathlib import Path
import shutil
from typing import Generator

import createrepo_agent
import pytest

FIXTURES_DIR: Path = Path(__file__).parent / 'fixtures'
EMPTY_REPO: Path = FIXTURES_DIR / 'empty'
POPULATED_REPO: Path = FIXTURES_DIR / 'populated'
POPULATED_RPM: Path = Path(
    POPULATED_REPO,
    'x86_64',
    'Packages',
    'r',
    'ros-dev-tools-1.0.1-1.el9.noarch.rpm',
)


@pytest.fixture
def mutable_populated_repo(tmp_path: Path) -> Generator[Path, None, None]:
    repo_path = tmp_path / 'populated'
    shutil.copytree(
        str(POPULATED_REPO), str(repo_path),
        ignore=shutil.ignore_patterns('repomd.xml.asc'))
    yield repo_path


def test_version() -> None:
    assert createrepo_agent.__version__


def test_add(tmp_path: Path) -> None:
    rpm_path = str(POPULATED_RPM)

    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            with pytest.raises(TypeError):
                c.add(None)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.add(rpm_path, 1)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.add(rpm_path, (1,))  # type: ignore[arg-type]
            c.set_invalidate_dependants(True)
            c.set_invalidate_family(True)
            c.add(rpm_path, ('x86_64',))
            c.commit()

    arch_path = tmp_path / 'x86_64'
    repomd_path = arch_path / 'repodata' / 'repomd.xml'

    assert repomd_path.is_file()
    assert (arch_path / 'Packages' / 'r' / POPULATED_RPM.name).is_file()


def test_commit_nothing(tmp_path: Path) -> None:
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            c.commit()


def test_server_socket_collision(tmp_path: Path) -> None:
    with createrepo_agent.Server(str(tmp_path)):
        pass

    with createrepo_agent.Server(str(tmp_path)):
        with pytest.raises(OSError):
            with createrepo_agent.Server(str(tmp_path)):
                pass  # pragma: no cover


def test_sync_all(tmp_path: Path) -> None:
    base_url = POPULATED_REPO.as_uri()
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            with pytest.raises(TypeError):
                c.sync(None)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.sync(base_url, arches=1)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.sync(base_url, arches=(1,))  # type: ignore[arg-type]
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


def test_sync_pattern_hit(tmp_path: Path) -> None:
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

    # Performing a sync with a pattern invalidates contents of the target repository
    # which match the pattern. Here, we specifically verify that the invalidation happens
    # even when the upstream repository doesn't have any matches.

    base_url = EMPTY_REPO.as_uri()
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            c.sync(base_url, pattern, ('x86_64',))
            c.commit()

    assert not (arch_path / 'Packages' / 'r' / POPULATED_RPM.name).is_file()


def test_sync_pattern_miss(tmp_path: Path) -> None:
    base_url = POPULATED_REPO.as_uri()
    pattern = 'does-not-match'
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            c.sync(base_url, pattern, ('x86_64',))
            c.commit()

    arch_path = tmp_path / 'x86_64'

    assert not (arch_path / 'Packages' / 'r' / POPULATED_RPM.name).is_file()


def test_remove_name(mutable_populated_repo: Path) -> None:
    arches = ('x86_64', )
    with createrepo_agent.Server(str(mutable_populated_repo)):
        with createrepo_agent.Client(str(mutable_populated_repo)) as c:
            with pytest.raises(TypeError):
                c.remove_name(1)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.remove_name('ros-dev-tools', (1,))  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.remove_name('ros-dev-tools', arches, 1)  # type: ignore[call-arg]

            # Omitting arches targets SRPMS which has no such package
            c.remove_name('ros-dev-tools')
            with pytest.raises(RuntimeError):
                c.commit()

            # Function treats 'None' arches the same as omission
            c.remove_name('ros-dev-tools', None)
            with pytest.raises(RuntimeError):
                c.commit()

            # Remove package
            c.remove_name('ros-dev-tools', arches)
            c.commit()

            # Try to remove again - expected to fail
            c.remove_name('ros-dev-tools', arches)
            with pytest.raises(RuntimeError):
                c.commit()

            # Explicitly allow no matches
            c.set_missing_ok(True)
            c.remove_name('ros-dev-tools', arches)
            c.commit()

            # ...and explicitly disallow
            c.set_missing_ok(False)
            c.remove_name('ros-dev-tools', arches)
            with pytest.raises(RuntimeError):
                c.commit()

    for arch in arches:
        arch_path = mutable_populated_repo / arch
        pkg_path = arch_path / 'Packages' / 'r' / POPULATED_RPM.name
        assert not pkg_path.is_file()


def test_remove_pattern(mutable_populated_repo: Path) -> None:
    arches = ('x86_64', )
    with createrepo_agent.Server(str(mutable_populated_repo)):
        with createrepo_agent.Client(str(mutable_populated_repo)) as c:
            with pytest.raises(TypeError):
                c.remove_pattern(1)  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.remove_pattern('ros-.*', (1,))  # type: ignore[arg-type]
            with pytest.raises(TypeError):
                c.remove_pattern('ros-.*', arches, 1)  # type: ignore[call-arg]

            # Omitting arches targets SRPMS which has no such package
            c.remove_pattern('ros-.*')
            with pytest.raises(RuntimeError):
                c.commit()

            # Function treats 'None' arches the same as omission
            c.remove_pattern('ros-.*', None)
            with pytest.raises(RuntimeError):
                c.commit()

            # Remove package
            c.remove_pattern('ros-.*', arches)
            c.commit()

            # Try to remove again - expected to fail
            c.remove_pattern('ros-.*', arches)
            with pytest.raises(RuntimeError):
                c.commit()

            # Explicitly allow no matches
            c.set_missing_ok(True)
            c.remove_pattern('ros-.*', arches)
            c.commit()

            # ...and explicitly disallow
            c.set_missing_ok(False)
            c.remove_pattern('ros-.*', arches)
            with pytest.raises(RuntimeError):
                c.commit()

    for arch in arches:
        arch_path = mutable_populated_repo / arch
        pkg_path = arch_path / 'Packages' / 'r' / POPULATED_RPM.name
        assert not pkg_path.is_file()


@pytest.mark.parametrize('option_name', (
    'invalidate_dependants',
    'invalidate_family',
    'missing_ok',
))
def test_option_arguments(tmp_path: Path, option_name: str) -> None:
    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            setter = getattr(c, f'set_{option_name}')

            setter(True)
            setter(False)

            # Must provide value
            with pytest.raises(TypeError):
                setter()

            # Only one argument accepted
            with pytest.raises(TypeError):
                setter(True, None)
