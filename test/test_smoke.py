# Copyright 2025 Open Source Robotics Foundation, Inc.
# Licensed under the Apache License, Version 2.0

from pathlib import Path

import createrepo_agent
import pytest

FIXTURES_DIR = Path(__file__).parent / 'fixtures'


def test_version():
    assert createrepo_agent.__version__


def test_add(tmp_path):
    packages_path = FIXTURES_DIR / 'populated' / 'x86_64' / 'Packages'
    rpm_path = packages_path / 'r' / 'ros-dev-tools-1.0.1-1.el9.noarch.rpm'

    with createrepo_agent.Server(str(tmp_path)):
        with createrepo_agent.Client(str(tmp_path)) as c:
            with pytest.raises(TypeError):
                c.add(str(rpm_path), 1)
            with pytest.raises(TypeError):
                c.add(str(rpm_path), (1,))
            c.set_invalidate_dependants(True)
            c.set_invalidate_family(True)
            c.add(str(rpm_path), ('x86_64',))
            c.commit()

    assert (tmp_path / 'x86_64' / 'repodata' / 'repomd.xml').is_file()


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
