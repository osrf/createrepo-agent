# Copyright 2026 Open Source Robotics Foundation, Inc.
# Licensed under the Apache License, Version 2.0

from typing import Any, Collection, Optional, Type

__version__: str
SOCK_NAME: str

EXIT_SUCCESS: int
EXIT_GENERAL_ERROR: int
EXIT_USAGE: int
EXIT_IN_USE: int


class Client:

    def __init__(self, name: str) -> None: ...

    @property
    def name(self) -> str: ...

    def add(self, package: str, arches: Optional[Collection[str]] = None) -> None: ...

    def commit(self) -> None: ...

    def connect(self) -> None: ...

    def disconnect(self) -> None: ...

    def remove_name(self, name: str, arches: Optional[Collection[str]] = None) -> None: ...

    def remove_pattern(self, pattern: str, arches: Optional[Collection[str]] = None) -> None: ...

    def set_invalidate_dependants(self, invalidate_dependants: bool) -> None: ...

    def set_invalidate_family(self, invalidate_family: bool) -> None: ...

    def set_missing_ok(self, missing_ok: bool) -> None: ...

    def sync(
        self,
        base_url: str,
        pattern: Optional[str] = None,
        arches: Optional[Collection[str]] = None,
    ) -> None: ...

    def __enter__(self) -> 'Client': ...

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Any,
    ) -> None: ...


class Server:

    def __init__(self, name: str) -> None: ...

    @property
    def name(self) -> str: ...

    def shutdown_thread(self) -> None: ...

    def start_thread(self) -> None: ...

    def __enter__(self) -> 'Server': ...

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Any,
    ) -> None: ...
