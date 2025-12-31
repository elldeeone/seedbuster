"""Global pytest configuration."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncGenerator

import inspect

import pytest

# Avoid preview-only reporting during tests even if .env sets it.
os.environ.setdefault("REPORT_PREVIEW_ONLY", "false")


@pytest.fixture(scope="session")
def event_loop() -> AsyncGenerator[asyncio.AbstractEventLoop, None]:
    """Provide a shared event loop for async tests and fixtures."""

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.close()


def _get_loop(request: pytest.FixtureRequest) -> asyncio.AbstractEventLoop:
    try:
        loop = request.getfixturevalue("event_loop")
    except pytest.FixtureLookupError:
        loop = asyncio.new_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):  # type: ignore[override]
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        testargs = {
            name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames
        }
        loop = testargs.get("event_loop") or asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(pyfuncitem.obj(**testargs))
        return True
    return None


@pytest.hookimpl(tryfirst=True)
def pytest_fixture_setup(fixturedef, request):  # type: ignore[override]
    func = fixturedef.func
    if inspect.iscoroutinefunction(func):
        loop = _get_loop(request)
        kwargs = {arg: request.getfixturevalue(arg) for arg in fixturedef.argnames}
        return loop.run_until_complete(func(**kwargs))

    if inspect.isasyncgenfunction(func):
        loop = _get_loop(request)
        kwargs = {arg: request.getfixturevalue(arg) for arg in fixturedef.argnames}
        agen = func(**kwargs)
        value = loop.run_until_complete(agen.__anext__())

        def finalize() -> None:
            try:
                loop.run_until_complete(agen.__anext__())
            except StopAsyncIteration:
                pass

        request.addfinalizer(finalize)
        return value

    return None


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "asyncio: mark test as requiring asyncio support")
