"""Keep the in-memory MongoDB used by the tests compatible with current PyMongo.

PyMongo 4.11 added a ``sort`` option to UpdateOne, UpdateMany and ReplaceOne.
Since then ``Collection.bulk_write`` hands every such operation to the bulk
builder as ``add_update(..., sort=<value or None>)``. mongomock up to and
including 4.3.0 (the latest release) has no ``sort`` parameter there, so any
``bulk_write`` containing an update fails with::

    TypeError: BulkOperationBuilder.add_update() got an unexpected keyword argument 'sort'

That is a gap in the test double, not in the application: against a real
MongoDB server the call is valid. The adapter below gives the builder the
missing parameter. ``sort=None`` ("no sort", which is all PyMongo sends unless
the caller asks for one) is dropped; an explicit sort is refused loudly,
because mongomock cannot honour it and silently ignoring it would let a test
pass on behaviour the mock does not implement.

A mongomock release that accepts ``sort`` itself is left untouched.
"""

from __future__ import annotations

import functools
import inspect

from mongomock.collection import BulkOperationBuilder

_METHODS = ("add_update", "add_replace")


def _accepting_sort(method):
    @functools.wraps(method)
    def wrapper(self, *args, sort=None, **kwargs):
        if sort is not None:
            raise NotImplementedError(
                "The installed mongomock does not implement 'sort' for bulk updates; "
                "this test needs a real MongoDB server or a newer mongomock."
            )
        return method(self, *args, **kwargs)

    # Report the real, widened signature (functools.wraps would otherwise show the original one).
    original = inspect.signature(method)
    wrapper.__signature__ = original.replace(parameters=[
        *original.parameters.values(),
        inspect.Parameter("sort", inspect.Parameter.KEYWORD_ONLY, default=None),
    ])
    wrapper.__mongomock_compat__ = True
    return wrapper


def apply() -> list[str]:
    """Patch the builder methods that lack ``sort``. Returns the names patched (idempotent)."""
    patched = []
    for name in _METHODS:
        method = getattr(BulkOperationBuilder, name)
        if "sort" in inspect.signature(method).parameters or getattr(method, "__mongomock_compat__", False):
            continue
        setattr(BulkOperationBuilder, name, _accepting_sort(method))
        patched.append(name)
    return patched
