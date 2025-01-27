Coding Standards
================

The coding standards for volatility are mostly by our linter and our code formatter.
All code submissions will be vetted automatically through tests from both and the submission
will not be accepted if either of these fail.

Code Linter: Ruff
Code Formatter: Black

In additio, there are some coding practices that we employ to prevent specific failure cases and
ensure consistency across the codebase.  These are documented below along with the rationale for the decision.

Imports
-------

Import should be of a module (not a class or a method), and ideally just one module except where naming would cause confusion.
This is to prevent people importing an imported method (which can lead to confusion and add in an unnecessary dependency in the import chain).

Good example:

```
from module import submodule
from module.submodule import submodule as subsubmodule

class NewClass(submodule.Class):
  def method(self):
    submodule.Class.classmethod()
```

Bad example:

```
from module import method
from module.submodule import Class
```

Versioning
----------

Modules that inherit from `VersionableInterface` define a `_version` attribute which states their version.
This is a tuple of `(MAJOR, MINOR, PATCH)` numbers, which can then be used for Semantic Versioning (where
modifications that change the API in a non-backwards compatible way bump the `MAJOR` version (and set
the `MINOR` and `PATCH` to 0) and additive changes increase the `MINOR` version (and set the `PATCH` to 0).
Changes that have no effect on the external interface (either input or output form) should have their `PATCH`
number incremented.  This allows for callers of the interface to determine when changes have happened and whether
their code will still work with it.  Volatility carries out these checks through the requirements system, where
a plugin can define what requirements it has.

Shared functionality
--------------------

Within a plugin, there may be functions that are useful to other plugins.  These are created as `classmethod`s
so that the plugin can be depended upon by other plugins in their requirements section, without needing to
instantiate a whole copy of the plugin.  It is not a staticmethod, because the caller may wish to determine
information about the class the method is defined in, and this is not easily accessible for staticmethods.

A classmethod usually takes a `context` for its first method (and if it requires one, a configuration string for
it second).  All other parameters should generally be basic types (such as strings, numbers, etc) so that future
work requiring paralellization does not have complex types to have to keep in sync.  In particular, the idea was
to ensure only one context was used per method (and each object brings its own context with it, meaning the
function signature should not include objects to avoid discrepancies).
