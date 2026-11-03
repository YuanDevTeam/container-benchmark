"""Fixed runtime and dedicated-builder resources for owned containers."""

CPUS = 5
MEMORY = "4G"
MEMORY_BYTES = 4 * 1024**3
ARGUMENTS = ("--cpus", str(CPUS), "--memory", MEMORY)
BUILDER_MEMORY = "16G"
BUILDER_MEMORY_BYTES = 16 * 1024**3
BUILDER_ARGUMENTS = ("--cpus", str(CPUS), "--memory", BUILDER_MEMORY)


def allocation(role, *, source=False):
    """A runtime peer stays at 4 GiB even if it compiles a small helper."""
    if source or role == "builder" or role.endswith("-builder"):
        return BUILDER_ARGUMENTS, BUILDER_MEMORY_BYTES
    return ARGUMENTS, MEMORY_BYTES
