"""Current HTTP targets shared by device and simulated packet-I/O measurements.

Raw load arrival remains independent of final rewrite throughput. Each observer
retains its own correctness, memory metric, TUN and lifecycle requirements.
"""

OFFERED_MBPS = 900
RAW_LOAD_MINIMUM_MBPS = 850


def minimum_mbps(mode):
    """Return the inclusive throughput goal for one declared processing mode."""
    if mode in ("disabled", "native"):
        return 850
    if mode in ("js", "mixed"):
        return 500
    raise ValueError("select disabled/native/js/mixed HTTP mode")
