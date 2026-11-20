"""Strict receipts for the two owned Mac generator timer threads."""


def mapping(value):
    return value if isinstance(value, dict) else {}


def integer(value, expected):
    return type(value) is int and value == expected


def snapshot_valid(value, wanted, *, ordinary):
    value = mapping(value)
    timer = mapping(value.get("ttc"))
    extended = mapping(value.get("extended"))
    basic = mapping(value.get("basic"))
    valid = all(
        integer(timer.get(key), expected)
        for key, expected in (
            ("returnCode", 0),
            ("inputCount", 4),
            ("count", 4),
            ("inputDefault", 0),
            ("default", 1 if ordinary else 0),
        )
    ) and all(
        integer(extended.get(key), expected)
        for key, expected in (
            ("returnCode", 0),
            ("inputCount", 1),
            ("count", 1),
            ("inputDefault", 0),
        )
    )
    valid &= all(
        integer(basic.get(key), expected)
        for key, expected in (
            ("returnCode", 0),
            ("inputCount", 10),
            ("count", 10),
            ("policy", 1 if ordinary else 2),
        )
    )
    if ordinary:
        return (
            valid
            and integer(extended.get("default"), 0)
            and integer(extended.get("timeshare"), 1)
            and all(
                type(timer.get(key)) is int and 0 <= timer[key] <= 2**32 - 1
                for key in ("period", "computation", "constraint")
            )
            and type(timer.get("preemptible")) is int
            and timer["preemptible"] in (0, 1)
        )
    return (
        valid
        and all(
            type(extended.get(key)) is int and extended[key] in (0, 1)
            for key in ("default", "timeshare")
        )
        and all(integer(timer.get(key), value) for key, value in wanted.items())
    )
