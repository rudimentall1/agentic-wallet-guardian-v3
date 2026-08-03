"""Shared constants for tests. Import addresses from here instead of
typing out '0x1111...aaaa'-style strings by hand - that pattern has
produced a wrong-length (40 instead of 42 char) address three separate
times across this test suite, each time silently making every test using
it fail on the address-format check rather than the thing being tested.
"""

DUMMY_ADDRESS_1 = "0x" + "1" * 36 + "aaaa"  # 42 chars total, verified below
DUMMY_ADDRESS_2 = "0x" + "2" * 36 + "bbbb"

assert len(DUMMY_ADDRESS_1) == 42
assert len(DUMMY_ADDRESS_2) == 42
