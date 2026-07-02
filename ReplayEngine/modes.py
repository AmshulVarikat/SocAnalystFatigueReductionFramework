from enum import Enum


class ReplayMode(str, Enum):
    SEQUENTIAL = "sequential"
    TIME_PRESERVED = "time_preserved"
    ACCELERATED = "accelerated"
    LIVE = "live"


class ReplayOutputFormat(str, Enum):
    RAW = "raw"
    TEST = "test"