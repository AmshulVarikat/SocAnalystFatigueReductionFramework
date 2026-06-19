from enum import Enum


class ReplayMode(str, Enum):
    SEQUENTIAL = "sequential"
    TIME_PRESERVED = "time_preserved"
    ACCELERATED = "accelerated"


class ReplayOutputFormat(str, Enum):
    RAW = "raw"
    TEST = "test"