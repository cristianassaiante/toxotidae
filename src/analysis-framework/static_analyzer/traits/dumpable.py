from __future__ import annotations
import pickle


class Dumpable:
    def dump(self, fout: str) -> None:
        with open(fout, "wb") as f:
            pickle.dump(self, f)
