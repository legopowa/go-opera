from typing import List, Tuple

RandPair = Tuple[str, str]
PubPair = Tuple[str, str]

class LamportKeyPair:
    def __init__(self, pri: List[RandPair], pub: List[PubPair]):
        self.pri = pri
        self.pub = pub

class KeyPair:
    def __init__(self, pri: List[RandPair], pub: List[PubPair]):
        self.pri = pri
        self.pub = pub

Sig = List[str]
