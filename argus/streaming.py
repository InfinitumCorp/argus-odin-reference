from typing import List, Dict, Any, Iterator
from argus.fusion import ArgusFusionEngine
from argus.detector import SimulatedDetector

class StreamingProcessor:
    def __init__(self, geo=None):
        self.engine = ArgusFusionEngine(detector=SimulatedDetector(), geo=geo)
    def process_batch(self, observations):
        return self.engine.ingest_and_fuse(observations)
    def process_stream(self, batches: Iterator[List[Dict[str, Any]]]):
        return [self.process_batch(b) for b in batches]
