import math
from typing import Tuple

class KalmanTrack:
    def __init__(self, lat, lon, process_noise=1e-8, measurement_noise=1e-6):
        self.x = [lat, lon, 0.0, 0.0]
        self.P = [1e-4, 1e-4, 1e-6, 1e-6]
        self.q = process_noise
        self.r = measurement_noise
    def predict(self, dt):
        if dt <= 0: return
        self.x[0] += self.x[2] * dt
        self.x[1] += self.x[3] * dt
        self.P[0] += self.q * dt
        self.P[1] += self.q * dt
    def update(self, lat, lon):
        k_lat = self.P[0] / (self.P[0] + self.r)
        k_lon = self.P[1] / (self.P[1] + self.r)
        self.x[0] += k_lat * (lat - self.x[0])
        self.x[1] += k_lon * (lon - self.x[1])
        self.P[0] *= (1 - k_lat)
        self.P[1] *= (1 - k_lon)
    @property
    def position(self) -> Tuple[float, float]:
        return self.x[0], self.x[1]
    @property
    def velocity_mps(self):
        v_n = self.x[2] * 111320
        v_e = self.x[3] * 111320 * math.cos(math.radians(self.x[0]))
        return math.hypot(v_n, v_e)
    @property
    def heading_deg(self):
        v_n = self.x[2] * 111320
        v_e = self.x[3] * 111320 * math.cos(math.radians(self.x[0]))
        return math.degrees(math.atan2(v_e, v_n)) % 360
