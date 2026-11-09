# >_ARGUS™ Military Edition — older reference copy

**Canonical code is [argus-military-reference](https://github.com/InfinitumCorp/argus-military-reference).** This repository is the shorter earlier copy. Do not add features here.

Military use only. Human-commanded. Advisory recommendations only. Private Firmament provenance. No public token.

## Usage

```bash
python main.py
python main.py datasets/sample_observations.csv
```

`cop.html` is written by the canonical repo's `main.py` (`argus.cop.generate_cop_html`). This copy does not ship a COP page.

## Geo datasets (opt-in)

v2fly GeoIP and GeoSite lists can annotate an address with a country code and a domain with categories. The hook stays off unless `INFINITUM_GEO_ENABLED` is `1`, `true`, `yes`, or `on`. Default pictures, alerts, and recommendations do not change.

```bash
python scripts/fetch_geo.py
INFINITUM_GEO_ENABLED=1 python main.py datasets/sample_observations.csv
```

`scripts/fetch_geo.py` reads `geo.lock.json`, checks each official `.sha256sum` asset, and writes `data/geo/geoip.dat` and `data/geo/geosite.dat`. Those binaries are gitignored. A checksum mismatch stops the fetch. Set `INFINITUM_GEO_DIR` to point the loader somewhere else. Attribution is in `THIRD_PARTY_NOTICES`.
