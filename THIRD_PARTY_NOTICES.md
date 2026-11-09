# Third-party notices

ARGUS can download the datasets below for optional cyber geo-routing annotations.
The `.dat` binaries are not part of this source tree. Fetch them with
`scripts/fetch_geo_dat.py`, which checks each file against the upstream
`.sha256sum` asset and the pin in `geo-datasets.lock.json`.

This product uses v2fly releases only. Loyalsoldier and sing-box datasets are
not approved and are refused by the lockfile check.

## geoip.dat

- Project: v2fly/geoip (Project V)
- Upstream: https://github.com/v2fly/geoip
- Release tag: 202611080027
- Asset: geoip.dat
- SHA-256: eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2
- License: Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA-4.0)
- License text: https://creativecommons.org/licenses/by-sa/4.0/legalcode
- Modifications: none. The bytes are stored only under the local data directory after the checksum matches.

Attribution: "geoip.dat" by the v2fly geoip contributors, licensed under CC-BY-SA-4.0.
No changes are made to the dataset. ShareAlike applies if a modified dataset is redistributed.

## geosite.dat

- Project: v2fly/domain-list-community (Project V)
- Upstream: https://github.com/v2fly/domain-list-community
- Release tag: 20261108011013
- Asset: dlc.dat, saved locally as geosite.dat
- SHA-256: dc4192dd1b644a38276ed06136d26e729fa674d25785adb38c87e040e92376b2
- License: MIT
- Modifications: filename only (`dlc.dat` saved as `geosite.dat`). Contents are not altered.

```
MIT License

Copyright (c) 2018-2019 V2Ray

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
