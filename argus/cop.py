from pathlib import Path
from typing import Dict, Any

def generate_cop_html(picture: Dict[str, Any], output_path="cop.html"):
    tracks = picture.get("tracks", [])
    alerts = picture.get("defense_alerts", [])
    lat = sum(t["position"]["lat"] for t in tracks)/len(tracks) if tracks else 38.9072
    lon = sum(t["position"]["lon"] for t in tracks)/len(tracks) if tracks else -77.0369
    markers = [{"lat": t["position"]["lat"], "lon": t["position"]["lon"], "id": t["track_id"], "cls": t["classification"], "color": "#c53030" if t["classification"]=="uas" else "#2b6cb0"} for t in tracks]
    html = f'''<!DOCTYPE html><html><head><meta charset="utf-8"><title>>_ARGUS™</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>body{{margin:0;font-family:Arial,sans-serif;background:#fff}}#h{{padding:16px 24px;border-bottom:1px solid #e2e8f0;display:flex;justify-content:space-between}}#map{{height:calc(100vh-56px)}}#s{{position:absolute;top:72px;right:12px;width:300px;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:12px;box-shadow:0 2px 8px rgba(0,0,0,.05)}}</style></head>
<body><div id="h"><div><strong>>_ARGUS™</strong><div style="font-size:12px;color:#718096">Common Operating Picture · Military Edition</div></div><div>Tracks {len(tracks)} · Alerts {len(alerts)}</div></div>
<div id="map"></div><div id="s"><div style="font-size:11px;color:#718096;text-transform:uppercase">Alerts</div>
{''.join(f'<div style="margin:6px 0;padding:8px;background:#fff5f5;border-radius:4px;font-size:12px">{a["threat_type"]}</div>' for a in alerts[:4])}
<div style="font-size:11px;color:#718096;margin-top:12px">Human-commanded. Advisory only.<br>Private Firmament.</div></div>
<script>const map=L.map('map').setView([{lat},{lon}],14);L.tileLayer('https://{{s}}.basemaps.cartocdn.com/light_all/{{z}}/{{x}}/{{y}}{{r}}.png').addTo(map);
const m={markers};m.forEach(t=>L.circleMarker([t.lat,t.lon],{{radius:7,fillColor:t.color,color:'#fff',weight:2,fillOpacity:.9}}).addTo(map).bindPopup(t.id+' '+t.cls));</script></body></html>'''
    Path(output_path).write_text(html)
    return output_path
