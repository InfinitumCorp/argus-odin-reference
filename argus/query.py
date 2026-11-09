from typing import Dict, Any


def _format_geo(geo):
    entries = geo.get("entries") or []
    if not entries:
        return "Geo-routing is on. No address annotations in this picture."
    parts = []
    for entry in entries:
        if "source_ip" in entry:
            country = entry.get("country") or "unknown"
            parts.append(f"{entry['source_ip']} {country}")
        if "domain" in entry:
            categories = entry.get("categories") or []
            label = ", ".join(categories) if categories else "uncategorized"
            parts.append(f"{entry['domain']} {label}")
    return "Geo-routing: " + "; ".join(parts)


class SceneQuery:
    def ask(self, question: str, picture: Dict[str, Any]):
        q = question.lower()
        tracks = picture.get("tracks", [])
        alerts = picture.get("defense_alerts", [])
        if "uas" in q or "drone" in q:
            return {"answer": f"Found {sum(1 for t in tracks if t['classification']=='uas')} UAS track(s)."}
        if "alert" in q or "threat" in q:
            return {"answer": f"{len(alerts)} active defense alert(s)."}
        geo = picture.get("geo")
        if geo and any(word in q for word in ("country", "domain", "category", "geo-routing", "geosite")):
            return {"answer": _format_geo(geo)}
        return {"answer": f"{len(tracks)} tracks, {len(alerts)} alerts."}
