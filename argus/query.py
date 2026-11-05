from typing import Dict, Any

class SceneQuery:
    def ask(self, question: str, picture: Dict[str, Any]):
        q = question.lower()
        tracks = picture.get("tracks", [])
        alerts = picture.get("defense_alerts", [])
        if "uas" in q or "drone" in q:
            return {"answer": f"Found {sum(1 for t in tracks if t['classification']=='uas')} UAS track(s)."}
        if "alert" in q or "threat" in q:
            return {"answer": f"{len(alerts)} active defense alert(s)."}
        return {"answer": f"{len(tracks)} tracks, {len(alerts)} alerts."}
