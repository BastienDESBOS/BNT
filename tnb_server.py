#!/usr/bin/env python3
"""
Serveur d'administration du TNB — interface web.

Démarre/arrête une campagne de mesure, expose le statut en direct et les
résultats, mémorise les paramètres déjà saisis (svID, gocbRef, MAC, APPID...)
et propose un scan du trafic GOOSE/SV transitant sur une interface.

Lancement (privilèges réseau requis pour la capture/émission) :
    sudo python3 tnb_server.py --port 7060
puis ouvrir http://localhost:7060

Backend stdlib uniquement (http.server) ; la mesure réutilise tnb.py.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import tnb

_HERE = Path(__file__).resolve().parent
_GUI_PATH = _HERE / "tnb_gui.html"
_STORE_PATH = _HERE / "tnb_store.json"

# Champs mémorisés pour l'auto-complétion (datalists du formulaire).
_HISTORY_KEYS = ("iface", "svid", "gocb_ref", "go_id", "src_mac", "dst_mac",
                 "goose_appid", "sv_appid")


# --------------------------------------------------------------------------- #
# Persistance : profils nommés + historique des valeurs saisies
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data: Dict[str, Any] = {"profiles": {}, "history": {k: [] for k in _HISTORY_KEYS}}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                self.data["profiles"] = raw.get("profiles", {}) or {}
                hist = raw.get("history", {}) or {}
                for k in _HISTORY_KEYS:
                    self.data["history"][k] = list(hist.get(k, []) or [])
            except (OSError, json.JSONDecodeError):
                pass

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.data))

    def save_profile(self, name: str, config: Dict[str, Any]) -> None:
        with self.lock:
            self.data["profiles"][name] = config
            self._save()

    def delete_profile(self, name: str) -> bool:
        with self.lock:
            ok = self.data["profiles"].pop(name, None) is not None
            if ok:
                self._save()
            return ok

    def remember(self, config: Dict[str, Any]) -> None:
        """Enregistre les valeurs scalaires/listes saisies dans l'historique."""
        with self.lock:
            h = self.data["history"]
            def add(key: str, val: Any) -> None:
                if val is None or val == "":
                    return
                lst = h.setdefault(key, [])
                if val not in lst:
                    lst.insert(0, val)
                    del lst[20:]
            add("iface", config.get("iface"))
            add("svid", config.get("svid"))
            add("src_mac", config.get("src_mac"))
            add("dst_mac", config.get("dst_mac"))
            add("goose_appid", config.get("goose_appid"))
            add("sv_appid", config.get("sv_appid"))
            for ref in (config.get("gocb_refs") or []):
                add("gocb_ref", ref)
            self._save()

    def remember_scan(self, scan: Dict[str, Any]) -> None:
        with self.lock:
            h = self.data["history"]
            def add(key: str, val: Any) -> None:
                if not val:
                    return
                lst = h.setdefault(key, [])
                if val not in lst:
                    lst.insert(0, val)
                    del lst[40:]
            for g in scan.get("goose", []):
                add("gocb_ref", g.get("gocb_ref"))
                add("go_id", g.get("go_id"))
                add("src_mac", g.get("src_mac"))
            for s in scan.get("sv", []):
                add("svid", s.get("svid"))
                add("src_mac", s.get("src_mac"))
            self._save()


# --------------------------------------------------------------------------- #
# Construction d'une RunConfig depuis le dict du formulaire
# --------------------------------------------------------------------------- #
def _opt_int(v: Any) -> Optional[int]:
    if v is None or v == "":
        return None
    return int(str(v), 0)


def _opt_float(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    return float(v)


def config_to_runconfig(c: Dict[str, Any]) -> tnb.RunConfig:
    model = tnb.FaultModel(
        freq=float(c.get("freq", 50.0)),
        i_peak=float(c.get("i_peak", 10.0)),
        v_peak=float(c.get("v_peak", 100.0)),
        phase_deg=float(c.get("phase", 0.0)),
        thr_factor=float(c.get("thr_factor", 0.5)),
    )
    refs = [r for r in (c.get("gocb_refs") or []) if r]
    members_raw = c.get("trip_members") or {}
    trip_members = {}
    for ref, idx in members_raw.items():
        iv = _opt_int(idx)
        if ref and iv is not None:
            trip_members[ref] = iv
    return tnb.RunConfig(
        iface=c["iface"],
        model=model,
        svid_filter=c.get("svid") or None,
        goose_appid=_opt_int(c.get("goose_appid")),
        gocb_refs=refs or None,
        trip_bool_index=_opt_int(c.get("trip_bool_index")),
        trip_timeout=float(c.get("trip_timeout_ms", 500.0)) / 1e3,
        num_shots=int(c.get("shots", 0) or 0),
        duration=_opt_float(c.get("duration")),
        debounce=int(c.get("debounce", 2)),
        trip_members=trip_members or None,
    )


def spawn_generator(c: Dict[str, Any]) -> Optional["subprocess.Popen"]:
    import subprocess
    if not c.get("generate") or not c.get("rt_sender"):
        return None
    cmd = [
        c["rt_sender"],
        "--freq", str(c.get("freq", 50)),
        "--i-peak", str(c.get("i_peak", 10)),
        "--v-peak", str(c.get("v_peak", 100)),
        "--phase", str(c.get("phase", 0)),
        "--fault",
        "--fault-i-peak", str(c.get("fault_i_peak", 0)),
        "--fault-v-peak", str(c.get("fault_v_peak", 0)),
        "--fault-phase", str(c.get("fault_phase", 0)),
        "--fault-cycle", str(c.get("fault_cycle", 2)),
        "--appid", str(c.get("sv_appid", "0x4000")),
        "--conf-rev", str(c.get("sv_conf_rev", 1)),
        "--smp-synch", str(c.get("smp_synch", 2)),
        "--format", str(c.get("sv_format", "6i3u")),
    ]
    if c.get("vlan_id") not in (None, ""):
        cmd += ["--vlan-id", str(c["vlan_id"]), "--vlan-priority", str(c.get("vlan_priority", 4))]
    cmd += [c["iface"], c.get("src_mac", "01:0c:cd:04:00:01"),
            c.get("dst_mac", "01:0c:cd:04:00:02"), c.get("svid") or "SV_TNB"]
    return subprocess.Popen(cmd)


# --------------------------------------------------------------------------- #
# Job de mesure (un seul à la fois)
# --------------------------------------------------------------------------- #
class Job:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cfg = config_to_runconfig(config)
        self.max_latency_ms = _opt_float(config.get("max_latency_ms"))
        self.session = tnb.MeasureSession(self.cfg)
        self.stop_event = threading.Event()
        self.started_at = time.time()
        self.finished_at: Optional[float] = None
        self.error: Optional[str] = None
        self._gen = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        try:
            self._gen = spawn_generator(self.config)
        except Exception as e:  # noqa: BLE001
            self.session.log.append(f"[gen] échec démarrage rt_sender: {e}")
        self.thread.start()

    def _run(self) -> None:
        try:
            tnb._capture_loop(self.cfg, self.session, self.stop_event)
        except Exception as e:  # noqa: BLE001
            self.error = f"{type(e).__name__}: {e}"
            self.session.log.append(f"[erreur] {self.error}")
        finally:
            self.finished_at = time.time()
            if self._gen is not None:
                self._gen.send_signal(2)  # SIGINT
                try:
                    self._gen.wait(timeout=2)
                except Exception:  # noqa: BLE001
                    self._gen.kill()

    @property
    def running(self) -> bool:
        return self.finished_at is None

    def stop(self) -> None:
        self.stop_event.set()

    def state(self) -> Dict[str, Any]:
        end = self.finished_at or time.time()
        return {
            "running": self.running,
            "error": self.error,
            "elapsed": round(end - self.started_at, 1),
            "shots": self.session.shot_index,
            "log": self.session.log[-200:],
            "results": tnb.compute_stats(self.session.tracker, self.max_latency_ms),
            "config": self.config,
        }


# --------------------------------------------------------------------------- #
# Serveur HTTP
# --------------------------------------------------------------------------- #
class TnbServer:
    def __init__(self):
        self.store = Store(_STORE_PATH)
        self.job: Optional[Job] = None
        self.job_lock = threading.Lock()
        self.scanning = False

    # --- actions ---
    def start_job(self, config: Dict[str, Any]) -> Dict[str, Any]:
        with self.job_lock:
            if self.job is not None and self.job.running:
                return {"ok": False, "error": "Une campagne est déjà en cours."}
            if not config.get("iface"):
                return {"ok": False, "error": "Interface manquante."}
            self.store.remember(config)
            self.job = Job(config)
            self.job.start()
            return {"ok": True}

    def stop_job(self) -> Dict[str, Any]:
        with self.job_lock:
            if self.job is None or not self.job.running:
                return {"ok": False, "error": "Aucune campagne en cours."}
            self.job.stop()
            return {"ok": True}

    def state(self) -> Dict[str, Any]:
        with self.job_lock:
            if self.job is None:
                return {"running": False, "shots": 0, "log": [], "results": None}
            return self.job.state()

    def scope(self) -> Dict[str, Any]:
        with self.job_lock:
            if self.job is None:
                return {"ia": [], "va": [], "fault": False, "shot": 0}
            return self.job.session.scope_snapshot()

    def scan(self, iface: str, duration: float) -> Dict[str, Any]:
        if self.scanning:
            return {"ok": False, "error": "Scan déjà en cours."}
        if self.job is not None and self.job.running:
            return {"ok": False, "error": "Impossible de scanner pendant une campagne."}
        self.scanning = True
        try:
            res = tnb.scan_traffic(iface, duration=duration)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}
        finally:
            self.scanning = False
        self.store.remember_scan(res)
        return {"ok": True, **res}


def make_handler(server: TnbServer):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):  # silencieux
            pass

        def _json(self, obj: Any, status: int = 200) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Dict[str, Any]:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode("utf-8"))
            except json.JSONDecodeError:
                return {}

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/" or path == "/index.html":
                try:
                    html = _GUI_PATH.read_bytes()
                except OSError:
                    self._json({"error": "tnb_gui.html introuvable"}, 500)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            elif path == "/api/state":
                self._json(server.state())
            elif path == "/api/scope":
                self._json(server.scope())
            elif path == "/api/store":
                self._json(server.store.snapshot())
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            body = self._body()
            if path == "/api/start":
                self._json(server.start_job(body.get("config", body)))
            elif path == "/api/stop":
                self._json(server.stop_job())
            elif path == "/api/scan":
                iface = body.get("iface", "")
                dur = float(body.get("duration", 5.0))
                self._json(server.scan(iface, dur))
            elif path == "/api/profiles":
                name = body.get("name", "").strip()
                if not name:
                    self._json({"ok": False, "error": "Nom de profil requis"}, 400)
                    return
                server.store.save_profile(name, body.get("config", {}))
                self._json({"ok": True})
            else:
                self._json({"error": "not found"}, 404)

        def do_DELETE(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path.startswith("/api/profiles/"):
                name = path.split("/", 3)[3]
                from urllib.parse import unquote
                ok = server.store.delete_profile(unquote(name))
                self._json({"ok": ok})
            else:
                self._json({"error": "not found"}, 404)

    return Handler


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Serveur d'administration du TNB.")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=7060)
    args = p.parse_args(argv)

    server = TnbServer()
    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(server))
    print(f"[TNB] Interface web sur http://{args.host}:{args.port}")
    print("[TNB] (capture/émission nécessitent les privilèges réseau — lancez en root)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[TNB] Arrêt.")
        if server.job and server.job.running:
            server.job.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
