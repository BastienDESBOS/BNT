#!/usr/bin/env python3
"""
TNB — Test Nominal de Base.

Mesure de bout en bout d'une chaîne de protection virtualisée (deux VIED) :

  1. on émet (ou on laisse émettre) un flux SV IEC 61869-9 contenant un défaut
     périodique sur la phase A (mode --fault de rt_sender) ;
  2. on capture SV (ethertype 0x88BA) ET GOOSE (0x88B8) sur la même interface,
     via un unique socket brut horodaté par le noyau (SO_TIMESTAMPNS) : les deux
     évènements partagent donc la même horloge et sont directement soustractibles ;
  3. pour chaque apparition de défaut (T0, détectée sur le flux SV) on mesure la
     latence jusqu'au premier GOOSE de déclenchement de chaque VIED (T1) ;
  4. on agrège N tirs et on rend min/moy/max/écart-type + taux de réussite et un
     verdict pass/fail par VIED.

Conçu pour tourner sur le même hôte que le contrôle-commande virtualisé
(horloge unique). Nécessite les privilèges réseau (CAP_NET_RAW / root) pour la
capture brute.

Réutilise le décodeur GOOSE pur du dépôt (goose61850.codec + iec_data) sans
dépendre de scapy : la capture se fait avec un socket AF_PACKET maison.
"""
from __future__ import annotations

import argparse
import math
import os
import signal
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import types as _types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Import du décodeur GOOSE pur (sans déclencher goose61850/__init__.py -> scapy)
# --------------------------------------------------------------------------- #
def _locate_po_root() -> Path:
    """Localise la racine du dépôt `po` (qui fournit iec_data + goose61850).

    Ordre : variable d'env PO_HOME, puis dépôt vendu/sous-module local, puis un
    voisin `../po`. tnb.py peut ainsi vivre hors de `po` (ex. repo BNT)."""
    here = Path(__file__).resolve().parent
    candidates = []
    env = os.environ.get("PO_HOME")
    if env:
        candidates.append(Path(env))
    candidates += [
        here,                 # tnb.py est à la racine de po
        here / "po",          # po vendu/sous-module sous le repo courant
        here.parent / "po",   # po voisin (../po)
    ]
    for c in candidates:
        if (c / "iec_data.py").is_file() and (c / "goose" / "goose61850").is_dir():
            return c
    raise SystemExit(
        "TNB: dépôt 'po' introuvable (iec_data.py + goose/goose61850). "
        "Définissez PO_HOME=/chemin/vers/po."
    )


_ROOT = _locate_po_root()
_GOOSE_PKG_DIR = _ROOT / "goose" / "goose61850"
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))  # pour `import iec_data`

# On enregistre un package « goose61850 » minimal pointant sur le bon dossier,
# sans exécuter son __init__ (qui importe transport -> scapy). Les imports
# relatifs des sous-modules (from .types import ...) restent ainsi valides.
if "goose61850" not in sys.modules:
    _pkg = _types.ModuleType("goose61850")
    _pkg.__path__ = [str(_GOOSE_PKG_DIR)]  # type: ignore[attr-defined]
    sys.modules["goose61850"] = _pkg

from goose61850.codec import decode_goose_pdu  # noqa: E402
from iec_data import BoolData  # noqa: E402

# --------------------------------------------------------------------------- #
# Constantes protocole / format SV (cf. rt_sender.c)
# --------------------------------------------------------------------------- #
ETH_P_ALL = 0x0003
ETH_P_8021Q = 0x8100
ETH_P_SV = 0x88BA
ETH_P_GOOSE = 0x88B8

SMP_PER_SEC = 4800       # rt_sender : 4800 échantillons/s
I_SCALE = 1000           # rt_sender : courants ×1000
V_SCALE = 100            # rt_sender : tensions ×100

# Disposition seqData (rt_sender) : Ia,Ib,Ic,Ires,In,Ih (6 I) puis Va,Vb,Vc (3 U),
# chaque canal = INT32 valeur (BE) + 4 octets qualité. 6I3U => 72 octets.
SEQDATA_6I3U = 72
SEQDATA_4I4U = 64        # variante 9-2LE : 4 I + 4 U, Va en canal index 4


# --------------------------------------------------------------------------- #
# Lecture BER minimale (identique à svgenerator/receiver.py)
# --------------------------------------------------------------------------- #
def _read_ber_tag_len(data: bytes, off: int) -> Tuple[Optional[int], int, int]:
    if off >= len(data):
        return None, 0, off
    tag = data[off]
    off += 1
    if off >= len(data):
        return tag, 0, off
    L = data[off]
    off += 1
    if L & 0x80:
        n = L & 0x7F
        L = 0
        for _ in range(n):
            if off >= len(data):
                return tag, 0, off
            L = (L << 8) | data[off]
            off += 1
    return tag, L, off


@dataclass
class SvSample:
    """Un ASDU SV décodé pour les besoins de la détection de défaut."""
    svid: str
    smp_cnt: int
    ia: float        # courant phase A (ampères)
    va: float        # tension phase A (volts)


def parse_sv_phaseA(payload: bytes) -> List[SvSample]:
    """Parse un payload SV (en-tête 8 octets + savPdu) et extrait, par ASDU,
    le courant et la tension de la phase A (canaux 0 et premier U)."""
    out: List[SvSample] = []
    if len(payload) < 8:
        return out
    off = 8

    tag, _sav_len, off = _read_ber_tag_len(payload, off)
    if tag != 0x60:
        return out
    tag, no_len, off = _read_ber_tag_len(payload, off)
    if tag != 0x80 or no_len != 1 or off >= len(payload):
        return out
    no_asdu = payload[off]
    off += 1
    tag, seq_len, off = _read_ber_tag_len(payload, off)
    if tag != 0xA2:
        return out
    seq_end = off + seq_len
    if seq_end > len(payload):
        seq_end = len(payload)

    for _ in range(no_asdu):
        if off >= seq_end:
            break
        tag, asdu_len, off = _read_ber_tag_len(payload, off)
        if tag != 0x30:
            off += asdu_len
            continue
        asdu_end = min(off + asdu_len, len(payload))
        svid: Optional[str] = None
        smp_cnt: Optional[int] = None
        seqdata: Optional[bytes] = None
        while off < asdu_end:
            t, L, off = _read_ber_tag_len(payload, off)
            if off + L > len(payload):
                break
            val = payload[off:off + L]
            off += L
            if t == 0x80:
                svid = val.decode("utf-8", errors="replace")
            elif t == 0x82 and L == 2:
                smp_cnt = struct.unpack("!H", val)[0]
            elif t == 0x87:
                seqdata = val
        off = asdu_end
        if svid is None or smp_cnt is None or seqdata is None:
            continue
        ia, va = _phaseA_from_seqdata(seqdata)
        if ia is None:
            continue
        out.append(SvSample(svid=svid, smp_cnt=smp_cnt, ia=ia, va=va))
    return out


def _phaseA_from_seqdata(seqdata: bytes) -> Tuple[Optional[float], Optional[float]]:
    """Renvoie (Ia, Va) en unités physiques depuis le bloc seqData."""
    if len(seqdata) >= SEQDATA_6I3U:
        v_index = 6           # 6 courants puis tensions => Va = canal 6
    elif len(seqdata) >= SEQDATA_4I4U:
        v_index = 4           # 4 courants puis tensions => Va = canal 4
    else:
        return None, None
    ia_raw = struct.unpack("!i", seqdata[0:4])[0]
    va_off = v_index * 8
    va_raw = struct.unpack("!i", seqdata[va_off:va_off + 4])[0]
    return ia_raw / I_SCALE, va_raw / V_SCALE


# --------------------------------------------------------------------------- #
# Détection de défaut sur la phase A
# --------------------------------------------------------------------------- #
@dataclass
class FaultModel:
    """Paramètres du flux sain attendu, pour reconstruire l'échantillon phase A."""
    freq: float
    i_peak: float
    v_peak: float
    phase_deg: float
    thr_factor: float = 0.5   # fraction de l'amplitude au-delà de laquelle = défaut

    def expected(self, smp_cnt: int) -> Tuple[float, float]:
        if self.freq <= 0.0:
            return 0.0, 0.0
        t = smp_cnt / SMP_PER_SEC
        ph = 2.0 * math.pi * self.freq * t
        ia = self.i_peak * math.sin(ph - math.radians(self.phase_deg))
        va = self.v_peak * math.sin(ph)
        return ia, va

    def is_fault(self, s: SvSample) -> bool:
        ia_exp, va_exp = self.expected(s.smp_cnt)
        # Référence d'écart : l'amplitude crête (avec un plancher pour le mode zéro).
        thr_i = self.thr_factor * max(self.i_peak, 1e-6)
        thr_v = self.thr_factor * max(self.v_peak, 1e-6)
        if abs(s.ia - ia_exp) > thr_i:
            return True
        if abs(s.va - va_exp) > thr_v:
            return True
        return False


class FaultDetector:
    """Machine à états sain/défaut avec anti-rebond, émettant les fronts de tir."""

    def __init__(self, model: FaultModel, debounce: int = 2):
        self.model = model
        self.debounce = debounce
        self.in_fault = False
        self._fault_run = 0
        self._healthy_run = 0

    def feed(self, s: SvSample) -> Optional[str]:
        """Retourne 'onset' (front sain->défaut), 'clear' (défaut->sain) ou None."""
        if self.model.is_fault(s):
            self._fault_run += 1
            self._healthy_run = 0
            if not self.in_fault and self._fault_run >= self.debounce:
                self.in_fault = True
                return "onset"
        else:
            self._healthy_run += 1
            self._fault_run = 0
            if self.in_fault and self._healthy_run >= self.debounce:
                self.in_fault = False
                return "clear"
        return None


# --------------------------------------------------------------------------- #
# Suivi des tirs et des trips GOOSE par VIED
# --------------------------------------------------------------------------- #
@dataclass
class Shot:
    index: int
    t0: float                                   # instant du défaut (s, horloge noyau)
    trips: Dict[str, float] = field(default_factory=dict)   # gocbRef -> T1
    baseline_stnum: Dict[str, int] = field(default_factory=dict)


class TripTracker:
    """Apparie les fronts de défaut (T0) aux trips GOOSE (T1) par gocbRef."""

    def __init__(
        self,
        gocb_refs: Optional[List[str]],
        trip_bool_index: Optional[int],
        trip_timeout: float,
    ):
        # gocb_refs explicites = les VIED attendus ; None => découverte automatique.
        self.expected_refs = gocb_refs
        self.trip_bool_index = trip_bool_index
        self.trip_timeout = trip_timeout
        self.last_stnum: Dict[str, int] = {}      # dernier stNum vu par gocbRef
        self.seen_refs: List[str] = list(gocb_refs) if gocb_refs else []
        self.current: Optional[Shot] = None
        self.shots: List[Shot] = []

    def _tracked(self, gocb_ref: str) -> bool:
        if self.expected_refs is None:
            if gocb_ref not in self.seen_refs:
                self.seen_refs.append(gocb_ref)
            return True
        return gocb_ref in self.expected_refs

    def on_goose(self, gocb_ref: str, st_num: int, all_data, t1: float) -> None:
        if not self._tracked(gocb_ref):
            return
        shot = self.current
        if shot is not None and gocb_ref not in shot.trips:
            base = shot.baseline_stnum.get(gocb_ref, self.last_stnum.get(gocb_ref))
            tripped = False
            if self.trip_bool_index is not None:
                idx = self.trip_bool_index
                if 0 <= idx < len(all_data) and isinstance(all_data[idx], BoolData):
                    tripped = bool(all_data[idx].value)
            else:
                tripped = base is None or st_num != base
            if tripped and (t1 - shot.t0) <= self.trip_timeout:
                shot.trips[gocb_ref] = t1
        self.last_stnum[gocb_ref] = st_num

    def on_fault_onset(self, index: int, t0: float) -> Shot:
        # Fige l'état stNum de référence (avant trip) pour chaque VIED connu.
        baseline = dict(self.last_stnum)
        shot = Shot(index=index, t0=t0, baseline_stnum=baseline)
        self.current = shot
        self.shots.append(shot)
        return shot

    def on_fault_clear(self) -> None:
        self.current = None


# --------------------------------------------------------------------------- #
# Capture brute horodatée par le noyau
# --------------------------------------------------------------------------- #
def _open_capture(iface: str) -> socket.socket:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    so_ts = getattr(socket, "SO_TIMESTAMPNS", 35)
    try:
        sock.setsockopt(socket.SOL_SOCKET, so_ts, 1)
    except OSError:
        pass
    return sock


def _kernel_ts(ancdata) -> Optional[float]:
    """Extrait l'horodatage noyau (SCM_TIMESTAMPNS) des données auxiliaires."""
    scm = getattr(socket, "SCM_TIMESTAMPNS", 35)
    for level, typ, data in ancdata:
        if level == socket.SOL_SOCKET and typ == scm and len(data) >= 16:
            secs, nsecs = struct.unpack("qq", data[:16])
            return secs + nsecs * 1e-9
    return None


def _ethertype_and_payload(frame: bytes) -> Tuple[Optional[int], bytes]:
    """Renvoie (ethertype, payload) en sautant l'éventuel tag VLAN 802.1Q."""
    if len(frame) < 14:
        return None, b""
    etype = (frame[12] << 8) | frame[13]
    if etype == ETH_P_8021Q:
        if len(frame) < 18:
            return None, b""
        inner = (frame[16] << 8) | frame[17]
        return inner, frame[18:]
    return etype, frame[14:]


# --------------------------------------------------------------------------- #
# Boucle de mesure
# --------------------------------------------------------------------------- #
@dataclass
class RunConfig:
    iface: str
    model: FaultModel
    svid_filter: Optional[str]
    goose_appid: Optional[int]
    gocb_refs: Optional[List[str]]
    trip_bool_index: Optional[int]
    trip_timeout: float
    num_shots: int
    duration: Optional[float]
    debounce: int


class MeasureSession:
    """État d'une campagne de mesure, alimentée trame par trame.

    Découplée de la capture réseau : utilisable depuis la boucle socket, depuis
    le serveur web (thread) ou depuis les tests (trames synthétiques)."""

    def __init__(self, cfg: RunConfig, on_event=None):
        self.cfg = cfg
        self.detector = FaultDetector(cfg.model, debounce=cfg.debounce)
        self.tracker = TripTracker(cfg.gocb_refs, cfg.trip_bool_index, cfg.trip_timeout)
        self.shot_index = 0
        self.on_event = on_event
        self.log: List[str] = []
        self.t_start: Optional[float] = None

    def _emit(self, msg: str) -> None:
        self.log.append(msg)
        if self.on_event:
            self.on_event(msg)

    def feed(self, etype: Optional[int], payload: bytes, ts: float) -> None:
        if etype == ETH_P_SV:
            for s in parse_sv_phaseA(payload):
                if self.cfg.svid_filter and s.svid != self.cfg.svid_filter:
                    continue
                ev = self.detector.feed(s)
                if ev == "onset":
                    self.shot_index += 1
                    self.tracker.on_fault_onset(self.shot_index, ts)
                    self._emit(f"Tir #{self.shot_index} : défaut SV "
                               f"(svID={s.svid}, smpCnt={s.smp_cnt}) à T0={ts:.6f}")
                elif ev == "clear":
                    self._close_shot()
                    self.tracker.on_fault_clear()
        elif etype == ETH_P_GOOSE:
            self._feed_goose(payload, ts)

    def _feed_goose(self, payload: bytes, ts: float) -> None:
        if len(payload) < 8:
            return
        app_id = int.from_bytes(payload[0:2], "big")
        length = int.from_bytes(payload[2:4], "big")
        if self.cfg.goose_appid is not None and app_id != self.cfg.goose_appid:
            return
        apdu = payload[8:length] if 8 < length <= len(payload) else payload[8:]
        try:
            pdu = decode_goose_pdu(apdu)
        except Exception:
            return
        cur = self.tracker.current
        had = cur is not None and pdu.gocb_ref in cur.trips
        self.tracker.on_goose(pdu.gocb_ref, pdu.st_num, pdu.all_data, ts)
        cur = self.tracker.current
        if cur is not None and not had and pdu.gocb_ref in cur.trips:
            lat = (cur.trips[pdu.gocb_ref] - cur.t0) * 1e3
            self._emit(f"    VIED {pdu.gocb_ref} : trip à +{lat:.3f} ms (tir #{cur.index})")

    def _close_shot(self) -> None:
        shot = self.tracker.current
        if shot is None:
            return
        for ref in (self.tracker.expected_refs or self.tracker.seen_refs):
            if ref not in shot.trips:
                self._emit(f"    VIED {ref} : AUCUN trip (timeout, tir #{shot.index})")

    def finalize(self) -> None:
        if self.tracker.current is not None:
            self._close_shot()
            self.tracker.on_fault_clear()

    def is_done(self) -> bool:
        return (bool(self.cfg.num_shots)
                and self.shot_index >= self.cfg.num_shots
                and self.tracker.current is None)


def _capture_loop(cfg: RunConfig, session: MeasureSession,
                  stop_event: threading.Event) -> None:
    """Boucle de capture brute alimentant `session` jusqu'à arrêt/fin/durée."""
    sock = _open_capture(cfg.iface)
    sock.settimeout(0.5)
    session.t_start = time.clock_gettime(time.CLOCK_REALTIME)
    try:
        while not stop_event.is_set():
            if session.is_done():
                break
            if cfg.duration is not None and \
                    time.clock_gettime(time.CLOCK_REALTIME) - session.t_start >= cfg.duration:
                break
            try:
                data, ancdata, _flags, _addr = sock.recvmsg(2048, 256)
            except (BlockingIOError, InterruptedError, socket.timeout):
                continue
            ts = _kernel_ts(ancdata)
            if ts is None:
                ts = time.clock_gettime(time.CLOCK_REALTIME)
            etype, payload = _ethertype_and_payload(data)
            session.feed(etype, payload, ts)
    finally:
        sock.close()
        session.finalize()


def run_measurement(cfg: RunConfig, on_event=print) -> TripTracker:
    """Lance une campagne (CLI) : SIGINT pour arrêter. Retourne le tracker."""
    session = MeasureSession(cfg, on_event=on_event)
    stop_event = threading.Event()
    old = None
    try:
        old = signal.signal(signal.SIGINT, lambda *_a: stop_event.set())
    except ValueError:
        old = None  # pas dans le thread principal
    if on_event:
        on_event(f"[TNB] Capture sur {cfg.iface} — SV svID={cfg.svid_filter or '*'}, "
                 f"GOOSE appid={'*' if cfg.goose_appid is None else hex(cfg.goose_appid)}, "
                 f"VIED={cfg.gocb_refs or 'auto'} (Ctrl+C pour arrêter)")
    try:
        _capture_loop(cfg, session, stop_event)
    finally:
        if old is not None:
            signal.signal(signal.SIGINT, old)
    return session.tracker


# --------------------------------------------------------------------------- #
# Scan : GOOSE (et svID SV) transitant sur l'interface
# --------------------------------------------------------------------------- #
def scan_traffic(iface: str, duration: float = 5.0,
                 stop_event: Optional[threading.Event] = None) -> dict:
    """Écoute `duration` secondes et inventorie les GOOSE et flux SV vus.

    GOOSE indexés par (gocbRef, appID, src_mac) ; SV par (svID, appID, src_mac)."""
    sock = _open_capture(iface)
    sock.settimeout(0.5)
    goose: Dict[Tuple[str, int, str], dict] = {}
    sv: Dict[Tuple[str, int, str], dict] = {}
    t_end = time.clock_gettime(time.CLOCK_REALTIME) + duration
    try:
        while time.clock_gettime(time.CLOCK_REALTIME) < t_end:
            if stop_event is not None and stop_event.is_set():
                break
            try:
                data, _anc, _f, _a = sock.recvmsg(2048, 256)
            except (BlockingIOError, InterruptedError, socket.timeout):
                continue
            src_mac = ":".join(f"{b:02x}" for b in data[6:12]) if len(data) >= 12 else "?"
            dst_mac = ":".join(f"{b:02x}" for b in data[0:6]) if len(data) >= 6 else "?"
            etype, payload = _ethertype_and_payload(data)
            if etype == ETH_P_GOOSE and len(payload) >= 8:
                app_id = int.from_bytes(payload[0:2], "big")
                length = int.from_bytes(payload[2:4], "big")
                apdu = payload[8:length] if 8 < length <= len(payload) else payload[8:]
                try:
                    pdu = decode_goose_pdu(apdu)
                except Exception:
                    continue
                key = (pdu.gocb_ref, app_id, src_mac)
                ent = goose.setdefault(key, {
                    "gocb_ref": pdu.gocb_ref, "go_id": pdu.go_id, "app_id": app_id,
                    "src_mac": src_mac, "dst_mac": dst_mac, "dat_set": pdu.dat_set,
                    "conf_rev": pdu.conf_rev, "count": 0,
                    "st_num": pdu.st_num, "sq_num": pdu.sq_num,
                    "num_entries": pdu.num_dat_set_entries,
                })
                ent["count"] += 1
                ent["st_num"] = pdu.st_num
                ent["sq_num"] = pdu.sq_num
            elif etype == ETH_P_SV and len(payload) >= 8:
                app_id = int.from_bytes(payload[0:2], "big")
                for s in parse_sv_phaseA(payload):
                    key = (s.svid, app_id, src_mac)
                    ent = sv.setdefault(key, {
                        "svid": s.svid, "app_id": app_id, "src_mac": src_mac,
                        "dst_mac": dst_mac, "count": 0, "last_smp_cnt": s.smp_cnt,
                    })
                    ent["count"] += 1
                    ent["last_smp_cnt"] = s.smp_cnt
    finally:
        sock.close()
    return {
        "goose": sorted(goose.values(), key=lambda e: (-e["count"], e["gocb_ref"])),
        "sv": sorted(sv.values(), key=lambda e: (-e["count"], e["svid"])),
    }


# --------------------------------------------------------------------------- #
# Statistiques et verdict
# --------------------------------------------------------------------------- #
def compute_stats(tracker: TripTracker, max_latency_ms: Optional[float]) -> dict:
    """Agrège le tracker en un dict JSON-sérialisable (CLI + serveur web)."""
    refs = tracker.expected_refs or tracker.seen_refs
    n_shots = len(tracker.shots)
    vieds: List[dict] = []
    rows: List[dict] = []
    all_ok = True
    for ref in refs:
        lats: List[float] = []
        for shot in tracker.shots:
            if ref in shot.trips:
                lat_ms = (shot.trips[ref] - shot.t0) * 1e3
                lats.append(lat_ms)
                rows.append({"gocb_ref": ref, "shot": shot.index, "latency_ms": lat_ms})
            else:
                rows.append({"gocb_ref": ref, "shot": shot.index, "latency_ms": None})
        success = len(lats)
        ref_ok = (success == n_shots and n_shots > 0)
        if max_latency_ms is not None and lats and max(lats) > max_latency_ms:
            ref_ok = False
        all_ok = all_ok and ref_ok
        vieds.append({
            "gocb_ref": ref,
            "success": success,
            "total": n_shots,
            "rate": (success / n_shots * 100.0) if n_shots else 0.0,
            "min": min(lats) if lats else None,
            "mean": statistics.fmean(lats) if lats else None,
            "max": max(lats) if lats else None,
            "std": statistics.pstdev(lats) if len(lats) > 1 else (0.0 if lats else None),
            "verdict": ref_ok,
        })
    return {
        "n_shots": n_shots,
        "max_latency_ms": max_latency_ms,
        "vieds": vieds,
        "rows": rows,
        "global_pass": all_ok and n_shots > 0,
    }


def report(tracker: TripTracker, max_latency_ms: Optional[float],
           csv_path: Optional[str]) -> bool:
    st = compute_stats(tracker, max_latency_ms)
    print("\n" + "=" * 60)
    print(f"TNB — {st['n_shots']} tir(s), {len(st['vieds'])} VIED")
    print("=" * 60)
    for v in st["vieds"]:
        print(f"\nVIED {v['gocb_ref']}")
        if v["success"]:
            print(f"  tirs réussis : {v['success']}/{v['total']} ({v['rate']:.0f} %)")
            print(f"  latence (ms) : min={v['min']:.3f}  moy={v['mean']:.3f}  "
                  f"max={v['max']:.3f}  σ={v['std']:.3f}")
        else:
            print(f"  tirs réussis : 0/{v['total']} — aucun trip détecté")
        seuil = (f"seuil ≤ {max_latency_ms:.3f} ms, " if max_latency_ms is not None else "")
        print(f"  verdict      : {'PASS' if v['verdict'] else 'FAIL'} "
              f"({seuil}100 % de réussite requis)")
    if csv_path:
        _write_csv(csv_path, st["rows"])
        print(f"\n[TNB] Détail écrit dans {csv_path}")
    print("\n" + "=" * 60)
    print(f"VERDICT GLOBAL TNB : {'PASS' if st['global_pass'] else 'FAIL'}")
    print("=" * 60)
    return st["global_pass"]


def _write_csv(path: str, rows: List[dict]) -> None:
    import csv
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["gocb_ref", "shot_index", "latency_ms"])
        for r in rows:
            lat = r["latency_ms"]
            w.writerow([r["gocb_ref"], r["shot"], "" if lat is None else f"{lat:.6f}"])


# --------------------------------------------------------------------------- #
# Lancement optionnel du générateur SV (rt_sender)
# --------------------------------------------------------------------------- #
def spawn_rt_sender(args: argparse.Namespace) -> Optional[subprocess.Popen]:
    if not args.rt_sender:
        return None
    cmd: List[str] = [
        args.rt_sender,
        "--freq", str(args.freq),
        "--i-peak", str(args.i_peak),
        "--v-peak", str(args.v_peak),
        "--phase", str(args.phase),
        "--fault",
        "--fault-i-peak", str(args.fault_i_peak),
        "--fault-v-peak", str(args.fault_v_peak),
        "--fault-phase", str(args.fault_phase),
        "--fault-cycle", str(args.fault_cycle),
        "--appid", str(args.sv_appid),
        "--conf-rev", str(args.sv_conf_rev),
    ]
    if args.vlan_id is not None:
        cmd += ["--vlan-id", str(args.vlan_id), "--vlan-priority", str(args.vlan_priority)]
    cmd += [args.iface, args.src_mac, args.dst_mac, args.svid or "SV_TNB"]
    print(f"[TNB] Démarrage du générateur SV : {' '.join(cmd)}")
    return subprocess.Popen(cmd)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="TNB — mesure de latence flux SV -> trip GOOSE (deux VIED).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("iface", help="Interface réseau de capture (et d'émission SV)")

    g_sv = p.add_argument_group("flux SV sain attendu (pour détecter le défaut)")
    g_sv.add_argument("--svid", default=None, help="Filtre svID (défaut: tous)")
    g_sv.add_argument("--freq", type=float, default=50.0, help="Fréquence (Hz)")
    g_sv.add_argument("--i-peak", type=float, default=10.0, help="Crête courant sain (A)")
    g_sv.add_argument("--v-peak", type=float, default=100.0, help="Crête tension saine (V)")
    g_sv.add_argument("--phase", type=float, default=0.0, help="Déphasage I/V (deg)")
    g_sv.add_argument("--thr-factor", type=float, default=0.5,
                      help="Seuil de défaut = fraction de l'amplitude crête")
    g_sv.add_argument("--debounce", type=int, default=2,
                      help="Échantillons consécutifs pour confirmer un front")

    g_g = p.add_argument_group("GOOSE / VIED")
    g_g.add_argument("--goose-appid", type=lambda x: int(x, 0), default=None,
                     help="Filtre APPID GOOSE (ex: 0x1000)")
    g_g.add_argument("--gocb-ref", action="append", dest="gocb_refs", default=None,
                     help="gocbRef d'un VIED (répéter pour les deux). Défaut: auto-découverte")
    g_g.add_argument("--trip-bool-index", type=int, default=None,
                     help="Index du booléen de trip dans allData (défaut: incrément stNum)")
    g_g.add_argument("--trip-timeout-ms", type=float, default=500.0,
                     help="Délai max après T0 pour considérer un trip")

    g_run = p.add_argument_group("campagne")
    g_run.add_argument("--shots", type=int, default=10, help="Nombre de tirs à mesurer (0=illimité)")
    g_run.add_argument("--duration", type=float, default=None,
                       help="Durée max de capture (s). Prioritaire sur l'arrêt par tirs si atteinte")
    g_run.add_argument("--max-latency-ms", type=float, default=None,
                       help="Seuil pass/fail de latence (ms)")
    g_run.add_argument("--csv", default=None, help="Chemin CSV de sortie (détail par tir)")

    g_gen = p.add_argument_group("génération SV optionnelle (rt_sender)")
    g_gen.add_argument("--rt-sender", default=None,
                       help="Chemin du binaire rt_sender pour émettre le flux SV")
    g_gen.add_argument("--src-mac", default="01:0c:cd:04:00:01")
    g_gen.add_argument("--dst-mac", default="01:0c:cd:04:00:02")
    g_gen.add_argument("--sv-appid", default="0x4000")
    g_gen.add_argument("--sv-conf-rev", default="1")
    g_gen.add_argument("--fault-i-peak", type=float, default=0.0)
    g_gen.add_argument("--fault-v-peak", type=float, default=0.0)
    g_gen.add_argument("--fault-phase", type=float, default=0.0)
    g_gen.add_argument("--fault-cycle", type=float, default=2.0,
                       help="Demi-cycle de défaut (s) : Xs sain puis Xs défaut, répété")
    g_gen.add_argument("--vlan-id", type=int, default=None)
    g_gen.add_argument("--vlan-priority", type=int, default=4)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    model = FaultModel(
        freq=args.freq, i_peak=args.i_peak, v_peak=args.v_peak,
        phase_deg=args.phase, thr_factor=args.thr_factor,
    )
    cfg = RunConfig(
        iface=args.iface,
        model=model,
        svid_filter=args.svid,
        goose_appid=args.goose_appid,
        gocb_refs=args.gocb_refs,
        trip_bool_index=args.trip_bool_index,
        trip_timeout=args.trip_timeout_ms / 1e3,
        num_shots=args.shots,
        duration=args.duration,
        debounce=args.debounce,
    )

    gen = spawn_rt_sender(args)
    try:
        tracker = run_measurement(cfg)
    finally:
        if gen is not None:
            gen.send_signal(signal.SIGINT)
            try:
                gen.wait(timeout=2)
            except subprocess.TimeoutExpired:
                gen.kill()

    ok = report(tracker, args.max_latency_ms, args.csv)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
