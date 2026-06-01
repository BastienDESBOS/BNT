#!/usr/bin/env python3
"""Tests hors-ligne de tnb.py : parsing SV, détection de défaut, appariement
T0->T1, statistiques. Aucune capture réseau ni privilège requis.

Lance : python3 tnb_test.py
"""
from __future__ import annotations

import math
import struct
import sys
from datetime import datetime, timezone

import tnb
from goose61850.codec import encode_goose_pdu
from goose61850.types import GoosePDU
from iec_data import BoolData

SMP_PER_SEC = tnb.SMP_PER_SEC
I_SCALE = tnb.I_SCALE
V_SCALE = tnb.V_SCALE

_failures = 0


def check(cond: bool, msg: str) -> None:
    global _failures
    status = "ok  " if cond else "FAIL"
    if not cond:
        _failures += 1
    print(f"  [{status}] {msg}")


# --------------------------------------------------------------------------- #
# Mini-encodeur SV reproduisant exactement le format de rt_sender.c
# --------------------------------------------------------------------------- #
def _ber_tl(tag: int, length: int) -> bytes:
    if length < 128:
        return bytes([tag, length])
    return bytes([tag, 0x81, length])


def _encode_seqdata_6i3u(smp_cnt: int, freq: float, i_peak: float, v_peak: float,
                         phase_deg: float, fault: bool,
                         fault_i: float, fault_v: float, fault_phase: float) -> bytes:
    vals = [0] * 9
    if freq > 0:
        t = smp_cnt / SMP_PER_SEC
        ph = 2.0 * math.pi * freq * t
        ia_peak = fault_i if fault else i_peak
        ph_ia = ph - math.radians(fault_phase if fault else phase_deg)
        ia = ia_peak * math.sin(ph_ia)
        ph_bc = ph - math.radians(phase_deg)
        ib = i_peak * math.sin(ph_bc - 2 * math.pi / 3)
        ic = i_peak * math.sin(ph_bc - 4 * math.pi / 3)
        vals[0] = round(ia * I_SCALE)
        vals[1] = round(ib * I_SCALE)
        vals[2] = round(ic * I_SCALE)
        vals[3] = round((ia + ib + ic) * I_SCALE)
        va_peak = fault_v if fault else v_peak
        vals[6] = round(va_peak * math.sin(ph) * V_SCALE)
        vals[7] = round(v_peak * math.sin(ph - 2 * math.pi / 3) * V_SCALE)
        vals[8] = round(v_peak * math.sin(ph - 4 * math.pi / 3) * V_SCALE)
    out = b""
    for v in vals:
        out += struct.pack("!i", v) + b"\x00\x00\x00\x00"
    return out


def _encode_asdu(svid: str, smp_cnt: int, seqdata: bytes) -> bytes:
    svid_b = svid.encode()
    body = (
        _ber_tl(0x80, len(svid_b)) + svid_b
        + _ber_tl(0x82, 2) + struct.pack("!H", smp_cnt)
        + _ber_tl(0x83, 4) + struct.pack("!I", 1)
        + _ber_tl(0x85, 1) + b"\x02"
        + _ber_tl(0x87, len(seqdata)) + seqdata
    )
    return _ber_tl(0x30, len(body)) + body


def make_sv_payload(svid: str, smp_base: int, freq: float, i_peak: float, v_peak: float,
                    phase_deg: float, fault: bool, fault_i=0.0, fault_v=0.0,
                    fault_phase=0.0) -> bytes:
    """Construit un payload SV (header 8o + savPdu, 2 ASDU)."""
    a0 = _encode_asdu(svid, smp_base, _encode_seqdata_6i3u(
        smp_base, freq, i_peak, v_peak, phase_deg, fault, fault_i, fault_v, fault_phase))
    a1 = _encode_asdu(svid, smp_base + 1, _encode_seqdata_6i3u(
        smp_base + 1, freq, i_peak, v_peak, phase_deg, fault, fault_i, fault_v, fault_phase))
    seq = a0 + a1
    sav_content = _ber_tl(0x80, 1) + b"\x02" + _ber_tl(0xA2, len(seq)) + seq
    sav = _ber_tl(0x60, len(sav_content)) + sav_content
    header = b"\x40\x00" + struct.pack("!H", 8 + len(sav)) + b"\x00\x00\x00\x00"
    return header + sav


def make_goose_payload(app_id: int, gocb_ref: str, st_num: int, sq_num: int,
                       trip: bool) -> bytes:
    pdu = GoosePDU(
        gocb_ref=gocb_ref, time_allowed_to_live=2000, dat_set="DS", go_id="GO",
        timestamp=datetime.now(timezone.utc), st_num=st_num, sq_num=sq_num,
        simulation=False, conf_rev=1, nds_com=False, num_dat_set_entries=1,
        all_data=[BoolData(trip)],
    )
    apdu = encode_goose_pdu(pdu)
    header = app_id.to_bytes(2, "big") + (8 + len(apdu)).to_bytes(2, "big") + b"\x00\x00\x00\x00"
    return header + apdu


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_sv_parse_and_detect() -> None:
    print("test_sv_parse_and_detect")
    model = tnb.FaultModel(freq=50, i_peak=10, v_peak=100, phase_deg=0, thr_factor=0.5)
    det = tnb.FaultDetector(model, debounce=2)

    # Quelques échantillons sains : aucun front.
    healthy_events = []
    for k in range(0, 20):
        payload = make_sv_payload("SV_1", k * 2, 50, 10, 100, 0, fault=False)
        samples = tnb.parse_sv_phaseA(payload)
        check(len(samples) == 2, f"2 ASDU décodés (k={k})") if k == 0 else None
        for s in samples:
            ev = det.feed(s)
            if ev:
                healthy_events.append(ev)
    check(healthy_events == [], "aucun front pendant la phase saine")
    check(abs(samples[0].ia) <= 10.001, "Ia sain dans l'amplitude attendue")

    # Bascule en défaut (court-circuit phase A : gros courant).
    onset_seen = False
    for k in range(20, 30):
        payload = make_sv_payload("SV_1", k * 2, 50, 10, 100, 0,
                                  fault=True, fault_i=200, fault_v=5)
        for s in tnb.parse_sv_phaseA(payload):
            ev = det.feed(s)
            if ev == "onset":
                onset_seen = True
    check(onset_seen, "front sain->défaut détecté")

    # Retour au sain : front 'clear'.
    clear_seen = False
    for k in range(30, 40):
        payload = make_sv_payload("SV_1", k * 2, 50, 10, 100, 0, fault=False)
        for s in tnb.parse_sv_phaseA(payload):
            if det.feed(s) == "clear":
                clear_seen = True
    check(clear_seen, "front défaut->sain détecté")


def test_fault_to_zero() -> None:
    print("test_fault_to_zero (--fault par défaut : phase A forcée à zéro)")
    model = tnb.FaultModel(freq=50, i_peak=10, v_peak=100, phase_deg=0, thr_factor=0.5)
    det = tnb.FaultDetector(model, debounce=2)
    # Flux sain 50 Hz, puis défaut qui annule la phase A (fault_i=fault_v=0).
    # On préchauffe en sain pour armer l'état, puis on injecte le défaut.
    for k in range(0, 10):
        for s in tnb.parse_sv_phaseA(make_sv_payload("Z", k * 2, 50, 10, 100, 0, fault=False)):
            det.feed(s)
    onset = False
    for k in range(10, 60):
        for s in tnb.parse_sv_phaseA(make_sv_payload("Z", k * 2, 50, 10, 100, 0,
                                                      fault=True, fault_i=0, fault_v=0)):
            if det.feed(s) == "onset":
                onset = True
    check(onset, "défaut 'phase A à zéro' détecté contre le flux sain attendu")


def test_goose_decode_and_trip() -> None:
    print("test_goose_decode_and_trip")
    from goose61850.codec import decode_goose_pdu
    payload = make_goose_payload(0x1000, "IED1/LLN0$GO$gcb", st_num=5, sq_num=3, trip=True)
    app_id = int.from_bytes(payload[0:2], "big")
    length = int.from_bytes(payload[2:4], "big")
    pdu = decode_goose_pdu(payload[8:length])
    check(app_id == 0x1000, "APPID GOOSE relu")
    check(pdu.gocb_ref == "IED1/LLN0$GO$gcb", "gocbRef relu")
    check(pdu.st_num == 5, "stNum relu")
    check(isinstance(pdu.all_data[0], BoolData) and pdu.all_data[0].value is True,
          "booléen trip relu = True")


def test_end_to_end_latency() -> None:
    print("test_end_to_end_latency (appariement T0->T1, 2 VIED)")
    refs = ["IED1/LLN0$GO$gcb", "IED2/LLN0$GO$gcb"]
    tracker = tnb.TripTracker(gocb_refs=refs, trip_bool_index=None, trip_timeout=0.5)

    # État de repos : on a vu un stNum stable pour les deux VIED.
    tracker.on_goose(refs[0], st_num=1, all_data=[BoolData(False)], t1=100.0)
    tracker.on_goose(refs[1], st_num=1, all_data=[BoolData(False)], t1=100.0)

    # Tir #1 : défaut à T0 = 101.0.
    tracker.on_fault_onset(1, t0=101.0)
    # VIED1 trip 8 ms après, VIED2 trip 12 ms après (stNum incrémenté).
    tracker.on_goose(refs[0], st_num=2, all_data=[BoolData(True)], t1=101.008)
    tracker.on_goose(refs[1], st_num=2, all_data=[BoolData(True)], t1=101.012)
    # Trame plus tardive ne doit pas écraser le premier trip.
    tracker.on_goose(refs[0], st_num=2, all_data=[BoolData(True)], t1=101.050)
    tracker.on_fault_clear()

    shot = tracker.shots[0]
    check(abs((shot.trips[refs[0]] - shot.t0) * 1e3 - 8.0) < 1e-6, "latence VIED1 = 8 ms")
    check(abs((shot.trips[refs[1]] - shot.t0) * 1e3 - 12.0) < 1e-6, "latence VIED2 = 12 ms")


def test_timeout_miss() -> None:
    print("test_timeout_miss (trip hors délai = échec)")
    refs = ["IEDx"]
    tracker = tnb.TripTracker(gocb_refs=refs, trip_bool_index=None, trip_timeout=0.1)
    tracker.on_goose("IEDx", st_num=1, all_data=[BoolData(False)], t1=10.0)
    tracker.on_fault_onset(1, t0=11.0)
    # Trip arrive 200 ms après -> > timeout 100 ms -> ignoré.
    tracker.on_goose("IEDx", st_num=2, all_data=[BoolData(True)], t1=11.2)
    check("IEDx" not in tracker.shots[0].trips, "trip hors délai non compté")


def test_bool_index_trigger() -> None:
    print("test_bool_index_trigger (déclencheur = booléen TRUE, pas stNum)")
    refs = ["IEDb"]
    tracker = tnb.TripTracker(gocb_refs=refs, trip_bool_index=0, trip_timeout=1.0)
    tracker.on_fault_onset(1, t0=0.0)
    # stNum change mais booléen reste False -> pas de trip.
    tracker.on_goose("IEDb", st_num=9, all_data=[BoolData(False)], t1=0.005)
    check("IEDb" not in tracker.shots[0].trips, "pas de trip tant que booléen False")
    # Booléen passe True -> trip.
    tracker.on_goose("IEDb", st_num=9, all_data=[BoolData(True)], t1=0.010)
    check(abs((tracker.shots[0].trips["IEDb"] - 0.0) * 1e3 - 10.0) < 1e-6,
          "trip sur booléen True à 10 ms")


def main() -> int:
    for fn in (
        test_sv_parse_and_detect,
        test_fault_to_zero,
        test_goose_decode_and_trip,
        test_end_to_end_latency,
        test_timeout_miss,
        test_bool_index_trigger,
    ):
        fn()
    print()
    if _failures:
        print(f"ÉCHEC : {_failures} assertion(s) en échec.")
        return 1
    print("Tous les tests passent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
