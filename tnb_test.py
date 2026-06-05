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

    # Retour au sain : front 'clear' (exige un cycle complet sous le seuil bas).
    clear_seen = False
    for k in range(30, 120):
        payload = make_sv_payload("SV_1", k * 2, 50, 10, 100, 0, fault=False)
        for s in tnb.parse_sv_phaseA(payload):
            if det.feed(s) == "clear":
                clear_seen = True
    check(clear_seen, "front défaut->sain détecté")


def test_no_flapping_during_fault() -> None:
    print("test_no_flapping_during_fault (pas de tir fantôme aux passages par zéro)")
    model = tnb.FaultModel(freq=50, i_peak=10, v_peak=100, phase_deg=0, thr_factor=0.5)
    det = tnb.FaultDetector(model, debounce=2)
    onsets = clears = 0
    # 50 paquets (~100 échantillons, plusieurs cycles) de défaut soutenu :
    # la sinusoïde de défaut traverse zéro à chaque demi-cycle mais ne doit
    # produire qu'UN onset et aucun clear intempestif.
    for k in range(0, 50):
        for s in tnb.parse_sv_phaseA(make_sv_payload("F", k * 2, 50, 10, 100, 0,
                                                     fault=True, fault_i=200, fault_v=5)):
            ev = det.feed(s)
            if ev == "onset":
                onsets += 1
            elif ev == "clear":
                clears += 1
    check(onsets == 1, f"un seul onset sur tout le défaut (obtenu {onsets})")
    check(clears == 0, f"aucun clear pendant le défaut soutenu (obtenu {clears})")


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


def _make_cfg(refs):
    return tnb.RunConfig(
        iface="x", model=tnb.FaultModel(50, 10, 100, 0, 0.5),
        svid_filter=None, goose_appid=None, gocb_refs=refs,
        trip_bool_index=None, trip_timeout=0.5, num_shots=0,
        duration=None, debounce=2,
    )


def test_session_feed_e2e() -> None:
    print("test_session_feed_e2e (chemin MeasureSession.feed, comme le serveur)")
    refs = ["IED1/LLN0$GO$gcb", "IED2/LLN0$GO$gcb"]
    sess = tnb.MeasureSession(_make_cfg(refs))

    # Repos GOOSE : établit la base de stNum pour les deux VIED.
    for r in refs:
        sess.feed(tnb.ETH_P_GOOSE, make_goose_payload(0x3000, r, 1, 0, trip=False), 100.0)
    # Défaut : un payload SV = 2 ASDU => anti-rebond satisfait => onset à T0.
    # smpCnt=200 (hors passage par zéro) pour un écart franc sur les 2 échantillons.
    sess.feed(tnb.ETH_P_SV, make_sv_payload("SV", 200, 50, 10, 100, 0,
                                            fault=True, fault_i=200, fault_v=5), 101.0)
    check(sess.shot_index == 1, "un tir armé sur le front de défaut")
    # Trips GOOSE (stNum incrémenté).
    sess.feed(tnb.ETH_P_GOOSE, make_goose_payload(0x3000, refs[0], 2, 1, trip=True), 101.008)
    sess.feed(tnb.ETH_P_GOOSE, make_goose_payload(0x3000, refs[1], 2, 1, trip=True), 101.012)
    # Retour au sain.
    sess.feed(tnb.ETH_P_SV, make_sv_payload("SV", 100, 50, 10, 100, 0, fault=False), 102.0)
    sess.finalize()

    shot = sess.tracker.shots[0]
    check(abs((shot.trips[refs[0]] - shot.t0) * 1e3 - 8.0) < 1e-3, "latence VIED1 ≈ 8 ms")
    check(abs((shot.trips[refs[1]] - shot.t0) * 1e3 - 12.0) < 1e-3, "latence VIED2 ≈ 12 ms")


def test_compute_stats_and_verdict() -> None:
    print("test_compute_stats_and_verdict")
    refs = ["A", "B"]
    tr = tnb.TripTracker(gocb_refs=refs, trip_bool_index=None, trip_timeout=1.0)
    tr.on_fault_onset(1, 0.0)
    tr.on_goose("A", 2, [BoolData(True)], 0.008)
    tr.on_goose("B", 2, [BoolData(True)], 0.012)
    tr.on_fault_clear()

    st = tnb.compute_stats(tr, max_latency_ms=50.0)
    check(st["n_shots"] == 1, "1 tir comptabilisé")
    check(st["global_pass"] is True, "verdict global PASS sous seuil 50 ms")
    by = {v["gocb_ref"]: v for v in st["vieds"]}
    check(abs(by["A"]["mean"] - 8.0) < 1e-3, "moyenne A = 8 ms")

    st2 = tnb.compute_stats(tr, max_latency_ms=10.0)
    by2 = {v["gocb_ref"]: v for v in st2["vieds"]}
    check(by2["A"]["verdict"] is True and by2["B"]["verdict"] is False,
          "seuil 10 ms : A PASS, B FAIL")
    check(st2["global_pass"] is False, "verdict global FAIL si un VIED dépasse")


def test_parse_4i4u_and_6i3u() -> None:
    print("test_parse_4i4u_and_6i3u (phase A extraite des deux formats)")
    def ch(v):
        return struct.pack("!i", v) + b"\x00\x00\x00\x00"
    # 4I4U : Ia,Ib,Ic,In, Ua,Ub,Uc,Un  -> Va en voie 4 (64 octets)
    seq4 = b"".join(ch(x) for x in [2588, -9659, 7071, 0, 12000, -6000, -6000, 0])
    ia, va = tnb._phaseA_from_seqdata(seq4)
    check(len(seq4) == 64, "seqData 4I4U = 64 octets")
    check(abs(ia - 2.588) < 1e-6 and abs(va - 120.0) < 1e-6, "4I4U : Ia voie 0, Va voie 4")
    # 6I3U : Ia,Ib,Ic,Ires,In,Ih, Ua,Ub,Uc -> Va en voie 6 (72 octets)
    seq6 = b"".join(ch(x) for x in [2588, -9659, 7071, 0, 0, 0, 12000, -6000, -6000])
    ia6, va6 = tnb._phaseA_from_seqdata(seq6)
    check(len(seq6) == 72 and abs(va6 - 120.0) < 1e-6, "6I3U : Va voie 6")


def test_per_vied_member() -> None:
    print("test_per_vied_member (DO/DA de trip choisi par VIED)")
    refs = ["X", "Y"]
    # X : trip sur le membre d'index 1 ; Y : pas de membre -> repli sur stNum.
    tr = tnb.TripTracker(refs, trip_bool_index=None, trip_timeout=1.0,
                         trip_members={"X": 1})
    # Repos : établit les bases (membres et stNum).
    tr.on_goose("X", 1, [BoolData(False), BoolData(False)], 0.0)
    tr.on_goose("Y", 5, [BoolData(False)], 0.0)
    tr.on_fault_onset(1, 1.0)
    # X : index 0 bascule (non surveillé) -> pas de trip ; stNum inchangé.
    tr.on_goose("X", 1, [BoolData(True), BoolData(False)], 1.003)
    check("X" not in tr.shots[0].trips, "X : pas de trip si le DA surveillé reste False")
    # X : index 1 (surveillé) passe True -> trip.
    tr.on_goose("X", 1, [BoolData(True), BoolData(True)], 1.006)
    check(abs((tr.shots[0].trips["X"] - 1.0) * 1e3 - 6.0) < 1e-3, "X : trip sur le DA d'index 1 à 6 ms")
    # Y : sans membre configuré, trip au changement de stNum.
    tr.on_goose("Y", 6, [BoolData(False)], 1.009)
    check(abs((tr.shots[0].trips["Y"] - 1.0) * 1e3 - 9.0) < 1e-3, "Y : trip via incrément stNum à 9 ms")


def main() -> int:
    for fn in (
        test_sv_parse_and_detect,
        test_no_flapping_during_fault,
        test_fault_to_zero,
        test_goose_decode_and_trip,
        test_end_to_end_latency,
        test_timeout_miss,
        test_bool_index_trigger,
        test_session_feed_e2e,
        test_compute_stats_and_verdict,
        test_parse_4i4u_and_6i3u,
        test_per_vied_member,
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
