# BNT — Test Nominal de Base

Mesure de latence d'une chaîne de protection IEC 61850 virtualisée (deux VIED) :
**flux SV avec défaut → trip GOOSE en retour**, sur un même hôte.

- `tnb.py` — l'utilitaire CLI (capture + détection + statistiques + verdict).
- `tnb_server.py` + `tnb_gui.html` — **interface web d'administration** (démarrer/
  arrêter, suivi en direct, résultats + verdict, profils mémorisés, scan GOOSE/SV).
- `tnb_test.py` — tests hors-ligne (aucun réseau ni privilège requis) :
  `python3 tnb_test.py`.
- `po/` — sous-module [insatomcat/po](https://github.com/insatomcat/po) :
  plateforme IEC 61850 fournissant le générateur SV (`rt_sender`) et le décodeur
  GOOSE pur (`goose61850`, `iec_data`) réutilisés ici.

## Interface web

```bash
sudo python3 tnb_server.py --port 7060      # capture/émission => privilèges réseau
# puis ouvrir http://localhost:7060
```

La GUI permet de :
- **démarrer / arrêter** une campagne et la suivre **en direct** (tirs, journal) ;
- **oscilloscope** du signal SV capté (phase A I/V) en temps réel ;
- **histogramme des latences** qui se remplit tir après tir (abscisse = latence,
  ordonnée = occurrences) ;
- **résultats par VIED + verdict** PASS/FAIL et **export CSV** ;
- choisir, pour chacun des **2 VIED**, le **DO/DA** (membre du dataset) qui porte
  le trip — le scan décode et liste les membres, et présélectionne un booléen ;
- **scanner** le trafic pour lister les GOOSE/SV (clic = ajout d'un VIED ou du svID) ;
- **profils** de paramètres et **auto-complétion** des valeurs déjà saisies
  (svID, gocbRef, MAC, APPID…), persistés dans `tnb_store.json`.

### Cadence des tirs

Chaque **fenêtre de défaut** dans le flux SV = **un tir**, mesuré séquentiellement.
La détection arme un tir sur le front montant (T0 précis) et ne le referme qu'après
un cycle réseau complet revenu au sain — ce qui évite qu'une sinusoïde en défaut,
qui repasse par zéro à chaque demi-cycle, ne génère des tirs fantômes. La cadence
est donc imposée par `fault-cycle` du générateur (un tir tous les `2×fault_cycle` s).

## Installation

```bash
git clone --recursive https://github.com/BastienDESBOS/BNT.git
# ou, si déjà cloné sans --recursive :
git submodule update --init --recursive
```

`tnb.py` localise le dépôt `po` automatiquement (sous-module `./po`, voisin
`../po`) ou via la variable d'environnement `PO_HOME=/chemin/vers/po`.

## Principe

```
   flux SV (0x88BA) défaut ─►┐   1 socket AF_PACKET    ┌─► GOOSE trip (0x88B8)
   phase A bascule           │   + SO_TIMESTAMPNS      │   stNum s'incrémente
                             └─► (horloge noyau unique)┘
   T0 = ts du 1er paquet SV en défaut
   T1 = ts du 1er GOOSE trip de chaque VIED
   latence = T1 − T0   (par VIED, par tir)
```

- **T0** : pour chaque paquet SV, l'échantillon phase A *sain attendu* est
  reconstruit depuis `smpCnt` (`ia = i_peak·sin(2π·f·smpCnt/4800 − φ)`). Quand le
  mesuré s'en écarte de plus de `thr_factor × amplitude`, c'est le défaut.
- **T1** : par `gocbRef` (un VIED), premier GOOSE dont le `stNum` change après T0
  (ou, avec `--trip-bool-index N`, premier où `allData[N]` passe à `True`).
- Le mode `--fault` de `rt_sender` rejoue le défaut tous les `2 × fault_cycle`
  secondes : chaque cycle = un **tir**. On agrège N tirs.

La capture est brute (socket maison) et **n'utilise pas scapy** ; seul le
décodeur GOOSE pur du dépôt `po` (`goose61850.codec`) est réutilisé.

## Pré-requis

- Tourner sur le **même hôte** que le contrôle-commande (horloge unique).
- Privilèges réseau : `sudo` ou `CAP_NET_RAW` (capture `AF_PACKET`).
- Compiler le générateur SV si on veut que `tnb.py` l'émette :
  `cc -O2 -o po/rt_sender po/svgenerator/rt_sender.c -lm`

## Exemples

### A. tnb.py émet le flux SV et mesure (tout-en-un)

```bash
sudo python3 tnb.py processbus \
  --rt-sender ./po/rt_sender --svid SV_TNB \
  --sv-appid 0x4000 --sv-conf-rev 1 \
  --src-mac 01:0c:cd:04:00:01 --dst-mac 01:0c:cd:04:00:02 \
  --freq 50 --i-peak 10 --v-peak 100 \
  --fault-i-peak 200 --fault-v-peak 5 --fault-cycle 2 \
  --gocb-ref "VIED1/LLN0\$GO\$gcbTrip" \
  --gocb-ref "VIED2/LLN0\$GO\$gcbTrip" \
  --goose-appid 0x3000 \
  --shots 20 --max-latency-ms 50 --csv tnb.csv
```

### B. Le flux SV est déjà émis ailleurs (po service / svctl) — mesure seule

```bash
sudo python3 tnb.py processbus \
  --svid SV_TNB --freq 50 --i-peak 10 --v-peak 100 \
  --gocb-ref "VIED1/LLN0\$GO\$gcbTrip" \
  --gocb-ref "VIED2/LLN0\$GO\$gcbTrip" \
  --shots 20 --max-latency-ms 50
```

Sans `--gocb-ref`, les VIED sont découverts automatiquement et tous reportés.

## Paramètres clés

| Option | Rôle |
|---|---|
| `--freq/--i-peak/--v-peak/--phase` | flux **sain attendu** (doit matcher l'émission) |
| `--thr-factor` | sensibilité de détection du défaut (fraction de l'amplitude) |
| `--gocb-ref` (×2) | les deux VIED ; sinon auto-découverte |
| `--trip-bool-index` | déclencheur = booléen précis du dataset (sinon : incrément stNum) |
| `--trip-timeout-ms` | au-delà, le tir est compté en échec pour ce VIED |
| `--shots` / `--duration` | taille de la campagne |
| `--max-latency-ms` | seuil pass/fail |
| `--csv` | export du détail par tir |

Le code de retour est `0` si le verdict global est PASS, `1` sinon.
