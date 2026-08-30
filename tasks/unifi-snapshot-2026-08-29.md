# Snapshot UniFi — 2026-08-29, pendant la panne réseau

Relevé au moment où le réseau est tombé, après le rollback de la migration Sonos
(VLAN 102 → LAN Maison). Site `default` (`5aca6e2de4b0d30c2f4be2fc`), UDM en
Network 10.x, gateway `78:45:58:eb:ab:9d` / `192.168.2.1`.

## 1. État des switchs au moment de la panne

`state`: 0 = déconnecté, 1 = connecté, 5 = provisioning, 9 = injoignable.

| Switch | Modèle | IP | MAC | device_id | state | uptime | uplink_depth |
|---|---|---|---|---|---|---|---|
| core-usw-13 | USMINI | 192.168.2.176 | `74:83:c2:0c:19:7d` | `5e7a0392d2371200704cd3ed` | **0 DOWN** | null | null |
| core-us-11 | US8 | 192.168.2.174 | `f0:9f:c2:1a:dc:a4` | `680ce5b139e6796885e7ec67` | **0 DOWN** | null | null |
| core-us-12 | US8P60 | 192.168.2.175 | `f0:9f:c2:c2:f8:c9` | `5aca75c0e4b0d30c2f4be349` | **0 DOWN** | null | null |
| core-usw-92 | USL16LP | 192.168.2.172 | `ac:8b:a9:19:57:0c` | `6389bec06273d32b66fcb75c` | **9 INJOIGNABLE** | null | null |
| core-usw-93 | USMINI | 192.168.2.173 | `74:83:c2:0c:19:5c` | `5e7a0703d2371200704ced8d` | 1 | **1417** (rebooté) | 1 |
| core-us-94 | US8 | 192.168.2.181 | `f0:9f:c2:1c:aa:5f` | `68416bada747ce5837b9e97b` | 1 | **1421** (rebooté) | 1 |
| core-ups-91 | USWDA24 | 192.168.2.180 | `1c:0b:8b:3c:10:ae` | `699b286afefd4d12846d7572` | 1 | 2136744 | 1 |
| core-agg-91 | USL8A | 192.168.2.171 | `78:45:58:6d:92:d1` | `63b4104b436b05056ac41c1f` | 1 | 52439 | null |
| core-usw-21 | USWED37 | 192.168.2.177 | `94:2a:6f:fe:24:74` | `680ca8a139e6796885e7c983` | 1 | 52051 | 2 |
| core-usw-22 | USWED35 | 192.168.2.178 | `84:78:48:68:81:ee` | `681091447cd6c65570a47eb6` | 1 | 51977 | 3 |
| core-usw-23 | USWED35 | 192.168.2.179 | `84:78:48:68:f7:5e` | `699af4c6fefd4d12846cb202` | 1 | 52010 | 3 |

**Lecture** : la branche saine (agg-91, usw-21/22/23) tourne depuis ~52 000 s
(14 h 30), intacte. Les trois switchs DOWN plus usw-92 forment le groupe touché.
usw-93 et us-94 ont redémarré il y a ~23 min — ils sont revenus, eux.

`core-usw-92` en state 9 avec 329 Mo émis contre 10 Mo reçus : asymétrie forte,
compatible avec une boucle ou un port qui inonde.

## 2. Chaîne d'alimentation / uplink connue

- `core-us-12` port 8 (« Switch Flex Mini », PoE auto) → alimente **core-usw-13**.
  Les deux sont DOWN ensemble : si us-12 tombe, usw-13 tombe avec.
- `core-agg-91` port 7 (SFP+ 10G) → « USW-21 » → core-usw-21 → core-usw-22 / 23.
- `core-agg-91` port 8 → `SFP_trunk` → Synology 10G.
- `core-usw-92` port 15 est son uplink (profil `Uplink`).

**Anomalie relevée avant la panne** : `core-usw-13` avait réélu son uplink sur le
**port 5** (Sonos Meuble Salon) au lieu du port 1 nommé « Uplink ». Un Flex Mini
qui bascule son uplink sur un port client est un signal de boucle — c'est la
piste n°1 pour cette panne.

## 3. Profils de port (après suppression du profil Sonos)

| Nom | `_id` | forward | VLAN natif |
|---|---|---|---|
| Uplink | `5ada4e6ce4b00b58a9265962` | all | LAN Maison |
| SFP_trunk | `5e875a5cd2371200704cdbf3` | customize | — |
| IOT Port Profile | `69d12f3eeecf3cd004864935` | native | IOT (VLAN 101) |
| Disabled Port Profile | `69d13114eecf3cd004864ee2` | disabled | — |
| Maison Port Profile | `69d413aceecf3cd00493ef57` | native | LAN Maison |
| UPS Port Profile | `6a920b618f2542c2c1660ad8` | all | LAN Maison, PoE off |

`Sonos Port Profile` (`6a8c9ce21bb64618e8ebd39f`, natif VLAN 102) **a été supprimé**
pendant le rollback. Tout port qui le référençait encore retombe sur le profil par
défaut (All / natif LAN Maison).

## 4. Ports par switch (dernier relevé avant panne)

Ports sans `portconf_id` = profil par défaut (All, natif LAN Maison).

### core-usw-13 (USMINI) — DOWN
| Port | Nom | Profil | État |
|---|---|---|---|
| 1 | Uplink | défaut | up 1000, **plus marqué uplink** |
| 2 | Sonos Port | défaut | up 100 |
| 3 | Sonos Beam | défaut | up 100 |
| 4 | Sonos Sub Mini | défaut | up 100 |
| 5 | Sonos Meuble | défaut | up 100, **is_uplink: true** ← anormal |

### core-usw-22 (USWED35)
| Port | Nom | Profil | État |
|---|---|---|---|
| 1 | Port 1 | Maison | up 2500 |
| 2 | Port 2 | Maison | up 100 |
| 3 | Port 3 | défaut | **down** (ex-Valentin) |
| 4 | Port 4 | Disabled | down |
| 5 | Port 5 | défaut | up 2500, uplink |

### core-usw-21 (USWED37)
| Port | Nom | Profil | État |
|---|---|---|---|
| 1 | Port 1 | défaut, PoE off | down |
| 2 | Sonos Bureau | défaut, PoE off | down |
| 3 | Port 3 | Maison | up 100 |
| 4-6 | Port 4/5/6 | défaut | 4 down, 5 et 6 up 100 PoE |
| 7 | Port 7 | défaut, 2500 forcé | up 2500 |
| 8 | Port 8 | Uplink | up 2500 |
| 9 | Port 9 (10GE) | défaut | down |
| 10 | Port 10 (SFP+) | défaut | up 10000, uplink |

### core-usw-23 (USWED35)
Ports 1 et 3 en IOT (up 100 / 1000), port 2 Disabled, port 4 défaut down,
port 5 uplink up 100.

### core-usw-93 (USMINI)
Port 1 Uplink, ports 2/3/5 en IOT (up 100), port 4 Disabled.

### core-us-94 (US8)
Port 1 Uplink (uplink, 1000), port 2 Maison (1000), ports 3/5/6 IOT,
ports 4 et 8 Disabled, port 7 défaut (1000).

### core-us-11 (US8) — DOWN
Port 1 Uplink (uplink), port 2 défaut (1000), ports 3/4 Disabled,
ports 5/6 IOT (100), ports 7/8 Uplink (1000, port 8 en PoE passthrough).

### core-us-12 (US8P60) — DOWN
| Port | Nom | Profil |
|---|---|---|
| 1 | Uplink | Uplink (uplink) |
| 2 | Apple TV | IOT, PoE off |
| 3 | Port 3 | Maison (down) |
| 4 | Nintendo Switch | Maison |
| 5 | Port 5 | Maison (down) |
| 6 | PS4 | Maison |
| 7 | Samsung TV | IOT (down) |
| 8 | Switch Flex Mini | défaut, PoE auto → **alimente core-usw-13** |

### core-usw-92 (USL16LP) — state 9
Ports 2/3/4 IOT, 5/8/15/16 Uplink (15 = uplink), 10/11/12 Disabled,
1/6/7/9/13/14 défaut. Ports 7 et 14 nommés « Duncan en5 » / « Duncan en6s0f0 ».

### core-agg-91 (USL8A)
SFP+ 3 et 4 en Uplink, port 8 SFP_trunk (Synology 10G), ports 1/2/5/6/7 défaut.
Port 2 = uplink 10G, port 6 « Duncan 10G », port 7 « USW-21 ».

### core-ups-91 (USWDA24)
Aucun override, un seul port FE up.

## 5. Réseaux / VLAN

| Réseau | network_id | VLAN | Subnet | Domaine |
|---|---|---|---|---|
| LAN Maison | `5aca6e2ee4b0d30c2f4be305` | natif | 192.168.2.0/24 | cparla.fr |
| IOT | `5ada4ec1e4b00b58a9265964` | 101 | 192.168.110.0/24 | iot |
| Sonos | `5e077d48d2371200706e3a03` | 102 | 192.168.120.0/27 | sonos.cparla.fr |
| Vacation | `69f394f7cfee2033dc2f2f30` | 20 | 192.168.20.0/26 | — |
| Hosting | `677a608a149c5d490fc50969` | 999 | 192.168.5.0/29 | hosted |
| WanLTE | `68276eba8e07d3243ca31403` | 990 | 192.168.90.0/29 | — |
| Guest | `66c3aa7b05babe231d32af60` | 99 | 192.168.4.0/28 | désactivé |

Pool DHCP LAN Maison : `.20` → `.100`. Blocs occupés hors pool : ePaper `.140-150`,
switchs `.171-181`, Sonos `.210-220`.

Zone firewall `Internal` (`69b52d8913cfd792b51a03ac`) : LAN Maison, IOT, Sonos,
Vacation. Politique par défaut Internal→Internal = **Allow All Traffic**.
Seul `Isolated Networks` bloque, et uniquement `192.168.110.0/24` (IOT).

## 6. Réservations Sonos — état final validé

Toutes sur LAN Maison, `use_fixedip: true`, DNS actif, résolution vérifiée au `dig`
via AdGuard et via l'UDM (réponses identiques).

| Enceinte | MAC | IP | DNS |
|---|---|---|---|
| Beam | `34:7e:5c:90:79:c2` | 192.168.2.210 | beam.cparla.fr |
| Roam | `38:42:0b:33:1b:a4` | 192.168.2.211 | roam.cparla.fr |
| Cuisine | `48:a6:b8:1b:bd:6e` | 192.168.2.212 | cuisine.cparla.fr |
| ChambreG | `34:7e:5c:44:7c:36` | 192.168.2.213 | chambreg.cparla.fr |
| Port | `48:a6:b8:20:16:b4` | 192.168.2.214 | port.cparla.fr |
| Sub Mini | `f0:f6:c1:04:a1:6e` | 192.168.2.215 | submini.cparla.fr |
| Bureau | `78:28:ca:b8:33:22` | 192.168.2.216 | bureau.cparla.fr |
| Meuble Salon | `78:28:ca:b8:32:e2` | 192.168.2.217 | meuble-salon.cparla.fr |
| Chambre D | `78:28:ca:9e:f2:3c` | 192.168.2.218 | chambred.cparla.fr |
| Valentin | `34:7e:5c:f2:04:fc` | 192.168.2.219 | valentin.cparla.fr |
| Salle de bain | `34:7e:5c:30:88:1a` | 192.168.2.220 | salle-de-bain.cparla.fr |

Avant la panne : 7 des 11 répondaient au ping. Bureau tenait encore un bail
dynamique `192.168.2.77`. ChambreG et Valentin étaient connectées sans IP.
Chambre D était hors ligne depuis ~2 h.

## 7. WiFi

SSID `Sonos` (`5e078496d2371200706e4350`) : **rattaché à LAN Maison** depuis le
rollback, `enabled: true`, 2,4 GHz seul, passphrase inchangée, groupe AP
`5fdbe278d2371200703e698b`.
SSID `Apple Home SweetHome` (`63b168056273d308bc7e0f0e`) : LAN Maison,
`mcastenhance_enabled` passé à **false** pendant le diagnostic mDNS.
SSID `Sonos-Test` (`6a8ca0c71bb64618e8ebece0`) : désactivé, pointe encore VLAN 102.

## 8. DNS

AdGuard `192.168.2.2`. Upstreams : `[/cparla.fr/]192.168.2.1`, puis 9.9.9.9,
1.1.1.1, 8.8.8.8. **La zone `cparla.fr` est déléguée à l'UDM** — AdGuard ne
stocke aucun enregistrement local, il route. Un **wildcard `*.cparla.fr` →
192.168.2.100** (duncan@enp5s0) capte tout nom sans enregistrement explicite :
un nom manquant ne renvoie pas NXDOMAIN, il pointe silencieusement sur Duncan.

Le VLAN Sonos avait été oublié dans l'allowlist AdGuard (`Disallowed: yes` pour
tout `192.168.120.0/27`), corrigé depuis. Sans objet après le retour en `.2.x`.

## 9. Pistes de diagnostic

1. **Boucle réseau sur core-usw-13.** Un Flex Mini qui réélit son uplink sur un
   port client (port 5, Sonos Meuble Salon) est le symptôme classique. usw-13 et
   son alimentation us-12 sont tombés ensemble.
2. **core-usw-92 en state 9**, 329 Mo émis / 10 Mo reçus : à corréler avec la
   même boucle.
3. La branche agg-91 → usw-21/22/23 n'a jamais bronché (52 000 s d'uptime) :
   le problème est en aval de us-12 / usw-92, pas au cœur.
4. `core-usw-22` port 3 est down alors que Valentin s'y trouvait ; elle se
   déclare maintenant derrière `core-usw-21`. Câblage à vérifier.
5. Anomalie préexistante sans lien : réservation « Nuc Intel »
   (`54:b2:03:0b:86:fe`) porte `fixed_ip 192.168.110.75` sur le réseau LAN Maison.
