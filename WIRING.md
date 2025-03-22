# Wiring

## SB9600
TBD - Axel write some stuff here

## XCMP
### MotoTrbo
TBD. Done in an old revision using rear accessory USB and audio.
### Astro25, APX
Radios tested: XTL5000 High Power via J600
#### Via J2 (rear accessory)
Connection via J2 is required when J600 (front DB25) is not present (e.g. on a dashmount radio, or an APX8500) or unusable (e.g. an accessory is already installed).

TBD. Should be possible but untested.
#### Via J600 (DB25)
Connection via J600 is required when J2 (rear accessory connector) is not present (e.g. on an XTL high power) or unusable (e.g. an accessory is already installed).

J600 does not support USB. Connection is possible via serial only, at RS-232 levels. A level shifter is required to bring the voltage to logic level if interfacing directly with GPIO pins; or a USB-DE9 serial adapter can be used instead. The cable used in testing is as follows:

```
DB25    Signal      RJ45
2       RX          3 (grn/wht)
3       TX          6 (grn)
10      GND         4,5 (blu,blu/wht)

DB25    Signal      Audio Out 3.5mm
6       RX_Audio    Tip
11      GND         Sleeve

DB25    Signal      Audio In 3.5mm
8       Aux_TX      Tip
11      GND         Sleeve
```

RJ45 is not required, a DE-9F could easily take its place; however this was used during testing for ease of use with existing hardware.

* TBD -- verify audio works *