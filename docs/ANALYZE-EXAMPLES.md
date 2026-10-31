# Gamevoorbeelden: kopiëren en uitvoeren

Paden gecontroleerd op deze Mac op 31 oktober 2026. Games worden niet gestart.
Resultaten komen in `~/rea-notes/`. Begin met één voorbeeld.

## 1. CoD1: snel kijken wat erin zit

Metadata en strings, zonder uitgebreide Ghidra-analyse.

```sh
rea-suite analyze ~/Dev/Games/cod1/game/mp/CoDMP.exe --project ~/rea-notes/cod1 --preset triage
```

## 2. CoD1: beginnen bij de serverlijst

Zoek letterlijk `getservers` en volg verwijzingen naar code. Een startpunt voor een eigen browser.

```sh
rea-suite analyze ~/Dev/Games/cod1/game/mp/CoDMP.exe --project ~/rea-notes/cod1 --query getservers
```

## 3. CoD1: opgeslagen resultaten doorzoeken

Na voorbeeld 2. Start geen decompiler en werkt zonder AI.

```sh
rea-suite analyze --project ~/rea-notes/cod1 --search getservers
```

## 4. CoD1: de UI-module bekijken

Voeg de echte UI-DLL toe aan hetzelfde project. Exporteert maximaal 50 functies per run.

```sh
rea-suite analyze ~/Dev/Games/cod1/game/mp/Main/ui_mp_x86.dll --project ~/rea-notes/cod1 --preset decompile --max-functions 50
```

## 5. Rainbow Six Black Ops: eerst het plan

Controleer de game en DirectDraw-wrapper samen. Voert nog geen analysetool uit.

```sh
rea-suite analyze ~/Dev/Games/r6bo/game/R6BO.exe ~/Dev/Games/r6bo/game/ddraw.dll --project ~/rea-notes/r6bo --plan
```

## 6. Rainbow Six Black Ops: klein beginnen met decompileren

Exporteert maximaal 20 functies. Open daarna `~/rea-notes/r6bo/REPORT.md` in je IDE.

```sh
rea-suite analyze ~/Dev/Games/r6bo/game/R6BO.exe --project ~/rea-notes/r6bo --preset decompile --max-functions 20
```

## 7. Rainbow Six Black Ops: audiobestanden toevoegen

Meerdere bestanden, hetzelfde bestaande project. Eerst alleen snelle inspectie.

```sh
rea-suite analyze ~/Dev/Games/r6bo/game/dsound.dll ~/Dev/Games/r6bo/game/eax.dll --project ~/rea-notes/r6bo --preset triage
```

## 8. ETLegacy: de dedicated server inspecteren

De macOS-binary heeft geen `.exe`-extensie; herkenning gaat via de inhoud.

```sh
rea-suite analyze ~/Games/ETLegacy/app/etlded --project ~/rea-notes/etlegacy --preset triage
```

## 9. ETLegacy: alleen de renderer onderzoeken

Een apart onderdeel onderzoeken, met een kleine pseudocode-export.

```sh
rea-suite analyze ~/Games/ETLegacy/app/librenderer_opengl1_mac --project ~/rea-notes/etlegacy-renderer --preset decompile --max-functions 10
```

## Onthouden

- **Verdergaan:** herhaal hetzelfde commando; de export gaat verder waar mogelijk.
- **Een functie uitdiepen:** gebruik `--function` met de exacte naam of het adres uit jouw resultaat.
- **Geen treffer:** probeer een andere string; zoekwoorden zijn startpunten, geen bewezen gedrag.
- **Een patch bouwen:** doe dat in je eigen code. Controleer assembly, aanroepconventie en runtimegedrag.
- **CoD3:** de aanwezige `.xex`-bestanden vallen buiten de automatische formaten van deze eerste versie.

Meer opties: `rea-suite analyze --help`. Achtergrond en bronnen: [README](../README.md#offline-analysis-projects).
