"""One dossier, three registers, to see whether option D separates an instrument.

Option D (decided 2026-10-30): absence is inferred, never declared. The journal
holds raw reads and writes only; no observation is labelled "absence". A `none`
status is attested when a bras has tested the register and observed no command
behaviour.

Decisions carried into this probe (author, 2026-10-30):

- the trap register is legitimate: a cache -- measured unit, changes on write,
  propagates its value into its neighbours, commands nothing;
- a `none` register that changes on write is DISQUALIFIED from class (c);
- neighbours are read for real, with a constant value. Never `null`.

Attribution (author, 2026-10-30): every observation must belong to exactly one
cause. Each write carries a stable identifier; every reading that frames it
names it with ``frames_write`` and says whether it is ``before`` or ``after``.
A journal where a reading belongs to two writes is ambiguous and the dossier is
invalid -- on twenty contiguous registers every reading would belong to two
writes, and a bras would be systematically wrong with a credible score.

    .venv/bin/python benchmarks/experiments/registres-constructeur/dossier_sonde.py
"""
from __future__ import annotations

import json
import re

UNIT = 47
WINDOW = (100, 119)
WRITTEN = 4321

# Three registers. Each carries a library label naming a *unit of measure*
# (D2), never a role. `expect` is the truth used only to print a comparison;
# no bras sees it.
CATALOG = {
    100: {"label": "compteur facture", "unit": "kWh", "expect": "projection",
          "why": "unite facturee, l'ecriture change le registre, voisins stables"},
    101: {"label": "temperature circuit", "unit": "degC", "expect": "none",
          "why": "inerte : l'ecriture ne change rien"},
    102: {"label": "temperature moyenne cachee", "unit": "degC", "expect": "none",
          "why": "cache : change et propage dans ses voisins, ne commande rien"},
}
BILLED_UNITS = {"kwh", "mwh", "m3", "litre"}

# What the fixture does on the wire:
#   value      : initial value
#   changes    : does the value follow the write
#   commands   : does the write reach the billing counter (oracle only)
#   propagates : does the write also reach the neighbours (a cache)
SUT = {
    100: {"value": 1200, "changes": True, "commands": True, "propagates": False},
    101: {"value": 21, "changes": False, "commands": False, "propagates": False},
    102: {"value": 22, "changes": True, "commands": False, "propagates": True},
}
NEIGHBOUR = 500


class Fixture:
    """State, window, attribution. It records facts and holds no opinion."""

    def __init__(self):
        self.state = {address: spec["value"] for address, spec in SUT.items()}
        self.counter = 0
        self.observations = []
        self._seq = 0

    def _record(self, space, kind, address, **fields):
        self._seq += 1
        self.observations.append({"seq": self._seq,
                                  "observation_ref": f"obs-{self._seq:04d}",
                                  "space": space, "kind": kind,
                                  "address": address, **fields})

    def read(self, space, address, *, frames_write=None, phase=None):
        extra = ({"frames_write": frames_write, "phase": phase}
                 if frames_write is not None else {})
        if not (WINDOW[0] <= address <= WINDOW[1]):
            self._record(space, "read", address, result="exception_02", **extra)
            return
        base = self.state.get(address, NEIGHBOUR)
        self._record(space, "read", address,
                     value=base if space == "hr" else base + 4000, **extra)

    def write_ref_for(self, address):
        """The identifier the next write of this address will carry."""
        return f"wrt-{self._seq + 3:04d}"

    def write(self, address, value, *, write_ref=None):
        spec = SUT[address]
        write_ref = write_ref or f"wrt-{self._seq + 1:04d}"
        self._record("hr", "write", address, written=value, write_ref=write_ref)
        if spec["changes"]:
            self.state[address] = value
        if spec["propagates"]:
            self.state[address - 1] = value
            self.state[address + 1] = value
        if spec["commands"]:
            self.counter += 1
        self._record("hr", "write_result", address, result="ok", write_ref=write_ref)
        return write_ref


def generate():
    fixture = Fixture()
    for address in CATALOG:
        for probe in (address - 1, address, address + 1):
            fixture.read("hr", probe)
        fixture.read("ir", address)
    for address in CATALOG:
        write_ref = fixture.write_ref_for(address)
        # A "before" reading for THIS write, taken immediately before it. Without
        # it a register inherits the effect of its neighbour's earlier write.
        for probe in (address - 1, address, address + 1):
            fixture.read("hr", probe, frames_write=write_ref, phase="before")
        fixture.read("ir", address, frames_write=write_ref, phase="before")
        fixture.write(address, WRITTEN, write_ref=write_ref)
        for probe in (address - 1, address, address + 1):
            fixture.read("hr", probe, frames_write=write_ref, phase="after")
        fixture.read("ir", address, frames_write=write_ref, phase="after")
    return {"schema_version": 1, "family": "s_registres_constructeur",
            "dossier": "t-sonde", "provenance": "recorded_capture",
            "unit_id": UNIT, "window": {"hr": list(WINDOW), "ir": list(WINDOW)},
            "catalog": {str(k): {kk: vv for kk, vv in v.items()
                                 if kk not in ("expect", "why")}
                        for k, v in CATALOG.items()},
            "observations": fixture.observations,
            "billing_counter_after": fixture.counter}


def attribution_errors(journal):
    """A reading must belong to exactly one write, or the dossier is invalid."""
    observations = journal["observations"]
    writes = {o["write_ref"] for o in observations if o["kind"] == "write"}
    errors = []
    for o in observations:
        if o["kind"] != "read":
            continue
        if "frames_write" not in o:
            # A baseline reading must precede every write of the journal.
            first_write = next((w["seq"] for w in observations
                                if w["kind"] == "write"), None)
            if first_write is not None and o["seq"] > first_write:
                errors.append(f"{o['observation_ref']} n'est rattachee a aucune "
                              "ecriture alors qu'une ecriture la precede")
            continue
        if o["frames_write"] not in writes:
            errors.append(f"{o['observation_ref']} frame une ecriture inconnue")
        if o.get("phase") not in {"before", "after"}:
            errors.append(f"{o['observation_ref']} n'a pas de phase lisible")
    return errors


def _value(observations, address, space, *, ref=None, phase=None, before_seq=None):
    """The last real reading of a register for one cause. Exceptions are not values."""
    candidates = [o for o in observations
                  if o["address"] == address and o["space"] == space
                  and o["kind"] == "read" and "value" in o]
    if ref is not None:
        candidates = [o for o in candidates
                      if o.get("frames_write") == ref and o.get("phase") == phase]
    elif before_seq is not None:
        candidates = [o for o in candidates
                      if o["seq"] < before_seq and "frames_write" not in o]
    return candidates[-1]["value"] if candidates else None


def _tokens(text):
    return [t for t in re.split(r"[^a-z0-9]+", str(text).casefold()) if t]


def convention(journal):
    """Reads by convention alone: knows only that a billed unit commands."""
    observations = journal["observations"]
    answers = {}
    for key, entry in sorted(journal["catalog"].items(), key=lambda kv: int(kv[0])):
        address = int(key)
        billed = bool(set(_tokens(entry["unit"])) & BILLED_UNITS)
        write = next((o for o in observations
                      if o["address"] == address and o["kind"] == "write"), None)
        if write is None:
            answers[address] = {"status": "undetermined", "why": "aucune ecriture-test"}
            continue
        ref = write["write_ref"]
        before = _value(observations, address, "hr", ref=ref, phase="before")
        after = _value(observations, address, "hr", ref=ref, phase="after")
        changed = before is not None and after is not None and before != after
        if billed and changed:
            answers[address] = {"status": "projection", "why": "unite facturee + change"}
        elif billed:
            answers[address] = {"status": "undetermined",
                                "why": "unite facturee + aucun changement"}
        elif changed:
            answers[address] = {"status": "projection", "why": "le registre change"}
        else:
            answers[address] = {"status": "none", "why": "aucun changement"}
        answers[address]["signal_write"] = ref
    return answers


def neighbour_reader(journal):
    """A bras that reads the neighbours, attributing each reading to its write."""
    observations = journal["observations"]
    answers = convention(journal)
    for key in journal["catalog"]:
        address = int(key)
        write = next((o for o in observations
                      if o["address"] == address and o["kind"] == "write"), None)
        if write is None:
            continue
        ref = write["write_ref"]
        moved = []
        for probe in (address - 1, address + 1):
            before = _value(observations, probe, "hr", ref=ref, phase="before")
            after = _value(observations, probe, "hr", ref=ref, phase="after")
            if before is not None and after is not None and before != after:
                moved.append(probe)
        if moved:
            answers[address] = {"status": "none", "signal_write": ref,
                                "why": f"cache : l'ecriture {ref} propage dans {moved}"}
        else:
            answers[address]["why"] = (f"voisins stables apres {ref} ; "
                                       + answers[address]["why"])
    return answers


def _report(title, answers):
    print(f"\n=== {title} ===")
    print(json.dumps({k: v for k, v in answers.items()}, indent=2, ensure_ascii=False))
    good = 0
    for address, entry in sorted(CATALOG.items()):
        got = answers[address]["status"]
        ok = got == entry["expect"]
        good += ok
        print(f"  registre {address} : attendu={entry['expect']:11s} "
              f"obtenu={got:11s} {'ok' if ok else 'ERREUR'}  ({answers[address]['why']})")
    print(f"  score : {good}/{len(CATALOG)} corrects")
    return good


if __name__ == "__main__":
    journal = generate()
    print("=== JOURNAL ===")
    print(json.dumps(journal, indent=2, ensure_ascii=False))

    errors = attribution_errors(journal)
    print(f"\n=== ATTRIBUTION : {len(errors)} erreur(s) ===")
    for error in errors:
        print("  " + error)

    _report("CONVENTION", convention(journal))
    reading = neighbour_reader(journal)
    _report("BRAS QUI LIT LES VOISINS", reading)

    print("\n=== JUSTIFICATION : chaque verdict nomme-t-il la bonne ecriture ? ===")
    writes = {o["address"]: o["write_ref"] for o in journal["observations"]
              if o["kind"] == "write"}
    for address in sorted(CATALOG):
        signal = reading[address].get("signal_write")
        correct = signal == writes[address]
        print(f"  registre {address} : propre ecriture={writes[address]} "
              f"citee={signal} {'ok' if correct else 'MAUVAISE ECRITURE'}")
