"""Probe: can a script without a model decide the revocation verdict?

A gateway queues a command for a sleeping device; the sender's permissions are
withdrawn before delivery; the command is delivered anyway. Whether that is a
flaw depends on the product's documentation:

- behaviour 1: withdrawing permissions discards undelivered commands -> flaw;
- behaviour 2: permissions are checked at submission only -> expected;
- behaviour 3: undelivered commands are discarded after a period -> flaw only
  if the command waited longer than that period.

Every documentation is read against the same journal. The answer key
(``corrige.json``) is read only to score; no script receives it.

    .venv/bin/python benchmarks/experiments/revocation_commandes_attente/sonde.py
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
DOCS_DIR = HERE / "documentations"
ANSWER_KEY = HERE / "corrige.json"
# "connu": the nine documentations the strongest script was written against.
# "inedit": documentations written after that script was frozen.
# "v3": documentations whose rule follows from several facts, written after the
# mechanism script was frozen.
LOTS = {
    "connu": (DOCS_DIR, ANSWER_KEY),
    "inedit": (HERE / "documentations-inedites", HERE / "corrige-inedites.json"),
    "v3": (HERE / "documentations-v3", HERE / "corrige-v3.json"),
}

# One journal for every documentation: nothing in it reveals the product.
JOURNAL = (
    "16:39:12  mqtt     publisher=operator_17  topic=site/x/device/y/request  result=accepted",
    "16:39:13  gateway  operation=queued        destination=device_y",
    "16:42:00  iam      principal=operator_17   status=revoked",
    "16:44:51  gateway  operation=dispatched    transport_identity=gateway_service",
)


def _journal(wait_s: int) -> tuple[str, ...]:
    """The same four events, dated, with the dispatch ``wait_s`` after queueing."""
    queued = datetime(2026, 3, 2, 16, 39, 13, tzinfo=timezone.utc)

    def stamp(moment: datetime) -> str:
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

    return (
        f"{stamp(queued - timedelta(seconds=1))}  mqtt     publisher=operator_17  topic=site/x/device/y/request  result=accepted",
        f"{stamp(queued)}  gateway  operation=queued        destination=device_y",
        f"{stamp(queued + timedelta(seconds=167))}  iam      principal=operator_17   status=revoked",
        f"{stamp(queued + timedelta(seconds=wait_s))}  gateway  operation=dispatched    transport_identity=gateway_service",
    )


# Version 2: four journals that differ only by how long the command waited, so a
# documented expiry period can fall on either side of the wait.
JOURNALS = {
    "attente-5min": _journal(338),
    "attente-10h": _journal(10 * 3600),
    "attente-60h": _journal(60 * 3600),
    "attente-4j": _journal(4 * 86400),
}


def _seconds(clock: str) -> int:
    if "T" in clock:
        return int(datetime.fromisoformat(clock.replace("Z", "+00:00")).timestamp())
    hours, minutes, seconds = (int(part) for part in clock.split(":"))
    return hours * 3600 + minutes * 60 + seconds


def journal_facts(journal) -> dict:
    """Technical facts every approach extracts the same way."""
    times = {}
    for line in journal:
        clock = line.split()[0]
        for event in ("queued", "revoked", "dispatched"):
            if event in line:
                times[event] = _seconds(clock)
    return {
        "dispatched_after_revocation": times["dispatched"] > times["revoked"],
        "waited_s": times["dispatched"] - times["queued"],
    }


def expected_verdict(behaviour: int, period_s: int | None, facts: dict) -> str:
    """Verdict implied by the answer key; used for scoring only."""
    if not facts["dispatched_after_revocation"]:
        return "expected"
    if behaviour == 1:
        return "flaw"
    if behaviour == 2:
        return "expected"
    return "flaw" if facts["waited_s"] > period_s else "expected"


# --------------------------------------------------------------------------
# Adversarial scripts. Each receives the documentation text and the journal
# only, and returns "flaw" or "expected". They are written to win.
# --------------------------------------------------------------------------

UNITS = {"s": 1, "sec": 1, "second": 1, "min": 60, "minute": 60,
         "h": 3600, "hr": 3600, "hour": 3600, "d": 86400, "day": 86400}
DURATION = re.compile(r"(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|hours?|hrs?|h|days?|d)\b",
                      re.IGNORECASE)
QUEUE = r"(queue|queued|pending|undelivered|outstanding|stored|buffer|backlog|waiting|not yet delivered|held)"
DISCARD = r"(discard|drop|purg|cancel|delet|remov|flush|invalidat|void|clear|expire|evict|reject)"
PERMISSION = r"(permission|privilege|right|role|access|credential|authori[sz]|revok|withdr[ae]w|deactivat|disabl|suspend)"
SUBMISSION = r"(at (?:the time of )?submission|when (?:a |the )?command is (?:submitted|sent|accepted|received)|upon (?:submission|acceptance|receipt)|on submission|at (?:enqueue|acceptance))"
ALWAYS = r"(regardless|irrespective|even if|even when|still (?:be )?deliver|guarantee|no matter|remain(?:s)? valid)"
EXPIRY = r"(expire|expiry|expiration|retention|retain|time-to-live|ttl|older than|longer than|discard|purg|drop)"
NEGATION = re.compile(r"\b(not|never|no longer|n't|without|nor)\b", re.IGNORECASE)


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text) if part.strip()]


def _has(pattern: str, sentence: str) -> bool:
    return re.search(pattern, sentence, re.IGNORECASE) is not None


def _negated_discard(sentence: str) -> bool:
    match = re.search(DISCARD, sentence, re.IGNORECASE)
    if match is None:
        return False
    window = sentence[max(0, match.start() - 40):match.start()]
    return NEGATION.search(window) is not None


def _durations(sentence: str) -> list[int]:
    found = []
    for value, unit in DURATION.findall(sentence):
        key = unit.lower().rstrip("s") or "s"
        key = {"sec": "s", "min": "min", "hr": "h"}.get(key, key)
        found.append(int(float(value) * UNITS.get(key, 1)))
    return found


def script_default(documentation: str, journal) -> str:
    """Delivered after revocation is always a flaw."""
    return "flaw" if journal_facts(journal)["dispatched_after_revocation"] else "expected"


def script_duration(documentation: str, journal) -> str:
    """Find an expiry period near queue words and compare it with the wait."""
    facts = journal_facts(journal)
    for sentence in _sentences(documentation):
        if _has(QUEUE, sentence) and _has(EXPIRY, sentence):
            durations = _durations(sentence)
            if durations:
                return "flaw" if facts["waited_s"] > durations[0] else "expected"
    return script_default(documentation, journal)


def script_keywords(documentation: str, journal) -> str:
    """Score behaviours sentence by sentence, with negation, then decide."""
    facts = journal_facts(journal)
    if not facts["dispatched_after_revocation"]:
        return "expected"
    scores = {1: 0, 2: 0, 3: 0}
    period = None
    for sentence in _sentences(documentation):
        queue, permission = _has(QUEUE, sentence), _has(PERMISSION, sentence)
        discard = _has(DISCARD, sentence) and not _negated_discard(sentence)
        durations = _durations(sentence)
        if queue and _has(EXPIRY, sentence) and durations:
            scores[3] += 2
            period = durations[0] if period is None else period
        if queue and permission and discard and not durations:
            scores[1] += 2
        if permission and _has(SUBMISSION, sentence):
            scores[2] += 2
        if (queue or permission) and _has(ALWAYS, sentence):
            scores[2] += 1
        if queue and permission and _negated_discard(sentence):
            scores[2] += 1
    behaviour = max(scores, key=lambda key: (scores[key], key == 1))
    if scores[behaviour] == 0:
        return "flaw"
    if behaviour == 3 and period is not None:
        return "flaw" if facts["waited_s"] > period else "expected"
    return "flaw" if behaviour == 1 else "expected"


# --------------------------------------------------------------------------
# Version 2: the strongest script, written after reading the nine known
# documentations and frozen before any unseen documentation exists. It stays
# general: no product name, no exact sentence, only patterns of meaning.
# --------------------------------------------------------------------------

# Sentences about sessions, tokens, probes or logs carry durations and verbs
# that say nothing about queued commands.
BEST_NOISE = (r"\b(sessions?|tokens?|credentials?|heartbeats?|poll\w*|probes?|sampl\w*|"
              r"refresh\w*|challenges?|log segment|consoles?|portals?|passwords?|certificates?|"
              r"every \d)\b")
BEST_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
              "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
              "fifteen": 15, "twenty": 20, "thirty": 30, "forty-eight": 48, "seventy-two": 72}
BEST_DURATION = re.compile(
    r"\b(\d+(?:\.\d+)?|" + "|".join(sorted(BEST_WORDS, key=len, reverse=True)) + r")"
    r"[\s-]*(seconds?|secs?|minutes?|mins?|hours?|hrs?|h|days?|d|weeks?)\b", re.IGNORECASE)
BEST_UNITS = {"s": 1, "sec": 1, "second": 1, "min": 60, "minute": 60, "h": 3600, "hr": 3600,
              "hour": 3600, "d": 86400, "day": 86400, "week": 604800}
# A lifetime bound on waiting work.
BEST_LIFETIME = (r"(discard\w*|purg\w*|remov\w*|delet\w*|expir\w*|drop\w*|evict\w*|no more than|"
                 r"maximum|max\.?|age limit|residence|retain\w*|retention|older than|"
                 r"time-to-live|ttl|lifetime|kept for|held for|stored for|up to)")
BEST_WORK = (r"(instructions?|commands?|requests?|operations?|records?|messages?|jobs?|tasks?|"
             r"queue\w*|pending|stor\w*|outstanding|awaiting|undelivered|buffer\w*|staged)")
# A change of the sender's rights.
BEST_CHANGE = (r"(revok\w*|withdr[ae]w\w*|\blos(?:e|es|t|ing)\b|remov\w*|disabl\w*|suspen\w*|"
               r"downgrad\w*|deactivat\w*|chang\w*|modif\w*|delet\w*|account status|"
               r"no longer (?:holds?|has|authori[sz]ed))")
BEST_RIGHTS = (r"(permissions?|privileges?|rights?|roles?|access|accounts?|operators?|"
               r"membership|assignments?|capabilit\w*|authori[sz]ation|group)")
# Work already on the device is not the question.
BEST_DELIVERED = (r"(already (?:transmitted|received|delivered|executed|applied)|"
                  r"received by the device|reached the device|remain in effect)")
# The waiting work survives the change.
BEST_SURVIVE = (r"(remains? (?:eligible|deliverable|valid|queued|scheduled|pending)|"
                r"can still|still (?:be )?(?:deliver|transmit|reach|forward|sent|dispatch|execut)|"
                r"(?:does|do|will) not (?:\w+ )?(?:prevent|invalidate|affect|cancel|stop|block|remove)|"
                r"not invalidated?|independent(?:ly)?|even if|even when|regardless|irrespective|"
                r"unaffected|is honou?red|are honou?red|guarantee\w*)")
# The waiting work is killed by the change.
BEST_KILL = (r"(discard\w*|eras\w*|remov\w*|purg\w*|delet\w*|invalidat\w*|cancel\w*|drop\w*|"
             r"void\w*|flush\w*|evict\w*|abort\w*|withdrawn from the queue|"
             r"(?:no longer|not|never) (?:be )?(?:deliver|transmit|forward|dispatch|execut|sent))")
BEST_CHECK = r"(verif\w*|check\w*|evaluat\w*|validat\w*|authori[sz]\w*|confirm\w*)"
# Rights checked once, when the gateway takes the command in.
BEST_AT_INTAKE = (BEST_CHECK + r".{0,60}\b(at the moment|at the time of|at|when|whenever|before|"
                  r"upon|on|during)\b.{0,40}(accept\w*|submi\w*|enter\w*|receiv\w*|enqueu\w*|"
                  r"admission|ingest\w*|intake)")
# Rights checked again later: at delivery, or when the account changes.
BEST_RECHECK = (BEST_CHECK + r".{0,60}(\bagain\b|re-?(?:evaluat|check|validat)\w*|"
                r"at (?:the time of )?(?:delivery|dispatch|transmission)|"
                r"before (?:each |every )?(?:delivery|dispatch|transmission|forwarding))")


def _best_durations(sentence: str) -> list[int]:
    found = []
    for value, unit in BEST_DURATION.findall(sentence):
        number = BEST_WORDS.get(value.lower()) or float(value)
        key = unit.lower()
        key = {"secs": "s", "sec": "s", "seconds": "second", "mins": "min", "minutes": "minute",
               "hrs": "hr", "hours": "hour", "days": "day", "weeks": "week"}.get(key, key)
        found.append(int(number * BEST_UNITS[key]))
    return found


def _best_period(sentence: str) -> int | None:
    """The expiry period of waiting work stated in this sentence, if any."""
    if not (_has(BEST_LIFETIME, sentence) and _has(BEST_WORK, sentence)):
        return None
    match = re.search(BEST_LIFETIME, sentence, re.IGNORECASE)
    if NEGATION.search(sentence[max(0, match.start() - 20):match.start()]):
        return None
    durations = _best_durations(sentence)
    return durations[0] if durations else None


def script_best(documentation: str, journal) -> str:
    """Decide what the product does with waiting work when the sender's rights go."""
    facts = journal_facts(journal)
    if not facts["dispatched_after_revocation"]:
        return "expected"
    killed = survives = 0
    period = None
    for sentence in _sentences(documentation):
        if _has(BEST_NOISE, sentence) or _has(BEST_DELIVERED, sentence):
            continue
        if period is None:
            period = _best_period(sentence)
        if _has(BEST_AT_INTAKE, sentence):
            survives += 2
        if _has(BEST_RECHECK, sentence):
            killed += 2
        if not (_has(BEST_CHANGE, sentence) and _has(BEST_RIGHTS, sentence)):
            continue
        if _has(BEST_SURVIVE, sentence):
            survives += 2
        elif _has(BEST_KILL, sentence):
            killed += 2
    if killed > survives:
        return "flaw"
    if period is not None:
        return "flaw" if facts["waited_s"] > period else "expected"
    if survives > killed:
        return "expected"
    return "flaw"


# --------------------------------------------------------------------------
# Version 3: the strongest script, written knowing the v3 drafting brief (the
# rule follows from two facts, the script's v2 words are banned) but not the
# documents. It looks for mechanisms: what is checked when work leaves, what
# the gateway signs with, what an account change does to what it owns, and how
# long waiting work lives. Without a clear mechanism it falls back on `best`.
# --------------------------------------------------------------------------

MECH_CHECK = (r"(verif\w*|check\w*|confirm\w*|validat\w*|look\w* up|consult\w*|compar\w*|"
              r"inspect\w*|evaluat\w*|quer(?:y|ies|ied)|match\w*|authenticat\w*|screen\w*)")
MECH_DELIVERY = (r"(deliver\w*|dispatch\w*|transmi\w*|forward\w*|\bsend(?:s|ing)?\b|\bsent\b|releas\w*|"
                 r"hand\w* (?:\w+ )?(?:over|off)|push\w*|wakes?\b|wake-up|reconnect\w*|"
                 r"leaves?|leaving|goes out|radio window|on (?:arrival|receipt)|"
                 r"(?:device|endpoint|sensor|actuator|node|controller)s? (?:\w+ ){0,2}"
                 r"(?:verif|check|validat|confirm|accept|execut|appl|act|refus|reject|ignor))")
MECH_INTAKE = (r"(accept\w*|submi\w*|enqueu\w*|admi(?:t|ssion)\w*|intake|ingest\w*|arriv\w*|"
               r"creat\w*|enter\w* the queue|placed in the queue|is queued|first (?:reach|arriv)\w*)")
MECH_IDENTITY = (r"(accounts?|operators?|users?|submitters?|senders?|originators?|authors?|"
                 r"issuers?|requesters?|owners?|signatures?|signing keys?|keys?|credentials?|"
                 r"tokens?|certificates?|roles?|membership|directory|roster|allow-?list|"
                 r"access list|entitlements?|privileges?|grants?|scopes?)")
MECH_LIVE = (r"(current\w*|\blive\b|still|active|enabled|valid|good standing|at that (?:moment|time|point)|"
             r"latest|up-to-date|fresh|in force|not been (?:disabled|deactivated|suspended|closed))")
MECH_AGAIN_NOT = (r"((?:not|never|no longer|without) (?:\w+ ){0,3}(?:again|re-?\w*(?:check|evaluat|"
                  r"validat|examin|consider|visit)\w*|consult\w*|look\w* at|query\w*|"
                  r"verif\w*|check\w*)|only once|once only|single (?:check|decision|evaluation)|"
                  r"not repeated|final once|is final|immutable|irrevocabl\w*)")
MECH_CONTRAST = (r"(rather than|instead of|not (?:\w+ ){0,2}(?:at|during|on|before|upon)|"
                 r"never (?:at|during|on|before|upon)).{0,40}" + MECH_DELIVERY)
MECH_GATEWAY_IDENTITY = (r"(gateway'?s? own|its own (?:key|credential|certificate|identity)|"
                         r"(?:gateway|platform|system)'?s? (?:own )?(?:service )?(?:identity|account|key|credential|certificate)|"
                         r"service identity|"
                         r"(?:re-?)?sign\w* (?:\w+ ){0,4}with (?:the |its )?(?:gateway|service|platform)|"
                         r"on behalf of the (?:gateway|platform|system))")
MECH_SNAPSHOT = (r"(snapshot|copy of|captur\w*|record\w*|stamp\w*|embed\w*|frozen|freez\w*|"
                 r"bak\w* into|attach\w*|carr(?:y|ies))")
MECH_ENTITLEMENT = (r"(roles?|grants?|entitlements?|privileges?|scopes?|access level|clearance|"
                    r"capabilit\w*|approval|decision)")
MECH_ONLY_FUTURE = (r"(only|solely|just) (?:\w+ ){0,2}(?:affects?|applies?|prevents?|blocks?|stops?|"
                    r"ends?|concerns?) (?:\w+ ){0,2}(?:new|future|further|subsequent|later|"
                    r"sign-?ins?|log-?ins?|sessions?)")
MECH_ACCOUNT_CHANGE = (r"(disabl\w*|deactivat\w*|suspend\w*|clos(?:e|ed|es|ing)\b|retir\w*|"
                       r"offboard\w*|de-?provision\w*|lock\w*|terminat\w*|expel\w*|"
                       r"leaves? the (?:organi[sz]ation|team|tenant))")
MECH_CASCADE = (r"(everything|all (?:\w+ )?(?:items?|objects?|records?|resources?|entries|requests?|"
                r"jobs?|tasks?|messages?|commands?|work)|every (?:\w+ )?(?:item|object|record|"
                r"resource|entry|request|job|task|message|command)|anything|"
                r"(?:owned|created|issued|submitted|signed|authored) by|associated|linked|tied|"
                r"bound|attached|belong\w*)")
MECH_EFFECT = (r"(cancel\w*|void\w*|clear\w*|expung\w*|invalidat\w*|clos(?:e|ed|es)\b|retir\w*|"
               r"archiv\w*|revert\w*|rolled back|stop\w*|halt\w*|freez\w*|frozen|null\w*|"
               r"inert|unusable|invalid|ceas\w*|terminat\w*|abandon\w*|end(?:s|ed)?\b|lapse\w*|"
               r"no longer (?:usable|valid|trusted|accepted|honou?red|recogni[sz]ed))")
MECH_REJECT = (r"(reject\w*|refus\w*|ignor\w*|declin\w*|skip\w*|set aside|quarantin\w*|"
               r"not (?:be )?(?:execut|appl|act|accept|honou?r|forward|deliver|transmi)\w*)")
MECH_BAD = (r"(invalid|expired|unknown|inactive|disabled|deactivated|suspended|closed|untrusted|"
            r"not (?:active|valid|enabled|trusted|recogni[sz]ed)|no longer (?:active|valid|enabled))")
MECH_NOISE = (r"\b(sessions?|log-?ins?|sign-?ins?|heartbeats?|poll\w*|probes?|sampl\w*|"
              r"refresh\w*|passwords?|certificates?|tokens?|backups?|logs?|reports?|firmware|"
              r"batter\w*|telemetry|metrics|dashboards?|lockouts?|idle|inactivity|every \d)\b")
MECH_WORK = (r"(instructions?|commands?|requests?|operations?|records?|messages?|jobs?|tasks?|"
             r"items?|entr(?:y|ies)|queue\w*|pending|waiting|held|parked|staged|buffer\w*|"
             r"backlog|deferred|stor\w*)")
MECH_LIFETIME = (r"(expir\w*|valid for|validity|kept for|held for|stored for|parked for|"
                 r"stays?|remain\w*|for up to|up to|no (?:more|longer) than|at most|maximum|"
                 r"lifespan|life ?time|shelf life|time-to-live|\bttl\b|older than|stale|"
                 r"gives? up|stops? (?:trying|retrying|attempting)|abandon\w*|retir\w*|"
                 r"archiv\w*|cancel\w*|void\w*|clear\w*|expung\w*|deadline|ages? out|lapse\w*|"
                 r"after which|once (?:\w+ ){0,3}(?:old|past|reach\w*|exceed\w*)|exceed\w*)")
MECH_LIFETIME_NOUN = (r"(deadline|expiry|expiration|lifespan|time-to-live|\bttl\b|validity window|"
                      r"shelf life|age limit|maximum age)")


def _mech_period(sentence: str) -> int | None:
    """A lifetime of waiting work stated in this sentence, if any."""
    if _has(MECH_NOISE, sentence) and not _has(r"(gives? up|abandon\w*|after which|then)", sentence):
        return None
    if not _has(MECH_LIFETIME, sentence):
        return None
    if not (_has(MECH_WORK, sentence) or _has(MECH_LIFETIME_NOUN, sentence)):
        return None
    durations = _best_durations(sentence)
    if not durations:
        return None
    match = re.search(MECH_LIFETIME, sentence, re.IGNORECASE)
    after = _best_durations(sentence[match.start():])
    return max(after) if after else max(durations)


def _mech_scores(sentence: str) -> tuple[int, int]:
    """Evidence that waiting work dies (flaw) or survives (kept) an account change."""
    flaw = kept = 0
    check = _has(MECH_CHECK, sentence)
    identity = _has(MECH_IDENTITY, sentence)
    not_again = _has(MECH_AGAIN_NOT, sentence)
    gateway_identity = _has(MECH_GATEWAY_IDENTITY, sentence)
    contrast = _has(MECH_CONTRAST, sentence)
    if (check and identity and _has(MECH_DELIVERY, sentence) and not contrast
            and not not_again and not gateway_identity):
        flaw += 3 if _has(MECH_LIVE, sentence) else 2
    if check and identity and _has(MECH_INTAKE, sentence) and (contrast or not _has(MECH_DELIVERY, sentence)):
        kept += 2 if contrast else 1
    if not_again and (identity or check):
        kept += 2
    if gateway_identity:
        kept += 2
    if _has(MECH_SNAPSHOT, sentence) and _has(MECH_ENTITLEMENT, sentence) and _has(MECH_INTAKE, sentence):
        kept += 2
    if _has(MECH_ONLY_FUTURE, sentence):
        kept += 2
    if _has(MECH_ACCOUNT_CHANGE, sentence) and _has(MECH_CASCADE, sentence) and _has(MECH_EFFECT, sentence):
        effect = re.search(MECH_EFFECT, sentence, re.IGNORECASE)
        if NEGATION.search(sentence[max(0, effect.start() - 25):effect.start()]):
            kept += 3
        else:
            flaw += 3
    if (_has(MECH_REJECT, sentence) and _has(MECH_BAD, sentence) and identity
            and not gateway_identity):
        flaw += 3
    return flaw, kept


def script_mechanism(documentation: str, journal) -> str:
    """Decide from the product's mechanisms; fall back on `best` without one."""
    facts = journal_facts(journal)
    if not facts["dispatched_after_revocation"]:
        return "expected"
    flaw = kept = 0
    period = None
    for sentence in _sentences(documentation):
        sentence_flaw, sentence_kept = _mech_scores(sentence)
        flaw += sentence_flaw
        kept += sentence_kept
        if period is None:
            period = _mech_period(sentence)
    if flaw > kept:
        return "flaw"
    if period is not None:
        return "flaw" if facts["waited_s"] > period else "expected"
    if kept > flaw:
        return "expected"
    return script_best(documentation, journal)


SCRIPTS = {"default": script_default, "keywords": script_keywords, "duration": script_duration,
           "best": script_best, "mechanism": script_mechanism}


def frozen_sha256() -> str:
    """Fingerprint of version 2: every script, every helper and every journal."""
    functions = (_journal, _seconds, journal_facts, _sentences, _has, _negated_discard,
                 _durations, script_default, script_duration, script_keywords,
                 _best_durations, _best_period, script_best)
    parts = [inspect.getsource(function) for function in functions]
    constants = (UNITS, DURATION.pattern, QUEUE, DISCARD, PERMISSION, SUBMISSION, ALWAYS,
                 EXPIRY, NEGATION.pattern, JOURNAL, JOURNALS, BEST_NOISE, BEST_WORDS,
                 BEST_DURATION.pattern, BEST_UNITS, BEST_LIFETIME, BEST_WORK, BEST_CHANGE,
                 BEST_RIGHTS, BEST_DELIVERED, BEST_SURVIVE, BEST_KILL, BEST_CHECK,
                 BEST_AT_INTAKE, BEST_RECHECK)
    parts.append(repr(constants))
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def frozen_v3_sha256() -> str:
    """Fingerprint of version 3: version 2 plus the mechanism script and its patterns."""
    functions = (_mech_period, _mech_scores, script_mechanism)
    parts = [frozen_sha256()] + [inspect.getsource(function) for function in functions]
    constants = (MECH_CHECK, MECH_DELIVERY, MECH_INTAKE, MECH_IDENTITY, MECH_LIVE,
                 MECH_AGAIN_NOT, MECH_CONTRAST, MECH_GATEWAY_IDENTITY, MECH_SNAPSHOT,
                 MECH_ENTITLEMENT, MECH_ONLY_FUTURE, MECH_ACCOUNT_CHANGE, MECH_CASCADE,
                 MECH_EFFECT, MECH_REJECT, MECH_BAD, MECH_NOISE, MECH_WORK, MECH_LIFETIME,
                 MECH_LIFETIME_NOUN)
    parts.append(repr(constants))
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def scripts_sha256() -> str:
    """Fingerprint of the first three scripts (version 1), to show they did not change."""
    parts = [inspect.getsource(function) for function in (
        journal_facts, _sentences, _has, _negated_discard, _durations,
        script_default, script_duration, script_keywords)]
    constants = (UNITS, DURATION.pattern, QUEUE, DISCARD, PERMISSION, SUBMISSION,
                 ALWAYS, EXPIRY, NEGATION.pattern, JOURNAL)
    parts.append(repr(constants))
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def run(docs_dir: Path = DOCS_DIR, answer_key: Path = ANSWER_KEY, journals=None) -> dict:
    """Every script on every documentation and every journal, scored on the key."""
    journals = JOURNALS if journals is None else journals
    key = json.loads(answer_key.read_text(encoding="utf-8"))
    rows = []
    for path in sorted(docs_dir.glob("*.md")):
        entry = key[path.name]
        text = path.read_text(encoding="utf-8")
        for name, journal in journals.items():
            expected = expected_verdict(entry["behaviour"], entry.get("period_s"),
                                        journal_facts(journal))
            verdicts = {script: SCRIPTS[script](text, journal) for script in SCRIPTS}
            rows.append({"doc": path.name, "journal": name, "behaviour": entry["behaviour"],
                         "expected": expected, "verdicts": verdicts})
    totals = {name: sum(row["verdicts"][name] == row["expected"] for row in rows)
              for name in SCRIPTS}
    return {"scripts_sha256": scripts_sha256(), "frozen_sha256": frozen_sha256(),
            "frozen_v3_sha256": frozen_v3_sha256(), "rows": rows, "totals": totals}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline probe of the revocation challenge.")
    parser.add_argument("--lot", choices=list(LOTS), default="connu")
    args = parser.parse_args(argv)
    result = run(*LOTS[args.lot])
    print(f"version 1 sha256: {result['scripts_sha256']}")
    print(f"version 2 sha256: {result['frozen_sha256']}")
    print(f"version 3 sha256: {result['frozen_v3_sha256']}")
    header = f"{'documentation':30} {'journal':13} beh  expected  " + "  ".join(f"{name:9}" for name in SCRIPTS)
    print(header)
    for row in result["rows"]:
        marks = "  ".join(f"{('ok ' if row['verdicts'][n] == row['expected'] else 'NO ') + row['verdicts'][n]:9}"
                          for n in SCRIPTS)
        print(f"{row['doc']:30} {row['journal']:13} {row['behaviour']:>3}  {row['expected']:8}  {marks}")
    count = len(result["rows"])
    print("correct: " + ", ".join(f"{name} {total}/{count}" for name, total in result["totals"].items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
