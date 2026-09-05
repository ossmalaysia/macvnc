# Licensing and commercial enquiries

Developed by [AnchorSprint](https://anchorsprint.com).
Contact [oss@anchorsprint.com](mailto:oss@anchorsprint.com) for commercial
licensing enquiries, enterprise customization and support.

## Current repository terms

The original MIT notice remains in `LICENSE`. The native combined application
and HP-derived components carry AGPL-3.0-or-later terms; dependencies retain
their respective licenses. See [NOTICE.md](NOTICE.md) and
[provenance](docs/THIRD_PARTY.md). Existing licenses permit commercial use when
their conditions are followed. Contacting AnchorSprint or purchasing a separate
license is not a condition added to those existing rights.

## Proposed future model — not an operative license

AnchorSprint's intended model is a **source-available community license plus
a separate commercial agreement**. It is not an OSI open-source license.

| Intended use | Proposed terms after rights clearance |
|---|---|
| Individual, personal noncommercial use | Free; source inspection and private modification allowed |
| Internal business use by fewer than 10 users | Free; internal modification allowed; 1–9 users |
| Internal business use by 10 or more users | Separate commercial agreement required |
| Resale, paid redistribution, embedding in a sold product, or a hosted/managed service for others | Separate commercial agreement required regardless of user count |
| Enterprise customization or contracted development | Enquire at oss@anchorsprint.com for scope and terms |

The proposed small-business permission is an explicit exception to the general
commercial-use restriction. Internal modifications within that permission would
remain allowed; using a modified version would not evade the user limit.
The final agreement must define user counting (named people versus concurrent
sessions, contractors and affiliates), permitted redistribution/forks, attribution,
license termination, patent rights and warranties. These are drafting decisions,
not restrictions currently imposed by this document.

## Why this cannot replace the current licenses yet

Open-source licenses must permit business use; commercial restrictions and user
caps do not meet the [Open Source Definition](https://opensource.org/osd).
The [GNU AGPL](https://www.gnu.org/licenses/agpl-3.0.html), particularly sections
7 and 10, does not permit downstream recipients to add these restrictions to
covered code. A source-visible repository does not change that requirement.

The HP implementation has documented iShareScreen AGPL provenance. Before a
restricted edition can be offered, obtain adequate alternative rights from all
relevant rights holders or replace the affected implementation with code whose
rights permit the intended model. Earlier grants and third-party notices cannot
simply be revoked or overwritten. No alternative rights have been established
by this document, and no proprietary license for upstream code is promised.

An unmodified [PolyForm Small Business license](https://polyformproject.org/licenses/small-business/1.0.0)
does not match this policy: it uses organization headcount and revenue thresholds,
not a nine-user product allowance. A custom agreement reviewed by licensing
counsel is the appropriate fit after the provenance and rights work is complete.
It must use its own name and must not be presented as an OSI-approved license.

Until then, the practical model is the current AGPL distribution with optional
paid support and customization that respect upstream terms. Any future broader
relicensing also needs compatible rights for new contributions; a standard
sign-off alone does not grant unlimited relicensing permission.
