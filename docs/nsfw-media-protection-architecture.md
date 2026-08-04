# NSFW Media Protection Architecture

Full architecture for protecting child and teen users from pornographic
content across every content surface the messenger runtime sees: incoming
media, outgoing media, links, and text. Text-level NSFW detection already
exists; this blueprint closes the media gap and unifies all layers under one
policy surface.

Status: P0 implemented (trust-gated blur, media EventKind/ReasonCode
contract); P1+ proposed. Owner: safety runtime. Related docs:
`DATAFLOW.md`, `proto-abi-stability.md`, `privacy-audit-policy.md`,
`context-architecture-blueprint.md`.

---

## 1. Problem Statement

The runtime today analyzes only text. `MessageInput.image_data` exists in the
proto contract and crosses the FFI boundary (`aura-agent-ffi`
`lifecycle/state.rs` forwards it), but no analyzer stage ever consumes it —
every call site in core, examples, and tests passes `image_data: None`. A
pornographic image or video with no caption passes through all ten analyzer
stages untouched.

What already works (and must not be duplicated):

| Layer | Status | Location |
|---|---|---|
| Text NSFW/Explicit detection | Done | `ThreatType::Nsfw`, `ThreatType::Explicit`, pattern rules in `patterns_mvp.json`, ML safety labels |
| NSFW evaluation pack | Done | `aura-core/src/scenario_packs/nsfw.rs` (canonical, adversarial, long-context, false-positive) |
| Grooming precursors | Done | `EVENT_KIND_PHOTO_REQUEST`, `EVENT_KIND_SEXUAL_CONTENT`, grooming context detector |
| UI actions | Done | `BlurUntilTap`, `WarnBeforeDisplay`, `WarnBeforeSend`, `EscalateToGuardian`, `SuggestBlockContact` |
| Contact trust model | Done | `CircleTier` (Inner/Regular/Occasional/New), trust decay, behavioral trend |
| Link analysis | Done (P1) | `url_checker.rs`: phishing/homoglyph/doppelganger + adult-content category (`find_adult_content_urls`, `link.adult_content`, `AdultLinkShared` event, minor profiles only) |
| Trust-gated media blur (P0) | Done | `aura-core/src/media.rs`, media stage 2b in the orchestrator, `media.trust_gate.*` policy routing, media `EventKind` contract (proto 57–60) |
| Image content analysis | **Missing** | — |
| Video content analysis | **Missing** | — |
| Outgoing media protection | **Missing** | — |

## 2. Threat Model

Vectors, ordered by expected frequency for the child/teen population:

- **V1 — Unsolicited explicit media** from a low-trust contact (cyberflashing,
  group spam). Highest frequency, lowest sophistication.
- **V2 — Coerced self-generated content**: a groomer pressures the minor to
  *send* explicit images (sextortion pipeline). Highest harm. The precursor
  chain (flattery → photo request → secrecy → threat) is already modeled by
  the context engine; the missing piece is the moment of media send.
- **V3 — Adult link drops** in groups and DMs (`spicycam.example/teens`-style
  spam already anticipated by the `nsfw_group_link_drop` scenario).
- **V4 — Explicit video / GIF / animated sticker** — same as V1 with a
  temporal dimension.
- **V5 — Known circulating material** (revenge-sharing, CSAM). Requires
  perceptual-hash matching against industry lists; legally distinct.
- **V6 — Adversarial evasion**: crops, filters, drawn/hentai content, borders,
  color-shifts, embedding explicit frames inside long benign videos.

Non-goals of this blueprint: server-side crawling, moderation of public feeds,
and CSAM *reporting* pipelines (V5 detection is phased in; reporting is a
product/legal integration, not a runtime concern).

## 3. Design Principles

1. **On-device only.** Media bytes never leave the device and are never
   persisted by the runtime. Matches the existing privacy-safe audit path:
   audit records carry reason codes and tokenized IDs, never content.
2. **Policy before pixels.** The cheapest effective control is trust-gated
   blurring, which needs no model. Classification refines the decision; it is
   not a prerequisite for protection.
3. **Fail closed for minors.** If the vision backend is unavailable, media
   from `New`/`Occasional` contacts on a child profile is still blurred.
4. **Additive ABI only.** All proto changes are new optional fields and new
   enum values, per `proto-abi-stability.md`.
5. **Platform-native where the OS provides it.** Apple ships an on-device
   sensitive-content model (SensitiveContentAnalysis); the core must be able
   to consume a client-side verdict instead of re-classifying.
6. **Evaluation-first.** No layer ships without a scenario pack and
   calibration gates, mirroring `nsfw_quality_gates()`.

## 4. Architecture Overview

```
                       ┌────────────────────────────────────────────┐
                       │              Client (Swift / Kotlin)       │
                       │                                            │
                       │  media ──► downscale ≤512px ──► thumbnail  │
                       │  video ──► keyframes (≤8 @ 1fps)           │
                       │  [Apple] SensitiveContentAnalysis verdict  │
                       └───────────────┬────────────────────────────┘
                                       │ MessageInput{ content_type,
                                       │   image_data?, media_info?,
                                       │   client_vision_verdict? }
═══════════════════════════════════════╪═══ C ABI (protobuf bytes) ═══
                                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│ aura-core  analyze_with_context_staged()                             │
│                                                                      │
│  1. Rate limiter                                                     │
│  2. Pattern layer (text)            ──► signals[]                    │
│  2b. ★ MEDIA STAGE (new)            ──► signals[], context_events[]  │
│      │                                                               │
│      │   ┌──────────────────────────────────────────────┐            │
│      │   │ aura-vision (new crate)                      │            │
│      │   │                                              │            │
│      │   │  client_vision_verdict? ──► trust & map ─┐   │            │
│      │   │  image_data? ──► VisionBackend ──────────┤   │            │
│      │   │    • OnnxNsfwClassifier (feature "onnx") │   │            │
│      │   │    • NoopBackend (fallback)              ├─► │ MediaVerdict│
│      │   │  no pixels + low trust ──► policy-only ──┘   │            │
│      │   └──────────────────────────────────────────────┘            │
│      │                                                               │
│  3. Signal enricher                                                  │
│  4. ML pipeline (text)                                               │
│  5. Domain module (Kids)  ◄── media verdict feeds kids policy        │
│  6. Context tracker       ◄── ExplicitMediaReceived/SendAttempt      │
│  7. Timing analyzer                                                  │
│  8. Contact risk boost    ◄── NSFW media degrades contact trust      │
│  9. Combine signals                                                  │
│ 10. Build output ──► UiActions via age × trust × direction matrix    │
└──────────────────────────────────────────────────────────────────────┘
```

Five defense layers, all converging on the same `AnalysisResult`:

- **L0 Trust gate** (no ML): media from low-trust contacts → blur.
- **L1 Link layer**: adult-category detection in `url_checker`.
- **L2 Text layer**: existing NSFW/Explicit detection (unchanged).
- **L3 Image layer**: on-device classifier / platform verdict.
- **L4 Video layer**: keyframes through L3.
- **L5 Known-material hashes** (phase 4): PDQ perceptual hashing.

## 5. New Crate: `aura-vision`

A focused crate, consistent with the workspace's one-concern-per-crate
layout (`aura-patterns`, `aura-ml`, …). It does **not** depend on `aura-ml`;
both are consumed by `aura-core`.

### 5.1 API surface

```rust
pub struct MediaVerdict {
    pub class: MediaClass,          // Neutral | Suggestive | Explicit | Drawing | Unclear
    pub confidence: f32,            // calibrated, 0.0..=1.0
    pub source: VerdictSource,      // OnDeviceModel | ClientPlatform | PolicyOnly
    pub abstained: bool,            // model unavailable or below decision floor
}

pub trait VisionBackend: Send + Sync {
    fn classify(&self, image: &DecodedImage) -> Result<RawVisionScores, VisionError>;
    fn descriptor(&self) -> BackendDescriptor;  // model id, version, checksum
}
```

Backends:

- **`OnnxNsfwClassifier`** — behind a `onnx` cargo feature, reusing the same
  `ort` (load-dynamic) dependency pattern as `aura-ml`. Input: RGB 224×224.
  Output: per-class logits → per-class calibration (mirroring
  `apply_calibration()` in the ML pipeline) → `MediaVerdict`.
- **`NoopBackend`** — always abstains; forces the policy layer onto the
  fail-closed path. Default when the feature is off or the model fails
  integrity checks.

Client platform verdicts (`client_vision_verdict` in the proto) are not a
backend: they arrive pre-computed, are validated for range/enum sanity, and
take priority over on-core classification when present (`VerdictSource::
ClientPlatform`). This is how Apple SensitiveContentAnalysis plugs in with
zero model shipping on iOS/macOS.

### 5.2 Model contract

| Property | Budget |
|---|---|
| Classes | neutral, suggestive, explicit, drawing/hentai, unclear |
| Format | ONNX, int8 quantized |
| Size | ≤ 20 MB on disk |
| Latency | ≤ 50 ms p95 on a mid-range 2022 Android device |
| Input | 224×224 RGB, client-downscaled thumbnail |
| Integrity | listed in `models/manifest.json`, checksum-verified at load (same discipline as `aura-ml/src/integrity.rs`) |

Decoding hardening: `image_data` is size-capped (recommended client
contract: downscaled thumbnail ≤ 512px longest side, ≤ 1 MB; hard cap 4 MB
enforced at proto decode, consistent with existing size-bounded decode).
Decode failures are non-fatal: they produce `MediaClass::Unclear` +
`abstained = true`, never a panic across the FFI boundary.

### 5.3 Why not extend `aura-ml`?

`aura-ml` is a text pipeline (normalizer → lexicon gate → cascade →
tokenizer → transformer). Image classification shares none of those stages,
only the `ort` dependency. A separate crate keeps both dependency trees
optional and independently testable, and keeps `aura-ml`'s cache/cascade
logic free of image concerns.

## 6. Pipeline Integration (`aura-core`)

### 6.1 New stage 2b — Media Analysis

Runs when `content_type ∈ {Image, Video}` (and later Voice for audio, out of
scope here). Placement after the pattern layer and before the enricher so
that:

- media signals participate in enrichment, the Kids domain module, contact
  risk boost, and combine-signals exactly like text signals;
- the context tracker records media events with full timeline semantics
  (trust decay, weekly snapshots, behavioral trend already apply).

Outputs:

- `Signal { threat: ThreatType::Nsfw, family: SignalFamily::Content, … }`
  with severity scaled by `MediaVerdict` class and confidence.
- Context events (new kinds, §8): `ExplicitMediaReceived`,
  `ExplicitMediaSendAttempt`, `SuggestiveMediaReceived`.

### 6.2 Interaction with the context engine

The high-value composition is media × history:

- `PhotoRequest`/`SecrecyRequest` events from a contact followed by an
  `ExplicitMediaSendAttempt` by the protected user is the sextortion
  signature → escalate independent of any single-message score.
- Repeated `ExplicitMediaReceived` from one contact degrades that contact's
  rating via the existing contact-profile update path — no new mechanism, the
  events flow through the tracker like any other `EventKind`.

### 6.3 Direction awareness

The media stage must know whether the message is being *received* or *sent*
(pre-send hook). `AnalysisMode` / the existing analyze entry points already
distinguish send-side checks for `WarnBeforeSend`; media analysis reuses that
flag. Outgoing explicit media from a minor profile triggers the sextortion
matrix (§7), never a punitive action — the UX goal is a pause-and-think
interstitial plus guardian escalation policy, aligned with Communication
Safety practice.

## 7. Policy Matrix

Decision inputs: age profile (child < 13, teen 13–17, adult), contact trust
(`CircleTier` + trust level), direction (incoming/outgoing), verdict class ×
confidence, and backend availability. Representative rows (full table lives
with `action_policy_expectations.json` when implemented):

| Profile | Direction | Trust | Verdict | Actions |
|---|---|---|---|---|
| Child | in | any | Explicit ≥ .8 | Block-render (BlurUntilTap non-dismissable) + EscalateToGuardian + SuggestBlockContact |
| Child | in | New/Occasional | abstained (no model) | BlurUntilTap + WarnBeforeDisplay (fail closed) |
| Teen | in | New | Explicit ≥ .8 | BlurUntilTap + WarnBeforeDisplay + SuggestReport |
| Teen | in | Inner | Suggestive | WarnBeforeDisplay only |
| Teen | out | any | Explicit ≥ .6 | WarnBeforeSend + SlowDownConversation; + EscalateToGuardian if sextortion signature active |
| Adult | in | New | Explicit | BlurUntilTap (user-configurable off) |
| Adult | in | Inner | Explicit | no action (consenting-adult negative controls stay green) |

Rules of composition:

- Domain (Kids) action override remains **upgrade-only**, as in stage 9
  today.
- Inference-aware refinement (risk horizon, escalation likelihood) may raise
  but never lower a media action for minor profiles.
- False-positive protection: verdicts of `Drawing` and `Suggestive` alone
  never trigger guardian escalation; medical/educational text context (already
  covered by FP scenarios) must not be contradicted by a blurry image verdict
  — text and media signals combine in stage 9, they do not veto each other.

## 8. Contract Changes (additive only)

`proto/aura/messenger/v1/messenger.proto`:

```proto
message MediaInfo {                      // new
  uint32 width = 1;
  uint32 height = 2;
  string mime_type = 3;
  uint64 original_size_bytes = 4;
  uint32 keyframe_index = 5;             // video: which sampled frame
  uint32 keyframe_count = 6;
}

message ClientVisionVerdict {            // new — platform-native result
  MediaVerdictClass class = 1;
  float confidence = 2;
  string provider = 3;                   // e.g. "apple.sca"
}

message MessageInput {
  // existing fields unchanged; image_data stays the thumbnail carrier
  optional MediaInfo media_info = 7;                 // next free tag
  optional ClientVisionVerdict client_vision_verdict = 8;
}

enum EventKind {
  // append after EVENT_KIND_MILITARY_DISINFO = 56
  EVENT_KIND_EXPLICIT_MEDIA_RECEIVED = 57;
  EVENT_KIND_EXPLICIT_MEDIA_SEND_ATTEMPT = 58;
  EVENT_KIND_SUGGESTIVE_MEDIA_RECEIVED = 59;
  EVENT_KIND_ADULT_LINK_SHARED = 60;
}
```

New `ReasonCode` values follow the existing newtype registry so audit
records stay explainable without content. FFI (`aura-ffi`, `aura-agent-ffi`)
needs no new entry points — `image_data` already crosses the boundary; only
the decode size cap and the new optional fields are added.

## 9. Link Layer: Adult Category in `url_checker`

Extend `aura-patterns/src/url_checker.rs` with an `AdultContentUrl`
assessment parallel to `SuspiciousUrl`:

- adult TLD set: `xxx`, `adult`, `porn`, `sex`;
- host/path keyword heuristics (same shape as `suspicious_keywords()`,
  separate list — porn-site vocabulary, uk/ru transliterations included);
- combined with existing IDN normalization so Cyrillic look-alike domains
  are covered for free;
- shorteners already resolve through existing heuristics; an unresolvable
  shortener toward a child profile maps to `ConfirmBeforeOpenLink`.

Signal: `ThreatType::Nsfw`, `SignalFamily::Link`, event
`EVENT_KIND_ADULT_LINK_SHARED`. The pattern database's fail-closed loading
discipline applies (strict validation, no partial lists).

## 10. Video, GIFs, Stickers

Frame extraction stays **client-side** (codecs are platform territory; the
core stays codec-free):

- client samples ≤ 8 keyframes at ~1 fps (first frame always included),
  downscales each, and submits them as a batch of `MessageInput`s sharing
  `conversation_id` with `media_info.keyframe_index/keyframe_count` set;
- core aggregates per-frame verdicts: max-severity wins; ≥ 2 explicit frames
  or 1 explicit + 1 suggestive → `Explicit` at elevated confidence;
- animated stickers/GIFs follow the same path with lower frame budget (≤ 3).

The existing batch entry point (`analyze_batch`) with atomic failure on
malformed input is the natural carrier.

## 11. Known-Material Matching (Phase 4, gated)

For V5 (circulating revenge material, CSAM):

- **PDQ** perceptual hashes (open Meta implementation) computed on-device;
- hash lists obtained via formal membership (NCMEC, IWF) — this is a legal
  and partnership prerequisite, not an engineering one;
- match → immediate block-render + product-level reporting hook (outside the
  runtime); the runtime never stores the media, only the reason code.

Until partnerships exist this layer stays out of the build entirely. It is in
the architecture so the media stage exposes a stable extension point
(`MediaVerdict::source = KnownHashMatch`) rather than being retrofitted.

## 12. Privacy & Audit

- Media bytes: analyzed in memory, never written to disk, never exported in
  `ExportContextResponse`, never included in audit records or evidence
  manifests.
- Audit records carry: reason codes, verdict class, confidence bucket,
  backend descriptor (model id/version), tokenized sender/conversation ids
  under the declared salted scheme. No thumbnails, no hashes of content
  except phase-4 PDQ matches (which are list-membership booleans, not stored
  hashes).
- Guardian escalation surfaces *that* explicit media was involved, never the
  media itself.
- Model files ship with the app bundle; no network fetch at runtime.

## 13. Evaluation Strategy

Extends the existing evaluation-first discipline:

1. **Scenario harness support for media steps.** `ScenarioStep` gains an
   optional synthetic media descriptor (class + confidence the backend is
   mocked to return). Scenario packs test the *policy and context* behavior,
   not the model — the mock backend makes packs deterministic and keeps the
   repo free of explicit imagery.
2. **New pack `media_nsfw.rs`**: trust-gate cases, fail-closed cases,
   sextortion signature (photo request history + outgoing explicit),
   keyframe aggregation, consenting-adult negative controls, FP controls
   (breastfeeding photo → Suggestive/Drawing must not escalate).
3. **Model-level eval outside the repo tree** (same pattern as
   `data/raw/hf` + `dataset_source_manifest`): public NSFW benchmark sets
   referenced by manifest, never vendored. Gates per class: explicit recall
   ≥ 0.90, neutral FPR ≤ 0.03, medical/art slice FPR ≤ 0.05, calibration ECE
   ≤ 0.10 — enforced in the same style as `ThreatCalibrationGate`.
4. **FFI soak**: malformed/oversized/truncated `image_data` corpus in the
   existing FFI smoke/soak suites; panic-free guarantee extends to decode.
5. Workspace gate unchanged: `cargo test --workspace --all-targets
   --all-features` stays the single green path.

## 14. Rollout Phases

| Phase | Scope | ML needed | Exit criteria |
|---|---|---|---|
| **P0** ✅ | Trust-gated blur: media from `New`/`Occasional` contacts on minor profiles → `BlurUntilTap` + `WarnBeforeDisplay`; policy matrix skeleton; new EventKinds/ReasonCodes | none | shipped: deterministic policy-matrix integration tests (`aura-core/tests/media_trust_gate.rs`) green, full workspace green; probabilistic media scenario pack arrives with the P2 mock backend |
| **P1** ✅ | Adult-URL category in `url_checker`; `ADULT_LINK_SHARED` wired to context | none | shipped: heuristic unit tests + integration tests (`aura-core/tests/adult_link_gate.rs`) green incl. IDN/Cyrillic hosts and benign look-alike negatives; minor profiles only |
| **P2** | `aura-vision` crate: ONNX backend + `ClientVisionVerdict` path; Apple SCA integration in `swift/Sources/AuraAgent`; media stage 2b; full policy matrix | yes | model gates (§13.3) green; latency budget met on reference devices; FFI soak green |
| **P3** | Video keyframes; outgoing (send-side) protection + sextortion signature escalation | reuses P2 | sextortion scenario pack green; send-side UX contract signed off |
| **P4** | PDQ known-material matching | list membership | legal/partnership sign-off; block-render path verified |

P0 and P1 ship real protection with zero model risk and should not wait for
P2.

## 15. Risks & Open Questions

- **Model bias / FP harm**: skin-exposure classifiers historically over-flag
  darker skin tones and breastfeeding; the FP slice gates in §13.3 are
  mandatory, and `Suggestive` alone never escalates to a guardian.
- **`ort` on mobile**: load-dynamic ONNX Runtime on Android is proven in
  `aura-ml`'s design but not yet exercised with vision workloads; P2 needs a
  device benchmark spike before committing to the 50 ms budget.
- **Thumbnail contract adoption**: clients must downscale before submission;
  until Kotlin/Swift shims implement it, the hard 4 MB cap plus in-core
  downscale is the fallback (CPU cost noted).
- **Adult-link list maintenance**: keyword/TLD lists need the same dataset
  governance as pattern rules (changelog, review) — folds into
  `dataset-governance.md`.
- **Open**: should `Drawing` (hentai) map to the same policy as `Explicit`
  for child profiles? Current matrix says yes for blur, no for guardian
  escalation; needs product sign-off.
- **Open**: voice-note moaning/audio NSFW is explicitly out of scope here;
  `CONTENT_TYPE_VOICE` remains text-transcript-only.
