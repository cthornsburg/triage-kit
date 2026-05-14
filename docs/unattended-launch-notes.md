# Unattended Launch Notes

## Goal

Nice-to-have future behavior for **SEKER**:
- launch with minimal operator interaction
- ideally run after media insertion with as little clicking as possible
- preserve reliable collection even when the endpoint is not in an ideal interactive state

## Important reality check

There is a big difference between:
1. **low-friction authorized launch**, and
2. **bypassing sleep, lock, or screensaver controls**

This project should target **authorized, low-friction launch**.
It should **not** assume or promise lock-screen bypass, stealth execution, or waking protected systems without approved host-side setup.

## Constraints

### Windows USB autorun
Modern Windows generally does **not** allow old-style arbitrary executable autorun from removable media in the way people remember from XP-era behavior.

Practical result:
- "plug in USB and EXE just runs" is not a safe baseline assumption
- expect at least some operator action unless the host has prior approved configuration

### Sleep / suspended systems
If a machine is actually sleeping:
- the OS may not be executing userland processes at all
- USB insertion may or may not wake the host depending on hardware, BIOS/UEFI, and OS power policy
- SEKER cannot count on this without pre-approved endpoint configuration

### Locked screen / screensaver
If the system is awake but locked:
- interactive launch may be blocked or impractical
- trying to design around that drifts into bypass territory fast
- that is out of scope for the baseline collector

## Product requirement framing

Recommended wording:

- **Baseline requirement:** SEKER should be operable by low-skill staff with one obvious launch action.
- **Stretch requirement:** SEKER should support approved low-touch launch options in managed environments.
- **Explicit non-goal:** bypassing lock screens, protected sleep states, or endpoint security controls.

## Safer launch options to explore later

### Option A — One-click operator flow
Best default for v1.

Example:
- insert USB
- open drive
- run `seker.exe`
- optionally answer 1-2 prompts

Pros:
- realistic
- testable
- low compliance drama

### Option B — Managed-environment launcher
For environments you control, consider a pre-positioned helper on the endpoint side.

Examples:
- approved scheduled task
- RMM-triggered launch
- GPO-managed wrapper
- signed launcher already present on fleet systems

Pros:
- much more realistic than removable-media autorun
- can support low-touch response in municipal or enterprise fleets

Tradeoff:
- this is no longer truly "no install / no host prep"

### Option C — Wake-and-run only where explicitly engineered
If you really want wake behavior, treat it as an environment engineering problem, not a SEKER feature promise.

Dependencies may include:
- BIOS/UEFI wake support
- USB wake enabled
- OS power-policy allowance
- approved host-side launch path after wake

Pros:
- achievable in some managed fleets

Tradeoff:
- hardware/policy dependent
- not portable as a default field assumption

## Recommendation

For now:
- design **SEKER v1** around a one-click authorized launch
- document managed-environment low-touch launch as a future track
- keep sleep/lock-screen bypass ideas out of baseline scope

That keeps the collector useful without drifting into fantasy or sketchiness.
