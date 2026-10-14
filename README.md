# PLANK Linux Host

PLANK Linux Host makes a Linux workstation available to PLANK Clients on Ubuntu
and macOS. It is designed for low-latency remote desktop and color-sensitive
creative applications, including workstations used both at a physical desk and
remotely.

This repository contains the maintained Linux Host source, derived from
Sunshine. The [main PLANK repository](https://github.com/instinctual/plank)
provides its native transport, pinned dependencies, installation integration,
releases and qualification tests.

**The macOS Host is a separate native implementation in
[`apps/host/macos/`](https://github.com/instinctual/plank/tree/main/apps/host/macos)
of the main repository. It is not built from this Linux Host fork.**

[Downloads](https://github.com/instinctual/plank/releases) ·
[Documentation](https://github.com/instinctual/plank/blob/main/docs/README.md) ·
[Build from source](https://github.com/instinctual/plank/blob/main/docs/development/build/from-source.md)

## Platform and capabilities

The Linux build and hardware qualification baseline is **Rocky Linux 9.7,
x86-64, with NVIDIA graphics and an X11 desktop**, packaged for the RHEL 9 family.
Other operating systems, capture stacks and GPU vendors present in inherited
source are not automatically supported PLANK configurations.

- **Capture:** NvFBC for the established 8-bit source path, and experimental
  native X11/XShm capture for a properly configured 10-bit desktop.
- **Encoding:** software x264 and direct NVIDIA NVENC paths, selected by the
  Client's per-bookmark profile. Supported choices include H.264/HEVC and
  8/10-bit 4:4:4 workflows; each encoder has its own format and resolution limits.
- **Color:** full-range RGB-identity 4:4:4 profiles and explicit profile-specific
  conversion. Encoding an NvFBC capture as 10-bit does not turn its 8-bit source
  into native 10-bit capture. H.264 10-bit uses x264, not NVENC.
- **Displays:** physical and virtual/headless layouts, supported multi-display
  canvases, and authenticated layout changes for remote sessions.
- **Input:** keyboard, absolute mouse positioning, buttons, scrolling,
  normalized pen input and raw-HID Wacom forwarding. The Linux tablet path
  supports pressure and application features such as Flame Tablet Margins on
  qualified devices.
- **Desktop access:** OS-account authentication through PAM, desktop ownership
  checks, session takeover, and login/logout recovery.
- **Audio and clipboard:** Host audio streaming and bidirectional text clipboard
  synchronization.
- **Transport:** PLANK's native encrypted QUIC connection, with Kyber/Kymux
  media transport and RaptorQ forward error correction.

Features require a compatible PLANK Client and qualified hardware. Consult the
[acceptance criteria](https://github.com/instinctual/plank/blob/main/docs/development/acceptance-criteria.md)
rather than assuming every NVIDIA GPU or Wacom model behaves identically.

## Install and configure

Download the RPM from [PLANK releases](https://github.com/instinctual/plank/releases).
Install it using `sudo dnf install ./PACKAGE.rpm`, replacing `PACKAGE.rpm` with
the downloaded filename. Follow the release's Host/Client compatibility notes.

Administrator configuration is `/etc/plank/host.conf`. The
[documented Linux template](https://github.com/instinctual/plank/blob/main/packaging/host/linux/config/plank-host.conf)
lists supported settings. Capture source, encoding profile, session display
layout and bitrate are chosen in the Client bookmark, not through a Sunshine
WebUI.

For a hybrid physical/remote workstation, retain
`[display] startup_layout = physical`. For headless startup, use `virtual`.
These select the startup display policy, not a permanent restriction on the
Client's session layout.

The default Host port is **28989 on TCP and UDP**. Provide the required LAN,
VPN or forwarding path and firewall policy yourself. PLANK does not configure
UPnP, provide NAT traversal, or require a private broker/relay product.

Users authenticate with their workstation accounts through `/etc/pam.d/plank-host`.
PAM/SSSD and administrator policy determine account access; root login is disabled
by default. Authorization does not bypass ownership of an existing desktop.
Privileged authentication and system integration are separated from the media
worker; see the parent security documentation for the exact boundaries.

Runtime identity/state lives separately from configuration under `/var/lib/plank/`.
Product logs are under `/var/log/plank/` and require elevated access. Remove the
package with `sudo dnf remove plank-host`; ordinary removal is not a purge of
retained configuration and state.

## Building and contributing

Build from the [parent PLANK repository](https://github.com/instinctual/plank),
where this component is pinned at `apps/host/linux/`. Start with:

- [Building from source](https://github.com/instinctual/plank/blob/main/docs/development/build/from-source.md).
- [Linux builder bootstrap](https://github.com/instinctual/plank/blob/main/docs/development/build/builder-vm-bootstrap.md).
- [Release build runbook](https://github.com/instinctual/plank/blob/main/docs/development/build/release-build-runbook.md).

The parent owns the required dependency patches, native transport build,
packaging and hardware tests. An upstream Sunshine build or a bare standalone
CMake invocation is not the complete PLANK package workflow. Do not substitute
unpatched dependency sources just because they compile.

Linux Host changes belong here; shared protocol, packaging and cross-platform
changes also need the parent repository. Follow its
[contributor guide](https://github.com/instinctual/plank/blob/main/CONTRIBUTING.md)
and coordinate the Host gitlink update. Report PLANK-specific issues to PLANK,
not the upstream Sunshine maintainers.

## Relationship to Sunshine

PLANK retains Sunshine's history and credits, but no longer uses its GameStream
transport, PIN pairing, WebUI, gamepad support or UPnP workflow. A stock Moonlight
Client is not a supported peer for this Host.

Thanks to [Sunshine](https://github.com/LizardByte/Sunshine) and its contributors.
See [LICENSE](LICENSE) and the notices in individual files and dependencies.
The parent project's native transport is AGPL-3.0-or-later and retains its own
license.
