# PLANK host configuration

The host reads `/etc/plank/host.conf`. It uses INI-style
section headings and globally scoped `key = value` entries. Section names are
organizational only. Blank lines and text following `#` are ignored.

This document is the complete accepted runtime key set. A setting absent from
this document is intentionally rejected, including inherited Sunshine options
for unsupported platforms, encoders, display control, update notifications,
consumer NAT discovery, and product behaviors fixed by PLANK.

## General

### host_name

Host name returned during PLANK negotiation and used for mDNS service
advertisement. Default: the operating-system hostname.

### min_log_level

Minimum logged severity. Accepted values: `verbose`, `debug`, `info`,
`warning`, `error`, `fatal`, `none`, or the corresponding integer `0` through
`6`. Default: `info`.

## Network

### port

Base port used by PLANK HTTPS authentication and native QUIC. Default:
`28989`. Changing it requires matching firewall policy and client reachability.

### mdns_discovery

Publish the host through mDNS/Avahi for automatic client discovery. Accepted
values: `true` or `false`. Default: `false`. This controls advertisement only;
manually configured hostname/IP bookmarks continue to work while disabled.

### ping_timeout

Milliseconds allowed for initial media-channel pings and established-client
inactivity before the host cleans up the stream. Default: `10000`.

## Security and state

### allow_root_login

Allow PAM authentication as root. Default: `false`. Enabling this does not
bypass PAM/SSSD/HBAC policy or active-desktop ownership checks.

### publish_session_user

Publish the login name of the account that owns the active user desktop on
unauthenticated `/serverinfo`. Accepted values: `true` or `false`. Default:
`false`. When `true` and a user desktop is active, Clients show
`In Session - Ernie.Armitage`, using the account name as stored. When `false`,
or when the name cannot be published, Clients show `In Session` with no
account. This does not publish a UID or session id, and it does not apply to
the sign-in screen.

### pkey

Path to the host TLS private key. The packaged profile uses
`/etc/plank/tls/key.pem`.

### cert

Path to the host TLS certificate. The packaged profile uses
`/etc/plank/tls/cert.pem`.

### file_state

Path to mutable workstation identity state. The packaged profile uses
`/var/lib/plank/plank-state.json`.

### log_path

Path to the persistent host log. The packaged profile uses
`/var/log/plank/host.log`.

## Audio

### audio_sink

Optional PipeWire/Pulse-compatible host sink name to capture. Empty selects the
operating system's current output sink.

## Input

### keybindings

Optional comma-separated client-keycode/host-keycode replacement pairs. The
default PLANK modifier mappings remain in effect when omitted.

### key_repeat_delay

Milliseconds before a held remote key begins repeating. Default: `500`.

### key_repeat_frequency

Remote key-repeat events per second. Default: approximately `24.9`.

Keyboard, mouse, high-resolution scrolling, and native scancodes are mandatory
PLANK behaviors and are not configurable.

## Display

### startup_layout

Display policy applied before the display manager starts. `physical` preserves
connected displays. `virtual` prepares one internal 1920x1080 login output;
the authenticated bookmark then supplies the active virtual layout. Default:
`physical`.

### adapter_name

Optional GPU/display adapter selector for multi-GPU hosts. Empty uses automatic
selection.

## Common video behavior

### minimum_fps_target

Minimum capture cadence used when the desktop is static. Valid range: `0`
through `1000`. `0` derives the target from half the requested stream rate.

### min_threads

Minimum software-encoder thread/slice count. The packaged PLANK
profile uses `16`.

## NVIDIA NVENC

These settings tune both the qualified direct NVENC path and the retained
NVIDIA compatibility encoder where applicable. They do not select a codec or
backend; the bookmark's encoding profile does that.

### nvenc_preset

NVENC quality preset number from `1` through `7`. Default: `1`.

### nvenc_twopass

NVENC multipass mode: `disabled`, `quarter_res`, or `full_res`. Default:
`quarter_res`.

### nvenc_spatial_aq

Enable spatial adaptive quantization. Accepted values: `true` or `false`.
Default: `false`.

### nvenc_vbv_increase

Percentage added to the NVENC VBV buffer size. Valid range: `0` through `400`.
Default: `0`.

### nvenc_split_encode

Split-frame encoding policy: `disabled`, `driver_decides`, or `enabled`.
Default: `driver_decides`.

### nvenc_h264_cavlc

Use CAVLC rather than CABAC for H.264 when supported. Accepted values: `true`
or `false`. Default: `false`.

## x264 software encoder

### sw_preset

x264 speed/quality preset. The packaged PLANK profile uses
`ultrafast`.

### sw_tune

x264 tuning policy. The packaged PLANK profile uses `zerolatency`.

### sw_vbv_maxrate_percentage

Peak x264 rate as a percentage of the bookmark/session encoder target. Valid
range: `100` through `400`; the packaged value is `150`.

### sw_vbv_buffer_frames

VBV reservoir expressed in average-rate frame units. Valid range: `0` through
`16`; the packaged value is `4`.

### sw_scenecut

x264 scene-change threshold. Valid range: `0` through `100`; `0` disables
adaptive scene-change keyframes. The packaged value is `40`.
