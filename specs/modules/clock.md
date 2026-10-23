# Module `lib/clock.bend`

Wall-clock time in UTC for the HTTP service. HVM only offers a monotonic
clock (`IO/get_time`), so the service reads two Linux files and this module
turns them into a date:

- `/proc/stat`, line `btime <seconds>`: boot time in seconds since the Unix
  epoch, kept up to date by the kernel when the clock is adjusted;
- `/proc/uptime`: seconds since boot (the first number).

Their sum is the current time to the second.

## Representation

Times are pairs `(days, secs)`: days since 1970-01-01 and seconds of the
day. Epoch seconds do not fit in a `u24`, so decimal input is parsed
directly into this form: for each digit `d`, `t = 10·secs + d`,
`days' = 10·days + t / 86400`, `secs' = t % 86400` (all intermediate values
stay below `2^24` for dates before the year 6000).

## API

| Function | Contract |
|---|---|
| `Clock/now(stat, uptime) -> (ok, days, secs)` | Current time; `ok = 0` when `btime` or the uptime digits are missing. |
| `Clock/parse(xs) -> (days, secs, digits)` | Leading decimal digits (at most 12) as `(days, secs)`. |
| `Clock/civil(days) -> (year, month, day)` | Proleptic Gregorian calendar date (H. Hinnant's `civil_from_days`, using only non-negative arithmetic). |
| `Clock/stamp(days, secs)` | `YYYYMMDDHHmmSS`, the format of the signer's `time` parameter. |
| `Clock/iso(days, secs)` | `YYYY-MM-DDTHH:MM:SSZ`, used in job status responses. |
| `Clock/elapsed(d1, s1, d2, s2)` | Seconds from the first time to the second; 0 if the second is earlier, `0xFFFFFF` if they are 100 days or more apart. |

## Internal helpers

`Clock/DAY` (86 400), `Clock/after(xs, needle)` (the bytes after the first
occurrence of `needle`).

## Tests

`clock_civil` (1970-01-01, leap day 2000-02-29, 2026-10-23, 9999-12-31),
`clock_now` (uptime below and above one day), `clock_missing`, `clock_iso`,
`clock_elapsed`. Expected values come from `date -u -d @<seconds>`.
