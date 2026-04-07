# Changelog

---

## [1.2] - 2026-04-07
### Overview
Added features to `log_feeder.sh` so it's not just a rebranding of tail. We added a timezone feature `-tz`, and also a time range in the format HH:MM `-tr`. You can learn more about it with `-h`

### Added
- `-tr` for time range, its filter with format HH:MM-HH:MM, e.g. `./log_feeder.sh -tr 10:00-01:00 sample.log`
- `-tz` for timezone, using format UTC+x or UTC-x, e.g. `./log_feeder.sh -tz UTC+4 sample.log`

### Fixed
-  Fix the wrong time output

---
