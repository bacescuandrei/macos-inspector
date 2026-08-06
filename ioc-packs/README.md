# IOC packs

Place versioned JSON indicator packs in this directory. Disabled templates are ignored.

Required pack fields: `schema_version`, `name`, `version`, `source`, `updated_at`, and `indicators`.
Supported indicator types are `path`, `sha256`, `bundle_id`, and `launchd_label`.
SHA-256 indicators must declare explicit `paths`; macOS Inspector never performs an unrestricted disk scan.
