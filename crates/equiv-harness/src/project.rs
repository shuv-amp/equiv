//! Materialises the probe crate on disk.
//!
//! The probe is a standalone binary crate that depends on **both** versions of
//! the crate under test, linked under distinct aliases:
//!
//! ```toml
//! equiv_old = { package = "roman", version = "=0.1.6" }
//! equiv_new = { package = "roman", version = "=0.2.0" }
//! ```
//!
//! Cargo's dependency renaming is what makes this possible at all, and it is
//! the same mechanism `rust-semverver` uses to get two versions of a crate into
//! one dependency graph.
//!
//! # The constraint that decides which source you can use
//!
//! **Cargo unifies semver-compatible versions of a package.** Renaming does not
//! change that — it aliases the dependency, it does not duplicate the package.
//! So the manifest above works only because `0.1.6` and `0.2.0` are
//! *incompatible*. Ask for a patch or minor pair and nothing resolves:
//!
//! ```text
//! error: failed to select a version for `levenshtein`.
//! versions that meet the requirements `=1.0.4` are: 1.0.4
//! all possible versions conflict with previously selected packages
//!   previously selected package `levenshtein v1.0.5`
//! ```
//!
//! Patch and minor pairs are the entire population worth scanning, so
//! [`Source::Version`] is the *narrow* path, not the default one. The general
//! path is [`Source::Path`]: unpack both `.crate` tarballs and
//! [`retag_version`] them to [`OLD_VERSION`] and [`NEW_VERSION`], which are
//! deliberately incompatible with each other and with anything published.
//!
//! # Known hazard
//!
//! Two versions of a crate coexisting in one binary will collide on anything
//! process-global: `#[no_mangle]` symbols, `links =` native libraries, `static
//! mut`, or constructor attributes. The eligibility gate rejects those cases
//! upstream, but a link failure here is still a possible outcome and must be
//! reported as `UNKNOWN(BuildFailed)` — never as an absence of divergence.

use std::path::{Path, PathBuf};

use crate::codegen::{self, HarnessSpec, NEW, OLD};
use crate::corpus::Corpus;
use sha2::{Digest, Sha256};

/// Where one side of the comparison comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A local directory — a git worktree, or an unpacked `.crate` file.
    ///
    /// `version` must match what the directory's manifest actually declares.
    /// Use [`retag_version`] to make two copies distinguishable first; cargo
    /// refuses two path dependencies sharing a name *and* a version:
    ///
    /// ```text
    /// error: package collision in the lockfile: packages budget v0.0.0 (…/new)
    /// and budget v0.0.0 (…/old) are different, but only one can be written to
    /// lockfile unambiguously
    /// ```
    Path { dir: PathBuf, version: String },
    /// An exact version from a registry.
    ///
    /// Usable **only for a semver-incompatible pair** (`0.1.6` vs `0.2.0`,
    /// `1.x` vs `2.x`). Cargo unifies compatible versions, so a patch or minor
    /// pair fails to resolve; see the module docs. Vendor those with
    /// [`Source::Path`] and [`retag_version`] instead.
    Version(String),
}

impl Source {
    /// A path source at the conventional retagged version for the old side.
    pub fn old_path(dir: impl Into<PathBuf>) -> Self {
        Source::Path {
            dir: dir.into(),
            version: OLD_VERSION.into(),
        }
    }

    /// A path source at the conventional retagged version for the new side.
    pub fn new_path(dir: impl Into<PathBuf>) -> Self {
        Source::Path {
            dir: dir.into(),
            version: NEW_VERSION.into(),
        }
    }

    fn to_toml(&self, package: &str) -> String {
        match self {
            Source::Path { dir, version } => format!(
                "{{ package = {:?}, path = {:?}, version = {:?} }}",
                package,
                dir.display().to_string(),
                format!("={version}")
            ),
            Source::Version(v) => format!(
                "{{ package = {package:?}, version = {:?} }}",
                format!("={v}")
            ),
        }
    }

    /// Return a stable identity for the source used by a checked runner.
    ///
    /// Path sources are hashed by relative path and contents. Symlinks are
    /// rejected rather than followed, so a malformed artifact cannot make
    /// fingerprinting walk outside its root. Registry sources use their exact
    /// package version; Cargo additionally verifies registry checksums while
    /// resolving them.
    pub fn fingerprint(&self, package: &str) -> std::io::Result<String> {
        match self {
            Source::Version(version) => Ok(format!("registry:{package}@{version}")),
            Source::Path { dir, .. } => {
                let metadata = std::fs::symlink_metadata(dir)?;
                if !metadata.file_type().is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("artifact path is not a directory: {}", dir.display()),
                    ));
                }
                let mut hasher = Sha256::new();
                hash_tree(dir, Path::new(""), &mut hasher)?;
                Ok(format!("path:{package}:sha256:{:x}", hasher.finalize()))
            }
        }
    }
}

fn hash_tree(root: &Path, relative: &Path, hasher: &mut Sha256) -> std::io::Result<()> {
    let path = root.join(relative);
    let metadata = std::fs::symlink_metadata(&path)?;
    let name = relative.to_string_lossy();
    hasher.update([0x01]);
    hasher.update((name.len() as u64).to_le_bytes());
    hasher.update(name.as_bytes());

    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("artifact contains unsupported symlink: {}", path.display()),
        ));
    } else if file_type.is_dir() {
        hasher.update([0x03]);
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<_>>()?;
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
        for entry in entries {
            let child = entry
                .strip_prefix(root)
                .expect("read_dir entry must be below its root");
            hash_tree(root, child, hasher)?;
        }
    } else if file_type.is_file() {
        hasher.update([0x04]);
        let bytes = std::fs::read(path)?;
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    } else {
        hasher.update([0x05]);
    }
    Ok(())
}

/// Version stamped onto the old copy so cargo can tell the two apart.
pub const OLD_VERSION: &str = "0.0.0-equiv-old";
/// Version stamped onto the new copy.
pub const NEW_VERSION: &str = "0.0.0-equiv-new";

/// Rewrite the `version` field in a crate directory's `[package]` section.
///
/// Only the version is touched, never the package name: crates that refer to
/// themselves by name (macro expansions emitting `::mycrate::…`, `extern
/// crate`) keep working, while cargo gains the distinct identity it needs.
///
/// The directory is expected to be a throwaway copy — a git worktree or an
/// unpacked `.crate` — never the user's working tree.
pub fn retag_version(dir: &Path, version: &str) -> std::io::Result<()> {
    if version.is_empty()
        || version
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "version must contain only ASCII SemVer characters",
        ));
    }
    let manifest = dir.join("Cargo.toml");
    let src = std::fs::read_to_string(&manifest)?;
    let mut out = String::with_capacity(src.len() + 32);
    let mut in_package = false;
    let mut done = false;

    for line in src.lines() {
        let t = line.trim_start();
        if t.starts_with('[') {
            in_package = t.starts_with("[package]");
        }
        if in_package && !done && t.starts_with("version") && t[7..].trim_start().starts_with('=') {
            out.push_str(&format!("version = \"{version}\"\n"));
            done = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }

    if !done {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "no `version` field found in [package] of {}",
                manifest.display()
            ),
        ));
    }
    std::fs::write(&manifest, out)
}

/// A probe crate ready to be written out.
#[derive(Debug, Clone)]
pub struct ProbeCrate {
    /// Name of the crate under test, identical on both sides.
    pub package: String,
    pub old: Source,
    pub new: Source,
    pub spec: HarnessSpec,
    /// Literals mined from the crate under test, baked into the probe.
    ///
    /// Empty is legal and means uniform-ish random input, which finds very
    /// little: on `roman::to` the mined dictionary produced a witness in under
    /// 30 000 draws where an empty one found nothing in 200 000. Mine it with
    /// [`Corpus::mine`] over the crate's own sources.
    pub corpus: Corpus,
}

impl ProbeCrate {
    pub fn manifest(&self) -> String {
        format!(
            "# @generated by equiv-harness. Do not edit.\n\
             [package]\n\
             name = \"equiv-probe-gen\"\n\
             version = \"0.0.0\"\n\
             edition = \"2021\"\n\
             publish = false\n\n\
             # Standalone: must not be absorbed into an enclosing workspace.\n\
             [workspace]\n\n\
             [dependencies]\n\
             arbitrary = {{ version = \"1\", features = [\"derive\"] }}\n\
             {OLD} = {}\n\
             {NEW} = {}\n\n\
             [[bin]]\n\
             name = \"probe\"\n\
             path = \"src/main.rs\"\n\n\
             [profile.dev]\n\
             debug = false\n",
            self.old.to_toml(&self.package),
            self.new.to_toml(&self.package),
        )
    }

    pub fn main_rs(&self) -> String {
        codegen::generate_with(&self.spec, &self.corpus)
    }

    /// Write the crate into `dir`, creating it if needed.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("Cargo.toml"), self.manifest())?;
        std::fs::write(dir.join("src/main.rs"), self.main_rs())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::Param;
    use crate::gentype::GenType;

    fn probe(old: Source, new: Source) -> ProbeCrate {
        ProbeCrate {
            package: "semver".into(),
            old,
            new,
            corpus: Corpus::default(),
            spec: HarnessSpec {
                fn_path: "parse".into(),
                params: vec![Param {
                    name: "p0".into(),
                    ty: GenType::StrRef,
                }],
                max_len: 32,
            },
        }
    }

    #[test]
    fn registry_versions_are_pinned_exactly() {
        // A semver-*incompatible* pair, which is the only kind cargo will put
        // in one dependency graph. `=1.0.23` with `=1.0.24` renders just as
        // cleanly here and then fails to resolve; see the module docs.
        let p = probe(
            Source::Version("0.1.6".into()),
            Source::Version("0.2.0".into()),
        );
        let m = p.manifest();
        assert!(
            m.contains(r#"equiv_old = { package = "semver", version = "=0.1.6" }"#),
            "{m}"
        );
        assert!(
            m.contains(r#"equiv_new = { package = "semver", version = "=0.2.0" }"#),
            "{m}"
        );
    }

    #[test]
    fn the_retag_versions_are_incompatible_with_each_other() {
        // The property the whole vendored path rests on. Two pre-release
        // versions of `0.0.0` share no compatibility range, with each other or
        // with any published version, so cargo keeps both packages distinct.
        assert_ne!(OLD_VERSION, NEW_VERSION);
        for v in [OLD_VERSION, NEW_VERSION] {
            assert!(v.starts_with("0.0.0-"), "{v} must be a 0.0.0 pre-release");
        }
    }

    #[test]
    fn path_sources_carry_distinct_versions() {
        // Without distinct versions cargo refuses the lockfile outright.
        let p = probe(Source::old_path("/tmp/old"), Source::new_path("/tmp/new"));
        let m = p.manifest();
        assert!(
            m.contains(r#"path = "/tmp/old", version = "=0.0.0-equiv-old""#),
            "{m}"
        );
        assert!(
            m.contains(r#"path = "/tmp/new", version = "=0.0.0-equiv-new""#),
            "{m}"
        );
        assert_ne!(OLD_VERSION, NEW_VERSION);
    }

    #[test]
    fn retag_rewrites_only_the_package_version() {
        let dir = std::env::temp_dir().join(format!("equiv-retag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"budget\"\nversion = \"1.2.3\"\nedition = \"2021\"\n\n\
             [dependencies]\nserde = { version = \"1.0.0\" }\n",
        )
        .unwrap();

        retag_version(&dir, OLD_VERSION).unwrap();
        let m = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();

        assert!(m.contains("version = \"0.0.0-equiv-old\""), "{m}");
        assert!(!m.contains("\"1.2.3\""), "old version must be gone: {m}");
        assert!(
            m.contains("name = \"budget\""),
            "name must be preserved: {m}"
        );
        // A dependency's version must not be touched.
        assert!(m.contains("serde = { version = \"1.0.0\" }"), "{m}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retag_reports_a_manifest_without_a_version() {
        let dir = std::env::temp_dir().join(format!("equiv-retag-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        assert!(retag_version(&dir, OLD_VERSION).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retag_rejects_manifest_injection_in_version() {
        let dir = std::env::temp_dir().join(format!("equiv-retag-invalid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        assert!(retag_version(&dir, "0.0.0\"\n[workspace]").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manifest_declares_an_empty_workspace() {
        // Without this the probe is silently absorbed by any enclosing
        // workspace and the pinned-version trick stops working.
        assert!(
            probe(Source::Version("1".into()), Source::Version("2".into()))
                .manifest()
                .contains("[workspace]")
        );
    }

    #[test]
    fn manifest_parses_as_toml_shaped_keyvalues() {
        // No toml dependency here; check the structural essentials instead.
        let m = probe(Source::Version("1".into()), Source::Version("2".into())).manifest();
        for section in ["[package]", "[dependencies]", "[[bin]]", "[workspace]"] {
            assert!(m.contains(section), "missing {section}");
        }
        assert_eq!(m.matches("[dependencies]").count(), 1);
    }

    #[test]
    fn write_to_creates_both_files() {
        let dir = std::env::temp_dir().join(format!("equiv-probe-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = probe(Source::Version("1".into()), Source::Version("2".into()));
        p.write_to(&dir).unwrap();
        assert!(dir.join("Cargo.toml").is_file());
        assert!(dir.join("src/main.rs").is_file());
        let src = std::fs::read_to_string(dir.join("src/main.rs")).unwrap();
        syn::parse_file(&src).expect("written probe must be valid Rust");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_fingerprint_changes_when_source_changes() {
        let dir = std::env::temp_dir().join(format!("equiv-fingerprint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        std::fs::write(dir.join("lib.rs"), "pub fn f() -> u8 { 1 }\n").unwrap();
        let source = Source::old_path(&dir);
        let before = source.fingerprint("x").unwrap();
        std::fs::write(dir.join("lib.rs"), "pub fn f() -> u8 { 2 }\n").unwrap();
        let after = source.fingerprint("x").unwrap();
        assert_ne!(before, after);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn manifest_escapes_untrusted_version_text() {
        let p = probe(
            Source::Version("1.0.0\\\"\nmalformed".into()),
            Source::Version("2.0.0".into()),
        );
        let manifest = p.manifest();
        assert!(
            manifest.contains("\\\\\\\""),
            "version must be escaped: {manifest}"
        );
        assert!(!manifest.contains("version = \"=1.0.0\\\"\nmalformed\""));
    }
}
