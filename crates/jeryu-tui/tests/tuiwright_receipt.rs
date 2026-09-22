//! tuiwright receipt custody and emission tests.
//!
//! These read `JAIN_RELEASE_CI`, `JAIN_HOST_CI_WRITABLE_ROOT`,
//! `CARGO_TARGET_DIR` and `SOURCE_DATE_EPOCH`, so they behave differently under
//! the release gate. They live apart from the pure, environment-free render
//! assertions in `lens_snapshots.rs`.

mod support;

use jeryu_readmodel::sample_read_model;
use jeryu_tui::tuiwright::{self, SWEEP_SIZES};
use jeryu_tui::{ActiveTab, StreamMode};
use support::degraded_fixture_model;

// ── tuiwright receipt emission ────────────────────────────────────────────

/// Select receipt custody without ever falling back into immutable product
/// source during release CI.
fn select_receipt_target_dir(
    release_ci: bool,
    writable_root: Option<&std::path::Path>,
    cargo_target_dir: Option<&std::path::Path>,
    compile_target_tmpdir: &std::path::Path,
    current_dir: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    if release_ci {
        let root = writable_root
            .ok_or("JAIN_RELEASE_CI=1 requires root-broker JAIN_HOST_CI_WRITABLE_ROOT")?;
        let root_text = root
            .to_str()
            .ok_or("release TUIwright custody root is not UTF-8")?;
        if root == std::path::Path::new("/")
            || !root.is_absolute()
            || root.as_os_str().is_empty()
            || root.as_os_str().len() > 4096
            || root_text.chars().any(char::is_control)
            || root.components().any(|component| {
                !matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err("release TUIwright custody root is not a safe absolute path".to_owned());
        }
        return Ok(root.join("tuiwright-target"));
    }

    if let Some(target) = cargo_target_dir {
        if target.as_os_str().is_empty() || target.as_os_str().len() > 4096 {
            return Err("CARGO_TARGET_DIR is empty or overlong".to_owned());
        }
        return Ok(if target.is_absolute() {
            target.to_path_buf()
        } else {
            current_dir.join(target)
        });
    }

    // Resolve the workspace `target/` directory from the compile-time
    // `CARGO_TARGET_TMPDIR` by walking up to the nearest ancestor literally
    // named `target`. Fall back beside the tmpdir if none is found.
    let tmp = compile_target_tmpdir;
    let mut cur: &std::path::Path = tmp;
    loop {
        if cur.file_name().and_then(|n| n.to_str()) == Some("target") {
            return Ok(if cur.is_absolute() {
                cur.to_path_buf()
            } else {
                current_dir.join(cur)
            });
        }
        match cur.parent() {
            Some(p) => cur = p,
            None => {
                let fallback = tmp.join("target");
                return Ok(if fallback.is_absolute() {
                    fallback
                } else {
                    current_dir.join(fallback)
                });
            }
        }
    }
}

fn workspace_target_dir() -> Result<std::path::PathBuf, String> {
    let release_ci =
        std::env::var_os("JAIN_RELEASE_CI").as_deref() == Some(std::ffi::OsStr::new("1"));
    let writable_root = std::env::var_os("JAIN_HOST_CI_WRITABLE_ROOT");
    let cargo_target_dir = std::env::var_os("CARGO_TARGET_DIR");
    let current_dir = std::env::current_dir()
        .map_err(|error| format!("resolve current directory for TUIwright receipt: {error}"))?;
    let selected = select_receipt_target_dir(
        release_ci,
        writable_root.as_deref().map(std::path::Path::new),
        cargo_target_dir.as_deref().map(std::path::Path::new),
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")),
        &current_dir,
    )?;

    if release_ci {
        let root = writable_root
            .as_deref()
            .map(std::path::Path::new)
            .ok_or("release selection requires a writable root")?;
        let metadata = std::fs::symlink_metadata(root)
            .map_err(|error| format!("inspect release TUIwright custody root: {error}"))?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err("release TUIwright custody root is not a physical directory".to_owned());
        }
        let canonical = std::fs::canonicalize(root)
            .map_err(|error| format!("canonicalize release TUIwright custody root: {error}"))?;
        if canonical != root {
            return Err("release TUIwright custody root is not canonical".to_owned());
        }
    }
    Ok(selected)
}

#[test]
fn release_receipt_target_is_broker_owned_and_never_source_relative() {
    let selected = select_receipt_target_dir(
        true,
        Some(std::path::Path::new("/run/jain-host-ci/request/writable")),
        Some(std::path::Path::new("target")),
        std::path::Path::new("target/tmp/jeryu-tui"),
        std::path::Path::new("/immutable/product-source"),
    )
    .expect("select release receipt target");
    assert_eq!(
        selected,
        std::path::Path::new("/run/jain-host-ci/request/writable/tuiwright-target")
    );
    assert!(!selected.starts_with("/immutable/product-source"));
}

#[test]
fn release_receipt_target_rejects_missing_or_relative_custody() {
    for writable_root in [
        None,
        Some(std::path::Path::new("relative/writable")),
        Some(std::path::Path::new("/")),
        Some(std::path::Path::new("/tmp/control\npath")),
    ] {
        assert!(
            select_receipt_target_dir(
                true,
                writable_root,
                Some(std::path::Path::new("target")),
                std::path::Path::new("target/tmp/jeryu-tui"),
                std::path::Path::new("/immutable/product-source"),
            )
            .is_err()
        );
    }
}

#[test]
fn ordinary_receipt_target_prefers_runtime_cargo_target() {
    let selected = select_receipt_target_dir(
        false,
        None,
        Some(std::path::Path::new("build/target")),
        std::path::Path::new("target/tmp/jeryu-tui"),
        std::path::Path::new("/checkout"),
    )
    .expect("select ordinary receipt target");
    assert_eq!(selected, std::path::Path::new("/checkout/build/target"));
}

/// Render every tab at both sweep sizes across the healthy and degraded
/// fixtures, write the resulting tuiwright receipt under `target/jankurai/ux-qa/`,
/// and assert it covers the full matrix.
///
/// The stamp is injected (never wall-clock): `SOURCE_DATE_EPOCH` if set, else a
/// stable label. This keeps the receipt's identity reproducible.
#[test]
fn tuiwright_receipt_covers_every_tab_at_both_sizes() {
    let stamp = tuiwright::receipt_stamp();

    // Two fixture families: the healthy sample model under FIXTURE transport,
    // and the fully-degraded model under DEGRADED transport.
    let healthy =
        tuiwright::sweep_fixture(&stamp, "healthy", StreamMode::Fixture, sample_read_model);
    let degraded = tuiwright::sweep_fixture(
        &stamp,
        "degraded",
        StreamMode::Degraded,
        degraded_fixture_model,
    );

    // Merge both family sweeps into one receipt.
    let mut receipt = healthy;
    receipt.frames.extend(degraded.frames);

    let expected = ActiveTab::ALL.len() * SWEEP_SIZES.len() * 2;
    assert_eq!(
        receipt.len(),
        expected,
        "receipt must record every tab x both sizes x both fixtures"
    );
    assert_eq!(
        receipt.ok_count(),
        expected,
        "every certified frame must render cleanly"
    );

    // Every tab x size x fixture is present.
    for tab in ActiveTab::ALL {
        for &(width, height) in SWEEP_SIZES {
            for fixture in ["healthy", "degraded"] {
                assert!(
                    receipt.covers(*tab, width, height, fixture),
                    "receipt missing {tab:?} {width}x{height} ({fixture})"
                );
            }
        }
    }

    // Stamp is the injected, deterministic value — not a wall-clock instant.
    assert_eq!(receipt.stamp, stamp);
    assert!(!receipt.stamp.is_empty(), "receipt stamp must be set");

    // Write into the workspace target dir and assert the JSON file exists.
    // `CARGO_TARGET_TMPDIR` lives under the workspace `target/` (e.g.
    // `target/tmp/<pkg>`); walk up to the nearest ancestor named `target`.
    let target_dir = workspace_target_dir().expect("resolve writable tuiwright target");
    let path = tuiwright::write_receipt(&target_dir, &receipt).expect("write tuiwright receipt");
    assert!(
        path.exists(),
        "receipt file not written: {}",
        path.display()
    );
    assert!(
        path.to_string_lossy().contains("jankurai/ux-qa/"),
        "receipt not under target/jankurai/ux-qa/: {}",
        path.display()
    );

    // Round-trip: the on-disk JSON parses back into an identical receipt.
    let raw = std::fs::read_to_string(&path).expect("read back receipt");
    let parsed: tuiwright::TuiwrightReceipt =
        serde_json::from_str(&raw).expect("receipt JSON parses");
    assert_eq!(parsed, receipt, "round-tripped receipt diverged");
}
