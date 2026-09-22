//! Read-model fixtures shared by the jeryu-tui integration tests.

use jeryu_readmodel::{
    PoolActivity, PoolRollup, RepoActivity, TagDemand, TuiReadModel, sample_read_model,
};

/// A degraded pool fabric: a saturated `trusted` pool with a stuck runner plus
/// tag-starved (`gpu`) queued work that no pool serves.
pub fn degraded_pool_model() -> TuiReadModel {
    let mut saturated = PoolRollup::new("trusted");
    saturated.tags = vec!["oci".into()];
    saturated.active_slots = 2;
    saturated.running_jobs = 2;
    saturated.queued_jobs = 5;
    saturated.failed_jobs = 1;
    saturated.online_runners = 2;
    saturated.stuck_runners = 1;

    TuiReadModel {
        event_cursor: 91,
        pool_activity: PoolActivity {
            repos: vec![RepoActivity {
                repo: "neverhuman/jeryu".into(),
                queued_jobs: 5,
                running_jobs: 2,
                ..RepoActivity::default()
            }],
            pools: vec![saturated],
            unplaceable: vec![TagDemand {
                tags: vec!["gpu".into()],
                count: 3,
            }],
            freshness: None,
        },
        ..Default::default()
    }
}

/// A fully degraded fixture: the sample model with the freshness watermark
/// flipped stale and the runner fabric swapped for the saturated/tag-starved/
/// stuck rollup. Rendering this with [`StreamMode::Degraded`] exercises the
/// degraded path of the chrome (EXPIRED freshness chip + DEGRADED transport
/// badge) and every lens against a non-healthy snapshot.
pub fn degraded_fixture_model() -> TuiReadModel {
    let mut model = sample_read_model();
    model.freshness.overall_outdated = true;
    model.pool_activity = degraded_pool_model().pool_activity;
    model
}
