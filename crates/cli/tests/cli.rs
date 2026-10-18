use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_r3kj4"))
}
#[test]
fn json_is_machine_readable_and_sources_are_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/offline");
    let result = binary()
        .args([
            "scan",
            root.to_str().unwrap(),
            "--offline",
            "--format",
            "json",
            "--out",
            dir.path().join("out").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["recovered_sources"].as_array().unwrap().len(), 2);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["value"] == "LocalDemoKey9AbCd1234567")
    );
}
#[test]
fn beautify_never_overwrites_input() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("x.js");
    std::fs::write(&input, "const x=1;fetch('/a')").unwrap();
    let result = binary()
        .args(["beautify", input.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("const x = 1"));
    let before = std::fs::read(&input).unwrap();
    let result = binary()
        .args([
            "beautify",
            input.to_str().unwrap(),
            "--out",
            input.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(std::fs::read(input).unwrap(), before);
}
#[test]
fn parse_fallback_has_partial_exit_and_configuration_loads() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("bad.js");
    std::fs::write(&input, "const = ;").unwrap();
    let config =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/config.toml");
    let result = binary()
        .args([
            "--config",
            config.to_str().unwrap(),
            "analyze",
            input.to_str().unwrap(),
            "--out",
            dir.path().join("out").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        serde_json::from_slice::<serde_json::Value>(&result.stdout).unwrap()["coverage"]["partial"]
            == true
    );
}
