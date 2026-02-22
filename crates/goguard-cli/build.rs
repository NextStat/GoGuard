use std::process::Command;

fn main() {
    // Embed git commit hash at compile time
    let output = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output();

    let git_hash = match output {
        Ok(o) if o.status.success() => String::from_utf8(o.stdout)
            .unwrap_or_default()
            .trim()
            .to_string(),
        _ => "unknown".to_string(),
    };

    println!("cargo:rustc-env=GIT_HASH={git_hash}");

    // Only rebuild if git HEAD changes
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/");
}
