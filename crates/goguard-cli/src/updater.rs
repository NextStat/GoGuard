use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const REPO_OWNER: &str = "NextStat";
const REPO_NAME: &str = "goguard-internal";
const USER_AGENT: &str = "goguard-updater";

#[derive(Deserialize)]
struct ReleaseInfo {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Start an asynchronous background check for updates.
///
/// This is fire-and-forget: errors are silently ignored so the main
/// server operation is never disrupted.
pub async fn check_for_updates() {
    let current_version = env!("CARGO_PKG_VERSION");
    let client = match Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        REPO_OWNER, REPO_NAME
    );
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(release) = resp.json::<ReleaseInfo>().await {
            let latest = release.tag_name.trim_start_matches('v');
            if latest != current_version {
                eprintln!("\n💡 New version of GoGuard is available! (v{})", latest);
                eprintln!("   Run `goguard update` to seamlessly self-update.\n");
            }
        }
    }
}

/// Download and replace the current binary and Go bridge.
pub async fn run_update() -> Result<()> {
    println!("Checking for updates...");
    let current_version = env!("CARGO_PKG_VERSION");

    let client = Client::builder().user_agent(USER_AGENT).build()?;

    let url = format!(
        "https://api.github.com/repos/{}/{}/releases/latest",
        REPO_OWNER, REPO_NAME
    );
    let release: ReleaseInfo = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let latest = release.tag_name.trim_start_matches('v');
    if latest == current_version {
        println!(
            "✨ You are already on the latest version (v{}).",
            current_version
        );
        return Ok(());
    }

    println!("🚀 Found newer version: v{}", latest);

    // Determine platform
    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let pattern = match (os, arch) {
        ("macos", "aarch64") => "mac-arm64.tar.gz",
        ("macos", "x86_64") => "mac-amd64.tar.gz",
        ("linux", "x86_64") => "linux-amd64.tar.gz",
        ("linux", "aarch64") => "linux-arm64.tar.gz",
        ("windows", "x86_64") => "windows-amd64.zip",
        _ => anyhow::bail!("Unsupported platform for auto-update: {}-{}", os, arch),
    };

    let asset = release
        .assets
        .iter()
        .find(|a| a.name.contains(pattern))
        .context(format!(
            "Could not find a release asset for {}-{}",
            os, arch
        ))?;

    println!("⬇️  Downloading {}...", asset.name);

    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await?
        .error_for_status()?;
    let bytes = response.bytes().await?;

    let temp_dir = tempfile::tempdir()?;
    let archive_path = temp_dir.path().join(&asset.name);
    fs::write(&archive_path, &bytes)?;

    println!("📦 Extracting artifacts...");

    // Extract everything to the temp dir
    if asset.name.ends_with(".zip") {
        let file = fs::File::open(&archive_path)?;
        let mut archive = zip::ZipArchive::new(file)?;
        archive.extract(temp_dir.path())?;
    } else if asset.name.ends_with(".tar.gz") {
        let tar_gz = fs::File::open(&archive_path)?;
        let tar = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(tar);
        archive.unpack(temp_dir.path())?;
    } else {
        anyhow::bail!(
            "Unsupported archive format: {}. Expected .zip or .tar.gz",
            asset.name
        );
    }

    // Now find the extracted rust binary and go bridge binary
    let exe_ext = env::consts::EXE_SUFFIX;
    let goguard_bin = format!("goguard{}", exe_ext);
    let bridge_bin = format!("goguard-go-bridge{}", exe_ext);

    let extracted_goguard = temp_dir.path().join(&goguard_bin);
    let extracted_bridge = temp_dir.path().join(&bridge_bin);

    let final_goguard = if extracted_goguard.exists() {
        extracted_goguard
    } else {
        // Maybe it's inside a nested folder (like goguard-mac-arm64/goguard)
        find_file(temp_dir.path(), &goguard_bin)
            .context("Could not find goguard binary in the downloaded archive")?
    };

    let final_bridge = if extracted_bridge.exists() {
        Some(extracted_bridge)
    } else {
        find_file(temp_dir.path(), &bridge_bin)
    };

    // Replace self
    println!("🔄 Replacing CLI binary...");
    self_replace::self_replace(&final_goguard)?;

    // Attempt to replace the bridge binary that lives next to the current exe.
    // Bridge replacement is best-effort — if it fails, CLI update still succeeds.
    if let Some(bridge_path) = final_bridge {
        let current_exe = env::current_exe()?;
        if let Some(exe_dir) = current_exe.parent() {
            let target_bridge = exe_dir.join(&bridge_bin);
            println!("🔄 Replacing Go bridge...");

            let temp_bridge_dest = exe_dir.join(format!("{}.tmp", bridge_bin));
            match fs::copy(&bridge_path, &temp_bridge_dest) {
                Ok(_) => {
                    if let Err(e) = fs::rename(&temp_bridge_dest, &target_bridge) {
                        // Clean up temp file on rename failure
                        let _ = fs::remove_file(&temp_bridge_dest);
                        eprintln!("⚠️ Could not replace go-bridge: {e}");
                    } else {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(mut perms) =
                                fs::metadata(&target_bridge).map(|m| m.permissions())
                            {
                                perms.set_mode(0o755);
                                let _ = fs::set_permissions(&target_bridge, perms);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("⚠️ Could not copy go-bridge to temp location: {e}");
                }
            }
        }
    }

    println!("✅ Successfully updated GoGuard to v{}!", latest);
    Ok(())
}

fn find_file(dir: &Path, filename: &str) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && path
                    .file_name()
                    .map(|s| s.to_string_lossy() == filename)
                    .unwrap_or(false)
            {
                return Some(path);
            } else if path.is_dir() {
                if let Some(found) = find_file(&path, filename) {
                    return Some(found);
                }
            }
        }
    }
    None
}
