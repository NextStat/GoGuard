class Goguard < Formula
  desc "Rust-level safety analyzer for Go"
  homepage "https://github.com/NextStat/GoGuard"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/NextStat/GoGuard/releases/download/v#{version}/goguard-#{version}-aarch64-apple-darwin.tar.gz"
      # sha256 will be filled in by release automation
    end

    on_intel do
      url "https://github.com/NextStat/GoGuard/releases/download/v#{version}/goguard-#{version}-x86_64-apple-darwin.tar.gz"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/NextStat/GoGuard/releases/download/v#{version}/goguard-#{version}-aarch64-unknown-linux-gnu.tar.gz"
    end

    on_intel do
      url "https://github.com/NextStat/GoGuard/releases/download/v#{version}/goguard-#{version}-x86_64-unknown-linux-gnu.tar.gz"
    end
  end

  def install
    bin.install "goguard"
    bin.install "goguard-go-bridge"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/goguard --version")
  end
end
