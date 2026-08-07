//! AUR RPC pkgname→pkgbase resolution (Finding N). AUR git repos are keyed by
//! pkgbase, not pkgname — a split member's clone 404s without this. The awk
//! JSON parser becomes serde_json, but the *checks* are preserved exactly:
//! the result's Name must match the query (a wrong/ambiguous result must not
//! poison the clone URL), PackageBase must pass the path-safe grammar, and an
//! empty result set is a failure.

use std::path::PathBuf;

use anyhow::{bail, Result};
use serde::Deserialize;

use crate::state::valid_pkg_name;

#[derive(Deserialize, Debug)]
struct RpcResponse {
    #[serde(default)]
    resultcount: u64,
    #[serde(default)]
    results: Vec<RpcResult>,
}

#[derive(Deserialize, Debug)]
struct RpcResult {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "PackageBase")]
    package_base: String,
}

/// Overridable transport seam (the script mocks `_aur_rpc_info` in selftest).
pub trait RpcClient {
    /// GET <url>/rpc/v5/info?arg[]=<pkg>; returns the raw JSON body.
    fn info(&self, pkg: &str) -> Result<String>;
}

/// Real transport: `curl -sG --connect-timeout 3 --max-time 8`.
pub struct CurlRpc {
    curl_path: PathBuf,
    pub aur_url: String,
}

impl CurlRpc {
    /// Build a transport with an explicitly selected curl executable. The
    /// production caller supplies `/usr/bin/curl`; tests supply a disposable
    /// script without mutating process-global environment.
    pub fn new(curl_path: impl Into<PathBuf>, aur_url: impl Into<String>) -> Self {
        Self {
            curl_path: curl_path.into(),
            aur_url: aur_url.into(),
        }
    }
}

impl RpcClient for CurlRpc {
    fn info(&self, pkg: &str) -> Result<String> {
        let endpoint = format!("{}/rpc/v5/info", self.aur_url);
        let arg = format!("arg[]={pkg}");
        // ETXTBSY can occur when a test fixture writes a script and execs it
        // immediately, or when the curl binary is being replaced on disk
        // (e.g. a parallel package update). Retry a few times before failing.
        let out = retry_on_textfilebusy(|| {
            std::process::Command::new(&self.curl_path)
                .args([
                    "-sG",
                    "--connect-timeout",
                    "3",
                    "--max-time",
                    "8",
                    &endpoint,
                    "--data-urlencode",
                    &arg,
                ])
                .output()
        })?;
        if !out.status.success() {
            bail!("AUR RPC request failed");
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

fn retry_on_textfilebusy<F>(mut f: F) -> std::io::Result<std::process::Output>
where
    F: FnMut() -> std::io::Result<std::process::Output>,
{
    // ETXTBSY (raw OS error 26 on Linux) occurs when a test fixture writes a
    // script and execs it immediately, or when the curl binary is being
    // replaced on disk. `ErrorKind::TextFileBusy` is not stable, so check the
    // raw error code.
    const ETXTBSY: i32 = 26;
    let mut last_err = None;
    for _ in 0..5 {
        match f() {
            Ok(out) => return Ok(out),
            Err(e) if e.raw_os_error() == Some(ETXTBSY) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("retry loop exhausted")))
}

/// Resolve pkgname → pkgbase. Returns the pkgbase on success; errors on RPC
/// failure, package-not-found, Name mismatch, or an invalid pkgbase. Callers
/// fall back to `pkg` itself for non-split packages (pkgname == pkgbase).
pub fn resolve_pkgbase<C: RpcClient + ?Sized>(client: &C, pkg: &str) -> Result<String> {
    let body = client.info(pkg)?;
    let resp: RpcResponse =
        serde_json::from_str(&body).map_err(|e| anyhow::anyhow!("malformed RPC response: {e}"))?;
    if resp.resultcount == 0 || resp.results.is_empty() {
        bail!("package not found: {pkg}");
    }
    // Name must match the query: defend against a wrong/ambiguous result.
    let Some(result) = resp.results.iter().find(|r| r.name == pkg) else {
        bail!("RPC result Name does not match query {pkg}");
    };
    let base = result.package_base.clone();
    if !valid_pkg_name(&base) {
        bail!("RPC returned invalid pkgbase {base:?}");
    }
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::Path;

    fn logged_args(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Mock transport returning a canned body (or an error).
    struct MockRpc {
        body: RefCell<Option<String>>,
    }
    impl RpcClient for MockRpc {
        fn info(&self, _pkg: &str) -> Result<String> {
            self.body
                .borrow()
                .clone()
                .ok_or_else(|| anyhow::anyhow!("rpc unreachable"))
        }
    }

    fn mock(body: &str) -> MockRpc {
        MockRpc {
            body: RefCell::new(Some(body.to_string())),
        }
    }

    #[test]
    fn split_resolves_pkgbase() {
        // Name != PackageBase, PackageBaseID present, multi-element Depends.
        let body = r#"{"version":5,"type":"multiinfo","resultcount":1,"results":[{"ID":2141419,"Name":"opencl-nvidia-580xx","PackageBase":"nvidia-580xx-utils","PackageBaseID":2094476,"Depends":["zlib","nvidia-580xx-utils"],"Version":"580.173.02-1"}]}"#;
        assert_eq!(
            resolve_pkgbase(&mock(body), "opencl-nvidia-580xx").unwrap(),
            "nvidia-580xx-utils"
        );
    }

    #[test]
    fn nonsplit_resolves_self() {
        let body = r#"{"version":5,"type":"multiinfo","resultcount":1,"results":[{"ID":123,"Name":"cursor-bin","PackageBase":"cursor-bin","PackageBaseID":456,"Version":"3.9.16-1"}]}"#;
        assert_eq!(
            resolve_pkgbase(&mock(body), "cursor-bin").unwrap(),
            "cursor-bin"
        );
    }

    #[test]
    fn notfound_returns_err() {
        let body = r#"{"version":5,"type":"multiinfo","resultcount":0,"results":[]}"#;
        assert!(resolve_pkgbase(&mock(body), "totally-fake").is_err());
    }

    #[test]
    fn name_mismatch_returns_err() {
        // Response is for a DIFFERENT package → must not trust its PackageBase.
        let body = r#"{"version":5,"type":"multiinfo","resultcount":1,"results":[{"ID":1,"Name":"some-other-pkg","PackageBase":"evil-base","PackageBaseID":2}]}"#;
        assert!(resolve_pkgbase(&mock(body), "cursor-bin").is_err());
    }

    #[test]
    fn invalid_pkgbase_returns_err() {
        let body = r#"{"version":5,"type":"multiinfo","resultcount":1,"results":[{"ID":1,"Name":"cursor-bin","PackageBase":"../escape","PackageBaseID":2}]}"#;
        assert!(resolve_pkgbase(&mock(body), "cursor-bin").is_err());
    }

    #[test]
    fn unreachable_returns_err() {
        let m = MockRpc {
            body: RefCell::new(None),
        };
        assert!(resolve_pkgbase(&m, "cursor-bin").is_err());
    }

    #[test]
    fn curl_transport_uses_expected_endpoint_and_payload() {
        let temp = tempfile::tempdir().unwrap();
        let log = temp.path().join("curl.log");
        let script = temp.path().join("fake_curl");
        let expected =
            "{\"resultcount\":1,\"results\":[{\"Name\":\"pkg\",\"PackageBase\":\"pkg\"}]}";
        let script_body = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"{}\"\necho '{}'\n",
            log.display(),
            expected
        );
        std::fs::write(&script, script_body).unwrap();
        let mut perm = std::fs::metadata(&script).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(0o755);
        std::fs::set_permissions(&script, perm).unwrap();

        let rpc = CurlRpc::new(script.clone(), "https://example.invalid/api");
        let body = rpc.info("target").unwrap();
        assert_eq!(body.trim_end(), expected);
        let actual = logged_args(&log);
        let expected: Vec<String> = [
            "-sG",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            "https://example.invalid/api/rpc/v5/info",
            "--data-urlencode",
            "arg[]=target",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            actual, expected,
            "curl transport must receive the hardened argument vector"
        );
    }

    #[test]
    fn curl_transport_propagates_command_failure() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("fake_curl_fail");
        std::fs::write(&script, "#!/bin/sh\nexit 1\n").unwrap();
        let mut perm = std::fs::metadata(&script).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perm.set_mode(0o755);
        std::fs::set_permissions(&script, perm).unwrap();

        let rpc = CurlRpc::new(script.clone(), "https://example.invalid/api");
        assert!(rpc.info("target").is_err());
    }
}
