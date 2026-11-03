//! Offline, builder-only GeoData witnesses and library-default regex compilation.
//!
//! Uses the normal production regex dependency and defaults without introducing
//! experiment-owned compile limits or an end-to-end process-memory guarantee.

use std::{env, fs, net::IpAddr, path::Path, time::Instant};

use regex::bytes::RegexBuilder;
use serde_json::{Value, json};
use vole::{
    config::{DnsNameserverPolicy, DnsPolicySelector, RuleAction, RuleKind, RuleSpec},
    geodata::GeoData,
    routing::GeoMatcher,
};

fn regex_probe(kind: &str, index: usize, label: Option<&str>, pattern: &str) -> Value {
    let mut row = json!({
        "kind": kind,
        "index": index,
        "label": label,
        "source_bytes": pattern.len(),
        "internal_memory_bytes": null,
        "memory_scope": "unavailable: regex public API does not expose internal allocations",
    });
    let started = Instant::now();
    let compiled = RegexBuilder::new(pattern).unicode(false).build();
    row["compile_ms"] = json!(started.elapsed().as_secs_f64() * 1000.0);
    row["library_default_size_limit_exceeded"] = json!(false);
    match compiled {
        Ok(compiled) => {
            row["status"] = json!("ok");
            drop(compiled);
        }
        Err(regex::Error::CompiledTooBig(_)) => {
            row["status"] = json!("library-size-limit");
            row["library_default_size_limit_exceeded"] = json!(true);
        }
        // Never include a compiler error's source text or pattern in logs.
        Err(_) => row["status"] = json!("syntax-error"),
    }
    row
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return output;
        }
    }
}

fn scalar(field: u32, value: u64) -> Vec<u8> {
    let mut output = varint(u64::from(field) << 3);
    output.extend(varint(value));
    output
}

fn bytes(field: u32, value: &[u8]) -> Vec<u8> {
    let mut output = varint((u64::from(field) << 3) | 2);
    output.extend(varint(value.len() as u64));
    output.extend_from_slice(value);
    output
}

fn attribute(key: &str, value_field: u32, value: u64) -> Vec<u8> {
    let mut output = bytes(1, key.as_bytes());
    output.extend(scalar(value_field, value));
    bytes(3, &output)
}

fn domain(kind: u64, value: &str, attrs: &[(&str, u32, u64)]) -> Vec<u8> {
    let mut output = scalar(1, kind);
    output.extend(bytes(2, value.as_bytes()));
    for &(key, field, value) in attrs {
        output.extend(attribute(key, field, value));
    }
    bytes(2, &output)
}

fn rule(kind: RuleKind) -> RuleSpec {
    RuleSpec {
        kind,
        action: RuleAction::Direct,
        no_resolve: false,
    }
}

fn check(rows: &mut Vec<Value>, id: &str, actual: bool, expected: bool) {
    rows.push(json!({
        "id": id,
        "expected": expected,
        "actual": actual,
        "passed": actual == expected,
    }));
}

fn process_memory() -> Value {
    // This probe's own process, not wait4/launcher history or the builder VM.
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let memory = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .and_then(|text| text.split_whitespace().next())
            .and_then(|number| number.parse::<u64>().ok())
            .and_then(|kilobytes| kilobytes.checked_mul(1024))
    };
    json!({
        "vm_hwm_bytes": memory("VmHWM:"),
        "vm_rss_bytes": memory("VmRSS:"),
    })
}

fn actual_snapshot_probe(input: &Value) -> Result<Value, &'static str> {
    if input.is_null() {
        return Ok(json!({"status": "not-requested"}));
    }
    let directory = input["data_dir"].as_str().ok_or("missing-actual-assets")?;
    let mut rules = Vec::new();
    for (key, kind) in [
        ("site_codes", RuleKind::GeoSite as fn(String) -> RuleKind),
        ("ip_codes", RuleKind::GeoIp as fn(String) -> RuleKind),
    ] {
        for code in input[key].as_array().ok_or("invalid-actual-codes")? {
            rules.push(rule(kind(
                code.as_str().ok_or("invalid-actual-code")?.to_owned(),
            )));
        }
    }
    let directory = Path::new(directory);
    let baseline = process_memory();
    let started = Instant::now();
    let old = GeoData::load(directory, &rules).map_err(|_| "actual-first-load-error")?;
    let first_ms = started.elapsed().as_secs_f64() * 1000.0;
    let first_memory = process_memory();
    let started = Instant::now();
    let new = GeoData::load(directory, &rules).map_err(|_| "actual-second-load-error")?;
    let second_ms = started.elapsed().as_secs_f64() * 1000.0;
    let overlap_memory = process_memory();
    let positive = input["positive_domain"]
        .as_str()
        .ok_or("missing-actual-domain-witness")?;
    let negative = input["negative_domain"]
        .as_str()
        .ok_or("missing-actual-negative-witness")?;
    let address = input["positive_ip"]
        .as_str()
        .ok_or("missing-actual-ip-witness")?
        .parse::<IpAddr>()
        .map_err(|_| "invalid-actual-ip-witness")?;
    let mut checks = Vec::new();
    for (label, data) in [("old", &old), ("new", &new)] {
        check(
            &mut checks,
            &format!("{label}-cn-domain-positive"),
            data.matches_geosite("cn", positive),
            true,
        );
        check(
            &mut checks,
            &format!("{label}-cn-domain-negative"),
            data.matches_geosite("cn", negative),
            false,
        );
        check(
            &mut checks,
            &format!("{label}-cn-ip-positive"),
            data.matches_geoip("cn", address),
            true,
        );
    }
    let output = json!({
        "status": "completed",
        "synthetic": false,
        "passed": checks.iter().all(|row| row["passed"] == true),
        "cases": checks,
        "baseline": baseline,
        "first_snapshot": {
            "load_ms": first_ms,
            "process_memory": first_memory,
            "accounted_retained_bytes": old.allocation_capacity(),
            "accounted_peak_bytes": old.peak_allocation_capacity(),
        },
        "two_live_snapshots": {
            "second_load_ms": second_ms,
            "process_memory": overlap_memory,
            "accounted_retained_bytes": old.allocation_capacity() + new.allocation_capacity(),
            "new_accounted_peak_bytes": new.peak_allocation_capacity(),
        },
        "scope": "offline same-asset reload with old snapshot retained; not live update plus traffic",
        "rss_scope": "Linux probe process; excludes Vole runtime/DNS/TUN; not Apple footprint",
    });
    drop(new);
    drop(old);
    Ok(output)
}

fn selector_probe(directory: &Path) -> Result<Value, &'static str> {
    fs::create_dir_all(directory).map_err(|_| "synthetic-directory-error")?;
    let mut site = bytes(1, b"sample");
    site.extend(domain(
        2,
        "domain.probe.test",
        &[("ads", 2, 0), ("cn", 2, 1)],
    ));
    site.extend(domain(
        3,
        "full.probe.test",
        &[("ads", 3, 0), ("!ads", 2, 1)],
    ));
    site.extend(domain(0, "keyword", &[("cn", 2, 1)]));
    site.extend(domain(
        1,
        r"^regex[0-9]+\.probe\.test$",
        &[("ads", 2, 1), ("cn", 2, 0)],
    ));
    fs::write(directory.join("geosite.dat"), bytes(1, &site))
        .map_err(|_| "synthetic-geosite-write-error")?;

    let mut ip = bytes(1, b"sample");
    for (address, prefix) in [("198.51.100.0", 24), ("2001:db8::", 32)] {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "synthetic-ip-invalid")?;
        let packed = match address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        let mut cidr = bytes(1, &packed);
        cidr.extend(scalar(2, prefix));
        ip.extend(bytes(2, &cidr));
    }
    // Mihomo's DAT loader ignores this field. The selector ! is independent.
    ip.extend(scalar(3, 1));
    fs::write(directory.join("geoip.dat"), bytes(1, &ip))
        .map_err(|_| "synthetic-geoip-write-error")?;

    let selectors = [
        "sample",
        "sample@ads",
        "sample@ads@cn",
        "sample@cn",
        "sample@missing",
        "sample@!ads",
        "!sample@ads",
        "!sample@missing",
    ];
    let mut rules = selectors
        .iter()
        .map(|selector| rule(RuleKind::GeoSite((*selector).to_owned())))
        .collect::<Vec<_>>();
    rules.extend([
        rule(RuleKind::GeoIp("sample".to_owned())),
        rule(RuleKind::GeoIp("!sample".to_owned())),
    ]);
    let policy = DnsNameserverPolicy {
        selector: DnsPolicySelector::GeoSite(
            vec!["sample@ads".to_owned(), "!sample@missing".to_owned()].into_boxed_slice(),
        ),
        nameservers: Vec::new().into_boxed_slice(),
    };
    let data = GeoData::load_with_dns_policies(directory, &rules, &[policy])
        .map_err(|_| "synthetic-load-error")?;
    let mut checks = Vec::new();
    for (id, selector, input, expected) in [
        ("domain-suffix", "sample", "sub.domain.probe.test", true),
        ("domain-boundary", "sample", "notdomain.probe.test", false),
        ("full", "sample", "full.probe.test", true),
        ("full-not-subdomain", "sample", "sub.full.probe.test", false),
        ("plain-substring", "sample", "name-keyword.probe.test", true),
        ("regex", "sample", "regex17.probe.test", true),
        ("union-miss", "sample", "miss.probe.test", false),
        (
            "bool-false-key-present",
            "sample@ads",
            "domain.probe.test",
            true,
        ),
        (
            "int-zero-key-present",
            "sample@ads",
            "full.probe.test",
            true,
        ),
        ("plain-excluded", "sample@ads", "keyword.probe.test", false),
        (
            "regex-filtered-in",
            "sample@ads",
            "regex17.probe.test",
            true,
        ),
        ("attribute-and", "sample@ads@cn", "domain.probe.test", true),
        (
            "attribute-and-excluded",
            "sample@ads@cn",
            "full.probe.test",
            false,
        ),
        (
            "attribute-and-bool-false",
            "sample@ads@cn",
            "regex17.probe.test",
            true,
        ),
        ("plain-filtered-in", "sample@cn", "keyword.probe.test", true),
        (
            "literal-exclamation-key",
            "sample@!ads",
            "full.probe.test",
            true,
        ),
        (
            "not-attribute-exclusion",
            "sample@!ads",
            "domain.probe.test",
            false,
        ),
        ("filtered-empty", "sample@missing", "miss.probe.test", false),
        (
            "inverse-hit-excluded",
            "!sample@ads",
            "full.probe.test",
            false,
        ),
        (
            "inverse-includes-outside",
            "!sample@ads",
            "miss.probe.test",
            true,
        ),
        (
            "inverse-includes-other-filter",
            "!sample@ads",
            "keyword.probe.test",
            true,
        ),
        (
            "inverse-filtered-empty",
            "!sample@missing",
            "miss.probe.test",
            true,
        ),
        ("inverse-no-host", "!sample@missing", "", false),
    ] {
        check(
            &mut checks,
            id,
            data.matches_geosite(selector, input),
            expected,
        );
    }
    check(
        &mut checks,
        "filtered-empty-available",
        data.geosite_available("sample@missing"),
        true,
    );
    check(
        &mut checks,
        "missing-inverse-unavailable",
        data.geosite_available("!missing"),
        false,
    );
    check(
        &mut checks,
        "missing-inverse-not-universal",
        data.matches_geosite("!missing", "miss.probe.test"),
        false,
    );
    check(
        &mut checks,
        "missing-inverse-load-error",
        GeoData::load(directory, &[rule(RuleKind::GeoSite("!missing".to_owned()))]).is_err(),
        true,
    );
    for (id, selector, address, expected) in [
        (
            "geoip-v4-reverse-field-ignored",
            "sample",
            "198.51.100.1",
            true,
        ),
        ("geoip-v6", "sample", "2001:db8::1", true),
        ("geoip-v4-miss", "sample", "203.0.113.1", false),
        ("geoip-inverse-v4-in", "!sample", "198.51.100.1", false),
        ("geoip-inverse-v4-out", "!sample", "203.0.113.1", true),
        ("geoip-inverse-v6-out", "!sample", "2001:db9::1", true),
    ] {
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "synthetic-ip-invalid")?;
        check(
            &mut checks,
            id,
            data.matches_geoip(selector, address),
            expected,
        );
    }
    let passed = checks.iter().all(|row| row["passed"] == true);
    Ok(json!({
        "synthetic": true,
        "passed": passed,
        "case_count": checks.len(),
        "cases": checks,
        "accounted_retained_bytes": data.allocation_capacity(),
        "accounted_peak_bytes": data.peak_allocation_capacity(),
        "memory_scope": "diagnostic matcher ledger; not process RSS",
    }))
}

fn run() -> Result<bool, &'static str> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("expected-input-and-output-paths");
    }
    let input: Value =
        serde_json::from_slice(&fs::read(&arguments[1]).map_err(|_| "input-read-error")?)
            .map_err(|_| "input-json-error")?;
    let real = input["real_regexes"]
        .as_array()
        .ok_or("missing-real-regex-array")?;
    let synthetic = input["synthetic_regexes"]
        .as_array()
        .ok_or("missing-synthetic-regex-array")?;
    // Measure retained snapshots before compiler stress changes this process's
    // high-water mark. Later probes do not get attributed to snapshot loading.
    let snapshots = match actual_snapshot_probe(&input["actual_assets"]) {
        Ok(value) => value,
        Err(error) => json!({"status": "failed", "passed": false, "error": error}),
    };
    let mut patterns = Vec::new();
    for (index, pattern) in real.iter().enumerate() {
        patterns.push(regex_probe(
            "upstream",
            index,
            None,
            pattern.as_str().ok_or("invalid-real-regex")?,
        ));
    }
    for (index, item) in synthetic.iter().enumerate() {
        patterns.push(regex_probe(
            "synthetic",
            index,
            Some(item["name"].as_str().ok_or("invalid-synthetic-name")?),
            item["pattern"].as_str().ok_or("invalid-synthetic-regex")?,
        ));
    }
    let directory = input["data_dir"].as_str().ok_or("missing-data-directory")?;
    let selectors = match selector_probe(Path::new(directory)) {
        Ok(value) => value,
        Err(error) => json!({"synthetic": true, "passed": false, "error": error}),
    };
    let regexes_passed = patterns.iter().all(|row| {
        row["status"] == "ok"
            || (row["kind"] == "synthetic" && row["status"] == "library-size-limit")
    });
    let passed = regexes_passed
        && selectors["passed"] == true
        && (snapshots["status"] == "not-requested" || snapshots["passed"] == true);
    let output = json!({
        "regex_configuration": {
            "engine": "regex::bytes::RegexBuilder",
            "scope": "normal production dependency; library defaults, no experiment-owned limits",
            "library_defaults_used": true,
            "unicode": false,
            "retains_all_compiled_matchers": false,
            "timing_scope": "one RegexBuilder build; excludes matching and source extraction",
            "internal_memory_bytes": null,
            "memory_scope": "unavailable: regex public API does not expose internal allocations",
        },
        "regex_checks_passed": regexes_passed,
        "regex_patterns": patterns,
        "selector_checks": selectors,
        "actual_snapshot_checks": snapshots,
    });
    fs::write(
        &arguments[2],
        serde_json::to_vec_pretty(&output).map_err(|_| "output-json-error")?,
    )
    .map_err(|_| "output-write-error")?;
    Ok(passed)
}

fn main() {
    match run() {
        Ok(true) => (),
        Ok(false) => std::process::exit(2),
        Err(error) => {
            eprintln!("geodata-probe: {error}");
            std::process::exit(2);
        }
    }
}
