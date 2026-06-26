use crate::finding::{rule_code, Finding};
use crate::scan::Scan;
use std::collections::HashMap;

pub fn print(scan: &Scan, findings: &[Finding], json: bool, statistics: bool) {
    if statistics {
        print_statistics(findings, json);
    } else if json {
        print_json(findings);
    } else {
        print_text(scan, findings);
    }
}

fn print_text(scan: &Scan, findings: &[Finding]) {
    let total_loc: usize = scan.files.iter().map(|f| f.loc).sum();

    if findings.is_empty() {
        println!(
            "balinter: no findings ({} files, {total_loc} lines)",
            scan.files.len()
        );
        return;
    }

    let label = if findings.len() == 1 {
        "finding"
    } else {
        "findings"
    };
    println!(
        "balinter: {} {label} ({} files, {total_loc} lines)\n",
        findings.len(),
        scan.files.len()
    );

    for f in findings {
        let code = rule_code(f.rule);
        match f.line {
            Some(line) => println!("  {code}  {}:{line}: {}", f.file, f.message),
            None if f.file == "." => println!("  {code}  {}", f.message),
            None => println!("  {code}  {}: {}", f.file, f.message),
        }
    }
}

fn print_json(findings: &[Finding]) {
    let items: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "code": rule_code(f.rule),
                "rule": f.rule,
                "file": f.file,
                "line": f.line,
                "message": f.message,
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&items).expect("serialize findings to JSON")
    );
}

/// Per-rule counts, like ruff's `--statistics`. Sorted by count, then code.
fn print_statistics(findings: &[Finding], json: bool) {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for f in findings {
        *counts.entry(f.rule).or_insert(0) += 1;
    }
    let mut rows: Vec<(&str, usize)> = counts.into_iter().collect();
    rows.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| rule_code(a.0).cmp(rule_code(b.0)))
    });

    if json {
        let items: Vec<serde_json::Value> = rows
            .iter()
            .map(|(rule, count)| {
                serde_json::json!({ "code": rule_code(rule), "rule": rule, "count": count })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&items).expect("serialize statistics to JSON")
        );
    } else {
        for (rule, count) in rows {
            println!("{count:>5}  {}  {rule}", rule_code(rule));
        }
    }
}
