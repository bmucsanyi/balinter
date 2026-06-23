use crate::finding::{rule_code, Finding};
use crate::scan::Scan;

pub fn print(scan: &Scan, findings: &[Finding], json: bool) {
    if json {
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
        serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string())
    );
}
