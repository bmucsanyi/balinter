use crate::finding::{Finding, Rule};
use crate::scan::Scan;
use crate::OutputFormat;
use serde_json::{json, Value};
use std::collections::HashMap;

pub fn print(
    scan: &Scan,
    findings: &[Finding],
    format: OutputFormat,
    statistics: bool,
) -> Result<(), String> {
    if statistics {
        print_statistics(findings, format)
    } else {
        match format {
            OutputFormat::Text => {
                print_text(scan, findings);
                Ok(())
            }
            OutputFormat::Json => print_json(findings),
            OutputFormat::Sarif => print_sarif(findings),
            OutputFormat::Github => {
                print_github(findings);
                Ok(())
            }
        }
    }
}

fn print_text(scan: &Scan, findings: &[Finding]) {
    let total_loc: usize = scan.files.iter().map(|file| file.loc).sum();
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
    for finding in findings {
        let location = match (finding.cell, finding.span) {
            (Some(cell), Some(span)) => {
                format!("{}:cell {cell}:{}:{}", finding.file, span.line, span.column)
            }
            (None, Some(span)) => format!("{}:{}:{}", finding.file, span.line, span.column),
            (_, None) if finding.file == "." => String::new(),
            (_, None) => finding.file.clone(),
        };
        let separator = if location.is_empty() { "" } else { ": " };
        println!(
            "  {}  {location}{separator}{}",
            finding.rule.code(),
            finding.message
        );
    }
}

fn print_json(findings: &[Finding]) -> Result<(), String> {
    let value = Value::Array(findings.iter().map(finding_json).collect());
    println!(
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|error| format!("could not serialize findings: {error}"))?
    );
    Ok(())
}

fn print_sarif(findings: &[Finding]) -> Result<(), String> {
    let mut rules: Vec<Rule> = findings.iter().map(|finding| finding.rule).collect();
    rules.sort_unstable();
    rules.dedup();
    let value = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "columnKind": "unicodeCodePoints",
            "tool": {"driver": {
                "name": "balinter",
                "informationUri": "https://github.com/bmucsanyi/balinter",
                "rules": rules.iter().map(|rule| json!({
                    "id": rule.code(),
                    "name": rule.name(),
                    "shortDescription": {"text": rule.explanation()}
                })).collect::<Vec<_>>()
            }},
            "results": findings.iter().map(|finding| {
                let locations = finding_location(finding).into_iter().collect::<Vec<_>>();
                json!({
                    "ruleId": finding.rule.code(),
                    "message": {"text": finding_message(finding)},
                    "locations": locations
                })
            }).collect::<Vec<_>>()
        }]
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|error| format!("could not serialize SARIF: {error}"))?
    );
    Ok(())
}

fn print_github(findings: &[Finding]) {
    for finding in findings {
        let mut properties = vec![format!("title={}", escape_command(finding.rule.code()))];
        if finding.file != "." {
            properties.push(format!("file={}", escape_property(&finding.file)));
        }
        if finding.cell.is_none() {
            if let Some(span) = finding.span {
                properties.push(format!("line={}", span.line));
                properties.push(format!("col={}", span.column));
                properties.push(format!("endLine={}", span.end_line));
                properties.push(format!("endColumn={}", span.end_column));
            }
        }
        println!(
            "::error {}::{}",
            properties.join(","),
            escape_command(&finding_message(finding))
        );
    }
}

fn print_statistics(findings: &[Finding], format: OutputFormat) -> Result<(), String> {
    let mut counts: HashMap<Rule, usize> = HashMap::new();
    for finding in findings {
        *counts.entry(finding.rule).or_insert(0) += 1;
    }
    let mut rows: Vec<(Rule, usize)> = counts.into_iter().collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    match format {
        OutputFormat::Json => {
            let values: Vec<Value> = rows.iter().map(|(rule, count)| json!({"code": rule.code(), "rule": rule.name(), "count": count})).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&values)
                    .map_err(|error| format!("could not serialize statistics: {error}"))?
            );
        }
        OutputFormat::Text => {
            for (rule, count) in rows {
                println!("{count:>5}  {}  {}", rule.code(), rule.name());
            }
        }
        OutputFormat::Sarif | OutputFormat::Github => unreachable!(),
    }
    Ok(())
}

fn finding_json(finding: &Finding) -> Value {
    json!({
        "code": finding.rule.code(),
        "rule": finding.rule.name(),
        "file": finding.file,
        "cell": finding.cell,
        "span": finding.span,
        "line": finding.span.map(|span| span.line),
        "message": finding.message,
    })
}

fn finding_location(finding: &Finding) -> Option<Value> {
    if let Some(cell) = finding.cell {
        return Some(json!({
            "physicalLocation": {"artifactLocation": {"uri": finding.file}},
            "logicalLocations": [{"kind": "module", "name": format!("cell {cell}")}]
        }));
    }
    let mut physical = json!({"artifactLocation": {"uri": finding.file}});
    if let Some(span) = finding.span {
        physical["region"] = json!({
            "startLine": span.line,
            "startColumn": span.column,
            "endLine": span.end_line,
            "endColumn": span.end_column
        });
    }
    (finding.file != ".").then(|| json!({"physicalLocation": physical}))
}

fn finding_message(finding: &Finding) -> String {
    match (finding.cell, finding.span) {
        (Some(cell), Some(span)) => {
            format!("cell {cell}, line {}: {}", span.line, finding.message)
        }
        (Some(cell), None) => format!("cell {cell}: {}", finding.message),
        _ => finding.message.clone(),
    }
}

fn escape_command(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_property(value: &str) -> String {
    escape_command(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Span;

    fn finding(cell: Option<usize>) -> Finding {
        Finding {
            rule: Rule::Stub,
            file: "analysis.ipynb".to_string(),
            span: Some(Span {
                line: 2,
                column: 1,
                end_line: 2,
                end_column: 5,
            }),
            cell,
            message: "placeholder".to_string(),
        }
    }

    #[test]
    fn notebook_locations() {
        let mut finding = finding(Some(3));
        let location = finding_location(&finding).unwrap();
        assert!(location["physicalLocation"].get("region").is_none());
        assert_eq!(location["logicalLocations"][0]["name"], "cell 3");
        assert!(finding_message(&finding).starts_with("cell 3, line 2:"));
        finding.cell = None;
        finding.span = None;
        assert_eq!(
            finding_location(&finding).unwrap()["physicalLocation"]["artifactLocation"]["uri"],
            "analysis.ipynb"
        );
    }
}
