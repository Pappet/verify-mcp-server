use crate::contract::CheckStatus;
use crate::verification::RawResult;

pub(crate) fn check_value_in_range(
    input: Option<&str>,
    min: Option<f64>,
    max: Option<f64>,
) -> RawResult {
    let input = match input {
        Some(i) => i,
        None => {
            return RawResult {
                status: CheckStatus::Failed,
                message: "No input provided for range check".into(),
                details: None,
            }
        }
    };

    let value: f64 = match input.trim().parse() {
        Ok(v) => v,
        Err(e) => {
            return RawResult {
                status: CheckStatus::Failed,
                message: format!("Cannot parse '{input}' as number: {e}"),
                details: None,
            }
        }
    };

    let above_min = min.map_or(true, |m| value >= m);
    let below_max = max.map_or(true, |m| value <= m);
    let passed = above_min && below_max;

    let range_str = match (min, max) {
        (Some(lo), Some(hi)) => format!("[{lo}, {hi}]"),
        (Some(lo), None) => format!("[{lo}, ∞)"),
        (None, Some(hi)) => format!("(-∞, {hi}]"),
        (None, None) => "(-∞, ∞)".into(),
    };

    RawResult {
        status: if passed {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        message: if passed {
            format!("Value {value} is within range {range_str}")
        } else {
            format!("Value {value} is OUTSIDE range {range_str}")
        },
        details: None,
    }
}

pub(crate) fn check_diff_size(
    input: Option<&str>,
    max_additions: Option<usize>,
    max_deletions: Option<usize>,
) -> RawResult {
    let input = match input {
        Some(i) => i,
        None => {
            return RawResult {
                status: CheckStatus::Failed,
                message: "No diff input provided. Pass a unified diff in the 'input' field.".into(),
                details: None,
            }
        }
    };

    let mut additions = 0usize;
    let mut deletions = 0usize;
    for line in input.lines() {
        if line.starts_with('+') && !line.starts_with("+++") {
            additions += 1;
        } else if line.starts_with('-') && !line.starts_with("---") {
            deletions += 1;
        }
    }

    let add_ok = max_additions.map_or(true, |m| additions <= m);
    let del_ok = max_deletions.map_or(true, |m| deletions <= m);
    let passed = add_ok && del_ok;

    let mut issues = Vec::new();
    if !add_ok {
        issues.push(format!(
            "additions: {additions} > max {}",
            max_additions.unwrap()
        ));
    }
    if !del_ok {
        issues.push(format!(
            "deletions: {deletions} > max {}",
            max_deletions.unwrap()
        ));
    }

    RawResult {
        status: if passed {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        },
        message: if passed {
            format!("Diff size OK: +{additions} -{deletions} lines")
        } else {
            format!("Diff too large: {}", issues.join(", "))
        },
        details: Some(format!("+{additions} -{deletions} lines")),
    }
}

pub(crate) fn handle_assertion(claim: &str, input: Option<&str>) -> RawResult {
    // The agent asserts something is true and provides evidence.
    // We record it but flag that it's not independently verified.
    match input {
        Some(evidence) if !evidence.trim().is_empty() => RawResult {
            status: CheckStatus::Unverified,
            message: format!("Assertion recorded (UNVERIFIED): {claim}"),
            details: Some(format!(
                "⚠ Agent-provided evidence (not independently verified):\n{evidence}"
            )),
        },
        _ => RawResult {
            status: CheckStatus::Failed,
            message: format!("Assertion WITHOUT evidence: {claim}"),
            details: Some(
                "Agent made a claim but provided no evidence. This is exactly the blind-trust \
                 problem this server exists to prevent."
                    .into(),
            ),
        },
    }
}
