import json
from pathlib import Path
from typing import Any, Dict, Union


def evaluate_report(
    report_source: Union[str, Path, dict],
    ground_truth_source: Union[str, Path, dict],
) -> Dict[str, Any]:
    """
    Evaluates correlation results against ground truth using strict forensic definitions:
    • True Positive (TP): Database reported decrypted with expected fingerprint and expected profile.
    • False Positive (FP): Database reported decrypted or ambiguous that should not be, or decrypted with wrong fingerprint.
    • False Negative (FN): Database that should be decrypted but is not reported that way.
    • Precision = TP / (TP + FP). Recall = TP / (TP + FN). If denominator is 0, report 1.0.
    • Controls: Database expected plain or not_decrypted is correct only when reported with exactly that status.
    """
    if isinstance(report_source, (str, Path)):
        with open(report_source, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    else:
        report_data = report_source

    if isinstance(ground_truth_source, (str, Path)):
        with open(ground_truth_source, "r", encoding="utf-8") as f:
            ground_truth = json.load(f)
    else:
        ground_truth = ground_truth_source

    if isinstance(report_data, dict) and "databases" in report_data:
        actual_dbs = report_data["databases"]
    elif isinstance(report_data, list):
        actual_dbs = report_data
    else:
        raise ValueError("Invalid report data format")

    actual_by_relpath: Dict[str, Dict[str, Any]] = {}
    for db in actual_dbs:
        norm_path = Path(db.get("relpath", "")).as_posix()
        actual_by_relpath[norm_path] = db

    tp = 0
    fp = 0
    fn = 0
    controls_total = 0
    controls_correct = 0
    details = []

    seen_actual = set()

    for gt in ground_truth:
        rel = Path(gt.get("relpath", "")).as_posix()
        expected_status = gt.get("expected_status", gt.get("status"))
        expected_fp = gt.get("expected_key_fingerprint", gt.get("key_fingerprint"))
        expected_prof = gt.get("expected_profile", gt.get("profile"))

        actual = actual_by_relpath.get(rel)
        if actual:
            seen_actual.add(rel)

        actual_status = actual.get("status") if actual else "missing"
        actual_fp = actual.get("key_fingerprint") if actual else None
        actual_prof = actual.get("profile") if actual else None

        passed = False
        reason = ""

        if expected_status == "decrypted":
            if actual_status == "decrypted" and actual_fp == expected_fp and actual_prof == expected_prof:
                tp += 1
                passed = True
            else:
                fn += 1
                if not actual:
                    reason = "Missing database in report"
                elif actual_status in ("decrypted", "ambiguous") and (actual_fp != expected_fp or actual_prof != expected_prof):
                    fp += 1
                    reason = f"Decrypted with wrong key/profile (actual: {actual_fp}/{actual_prof}, expected: {expected_fp}/{expected_prof})"
                else:
                    reason = f"Expected decrypted but got {actual_status}"
        else:
            # Control database: plain or not_decrypted
            controls_total += 1
            if actual_status == expected_status:
                controls_correct += 1
                passed = True
            else:
                if not actual:
                    reason = "Missing database in report"
                elif actual_status in ("decrypted", "ambiguous"):
                    fp += 1
                    reason = f"Control database falsely reported as {actual_status}"
                else:
                    reason = f"Expected control status {expected_status} but got {actual_status}"

        details.append({
            "relpath": rel,
            "passed": passed,
            "expected": {
                "status": expected_status,
                "key_fingerprint": expected_fp,
                "profile": expected_prof,
            },
            "actual": {
                "status": actual_status,
                "key_fingerprint": actual_fp,
                "profile": actual_prof,
            },
            "reason": reason if not passed else None,
        })

    # Any extra databases in the report not in ground truth
    for rel, actual in actual_by_relpath.items():
        if rel not in seen_actual:
            actual_status = actual.get("status")
            if actual_status in ("decrypted", "ambiguous"):
                fp += 1
                details.append({
                    "relpath": rel,
                    "passed": False,
                    "reason": f"Unexpected database reported as {actual_status}",
                    "expected": None,
                    "actual": actual,
                })

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    accuracy = (tp + controls_correct) / len(ground_truth) if len(ground_truth) > 0 else 1.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "controls_total": controls_total,
        "controls_correct": controls_correct,
        "total_expected": len(ground_truth),
        "total_found": len(actual_dbs),
        "matched": tp + controls_correct,
        "details": details,
    }


def run_evaluation(report_file: Union[str, Path], ground_truth_file: Union[str, Path]) -> int:
    """
    Compares report with ground-truth and prints the table and totals.
    Exits with code 1 if precision or recall is below 1.0.
    """
    import sys
    report_path = Path(report_file)
    gt_path = Path(ground_truth_file)

    if not report_path.is_file():
        print(f"Error: Report file not found: {report_path}", file=sys.stderr)
        return 1
    if not gt_path.is_file():
        print(f"Error: Ground truth file not found: {gt_path}", file=sys.stderr)
        return 1

    print(f"[*] Evaluating report: {report_path}")
    print(f"[*] Ground truth: {gt_path}\n")

    try:
        eval_res = evaluate_report(report_path, gt_path)
    except Exception as e:
        print(f"Error during evaluation: {e}", file=sys.stderr)
        return 1

    # Print per-database table
    headers = ["Result", "Database", "Status (Exp / Act)", "Fingerprint (Exp / Act)", "Profile (Exp / Act)"]
    rows = []
    for item in eval_res["details"]:
        tag = "[PASS]" if item["passed"] else "[FAIL]"
        rel = item["relpath"]
        exp = item.get("expected") or {}
        act = item.get("actual") or {}

        exp_st = exp.get("status") or "-"
        act_st = act.get("status") or "-"
        st_col = f"{exp_st} / {act_st}"

        exp_fp = exp.get("key_fingerprint") or "-"
        act_fp = act.get("key_fingerprint") or "-"
        fp_col = f"{exp_fp} / {act_fp}"

        exp_pr = exp.get("profile") or "-"
        act_pr = act.get("profile") or "-"
        pr_col = f"{exp_pr} / {act_pr}"

        rows.append([tag, rel, st_col, fp_col, pr_col])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    print(header_line)
    print(sep_line)
    for row in rows:
        print(" | ".join(row[i].ljust(col_widths[i]) for i in range(len(headers))))

    print("\n=== Evaluation Totals ===")
    print(f"True Positives (TP):   {eval_res['tp']}")
    print(f"False Positives (FP):  {eval_res['fp']}")
    print(f"False Negatives (FN):  {eval_res['fn']}")
    print(f"Controls:              {eval_res['controls_correct']} / {eval_res['controls_total']} correct")
    print(f"Accuracy:              {eval_res['accuracy'] * 100.0:.1f}%")
    print(f"Precision:      {eval_res['precision']:.2f}")
    print(f"Recall:         {eval_res['recall']:.2f}")

    if eval_res["precision"] < 1.0 or eval_res["recall"] < 1.0 or eval_res["controls_correct"] < eval_res["controls_total"]:
        print("\n[-] Evaluation FAILED: precision or recall < 1.00 or control mismatch.", file=sys.stderr)
        return 1

    print("\n[+] All ground truth assertions satisfied.")
    print("[+] Evaluation PASSED: precision 1.00 and recall 1.00 verified.")
    return 0
