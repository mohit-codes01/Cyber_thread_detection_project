import os
import sys
import io
import json
import zipfile
import tempfile
import shutil
import pandas as pd
import numpy as np
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from app import (
    load_threat_model,
    run_model_inference,
    load_dataset_from_file_or_buffer,
    inspect_zip_entries,
    load_zip_dataset,
    format_file_size,
    get_file_type_label,
    SUPPORTED_TABULAR_EXTENSIONS
)

def run_multi_format_tests():
    print("=" * 70)
    print("RUNNING MULTI-FORMAT UPLOAD & INFERENCE VALIDATION TESTS")
    print("=" * 70)

    # Load Pipeline
    pipeline, err = load_threat_model()
    assert pipeline is not None, f"Failed to load ML pipeline: {err}"
    print("  [PASS] ML Pipeline loaded successfully.")

    # Load base sample data
    sample_csv_path = Path("data/sample/sample_network_traffic.csv")
    assert sample_csv_path.exists(), "Sample CSV not found."
    df_base = pd.read_csv(sample_csv_path)
    print(f"  [PASS] Base dataset loaded ({len(df_base)} rows, {len(df_base.columns)} columns).")

    # 1. TEST CSV
    print("\n[TEST 1] Testing CSV upload and processing...")
    csv_buf = io.BytesIO()
    df_base.to_csv(csv_buf, index=False)
    csv_buf.seek(0)
    df_csv = load_dataset_from_file_or_buffer(csv_buf, "traffic_sample.csv")
    assert df_csv.shape == df_base.shape
    res_csv, err_csv = run_model_inference(df_csv, pipeline)
    assert err_csv is None
    assert res_csv["total_records"] == len(df_base)
    print(f"  [PASS] CSV processed successfully. Total: {res_csv['total_records']}, Threats: {res_csv['threat_count']}")

    # 2. TEST XLSX
    print("\n[TEST 2] Testing XLSX upload and processing...")
    xlsx_buf = io.BytesIO()
    df_base.head(50).to_excel(xlsx_buf, index=False, engine="openpyxl")
    xlsx_buf.seek(0)
    df_xlsx = load_dataset_from_file_or_buffer(xlsx_buf, "traffic_sample.xlsx")
    assert len(df_xlsx) == 50
    res_xlsx, err_xlsx = run_model_inference(df_xlsx, pipeline)
    assert err_xlsx is None
    assert res_xlsx["total_records"] == 50
    print(f"  [PASS] XLSX processed successfully. Total: {res_xlsx['total_records']}, Threats: {res_xlsx['threat_count']}")

    # 3. TEST JSON (records list)
    print("\n[TEST 3] Testing JSON (array of records) upload and processing...")
    json_buf = io.BytesIO(df_base.head(40).to_json(orient="records").encode("utf-8"))
    json_buf.seek(0)
    df_json = load_dataset_from_file_or_buffer(json_buf, "traffic_sample.json")
    assert len(df_json) == 40
    res_json, err_json = run_model_inference(df_json, pipeline)
    assert err_json is None
    assert res_json["total_records"] == 40
    print(f"  [PASS] JSON (records array) processed successfully. Records: {res_json['total_records']}")

    # 4. TEST JSON (nested under 'data' dict)
    print("\n[TEST 4] Testing JSON (nested under dictionary 'data') upload...")
    nested_json = json.dumps({"data": df_base.head(30).to_dict(orient="records")}).encode("utf-8")
    nested_buf = io.BytesIO(nested_json)
    nested_buf.seek(0)
    df_nested = load_dataset_from_file_or_buffer(nested_buf, "nested_traffic.json")
    assert len(df_nested) == 30
    res_nested, err_nested = run_model_inference(df_nested, pipeline)
    assert err_nested is None
    print(f"  [PASS] Nested JSON parsed and inferred successfully.")

    # 5. TEST TXT (comma-separated)
    print("\n[TEST 5] Testing TXT (comma-delimited)...")
    txt_comma = io.StringIO()
    df_base.head(25).to_csv(txt_comma, index=False)
    txt_comma.seek(0)
    df_txt_c = load_dataset_from_file_or_buffer(txt_comma, "network_log.txt")
    assert len(df_txt_c) == 25
    res_txt_c, err_txt_c = run_model_inference(df_txt_c, pipeline)
    assert err_txt_c is None
    print(f"  [PASS] Comma-delimited TXT processed successfully.")

    # 6. TEST TXT (tab-separated)
    print("\n[TEST 6] Testing TXT (tab-delimited)...")
    txt_tab = io.StringIO()
    df_base.head(20).to_csv(txt_tab, sep="\t", index=False)
    txt_tab.seek(0)
    df_txt_t = load_dataset_from_file_or_buffer(txt_tab, "network_tab.txt")
    assert len(df_txt_t) == 20
    res_txt_t, err_txt_t = run_model_inference(df_txt_t, pipeline)
    assert err_txt_t is None
    print(f"  [PASS] Tab-delimited TXT processed successfully.")

    # 7. TEST TXT (whitespace-separated)
    print("\n[TEST 7] Testing TXT (whitespace-delimited)...")
    txt_space = io.StringIO()
    df_subset = df_base.head(15)[["id", "dur", "spkts", "sbytes", "rate", "label"]]
    df_subset.to_csv(txt_space, sep=" ", index=False)
    txt_space.seek(0)
    df_txt_s = load_dataset_from_file_or_buffer(txt_space, "network_space.txt")
    assert len(df_txt_s) == 15
    print(f"  [PASS] Whitespace-delimited TXT parsed successfully into {df_txt_s.shape[1]} columns.")

    # 8. TEST PARQUET
    print("\n[TEST 8] Testing PARQUET upload and processing...")
    pq_buf = io.BytesIO()
    df_base.head(60).to_parquet(pq_buf, index=False)
    pq_buf.seek(0)
    df_pq = load_dataset_from_file_or_buffer(pq_buf, "traffic.parquet")
    assert len(df_pq) == 60
    res_pq, err_pq = run_model_inference(df_pq, pipeline)
    assert err_pq is None
    assert res_pq["total_records"] == 60
    print(f"  [PASS] PARQUET processed successfully. Total: {res_pq['total_records']}, Threats: {res_pq['threat_count']}")

    # 9. TEST ZIP ARCHIVE (Inspection, Selection, Temp Cleanup)
    print("\n[TEST 9] Testing ZIP archive with multiple datasets inside...")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add a CSV file
        zf.writestr("traffic_a.csv", df_base.head(30).to_csv(index=False))
        # Add a JSON file
        zf.writestr("traffic_b.json", df_base.head(20).to_json(orient="records"))
        # Add an ignored file
        zf.writestr("notes.md", "# Security Notes")
        zf.writestr("__MACOSX/._traffic_a.csv", "junk metadata")

    zip_buf.seek(0)
    candidates = inspect_zip_entries(zip_buf)
    print(f"  [PASS] Found candidates in ZIP: {candidates}")
    assert "traffic_a.csv" in candidates
    assert "traffic_b.json" in candidates
    assert "notes.md" not in candidates
    assert "__MACOSX/._traffic_a.csv" not in candidates

    # Extract & Process selected CSV from ZIP
    df_from_zip = load_zip_dataset(zip_buf, "traffic_a.csv")
    assert len(df_from_zip) == 30
    res_zip, err_zip = run_model_inference(df_from_zip, pipeline)
    assert err_zip is None
    assert res_zip["total_records"] == 30
    print("  [PASS] Extracted dataset from ZIP and executed model inference successfully.")

    # 10. TEST FILE INFO LABELS & SIZE FORMATTING
    print("\n[TEST 10] Testing file metadata helper functions...")
    assert format_file_size(500) == "500 B"
    assert format_file_size(2048) == "2.00 KB"
    assert format_file_size(1048576 * 5) == "5.00 MB"
    assert "Excel" in get_file_type_label("dataset.xlsx")
    assert "Parquet" in get_file_type_label("dataset.parquet")
    assert "ZIP" in get_file_type_label("dataset.csv", is_inside_zip=True)
    print("  [PASS] Formatting helpers returned expected human-readable strings.")

    # 11. TEST INVALID TXT ERROR HANDLING
    print("\n[TEST 11] Testing invalid non-tabular TXT error handling...")
    bad_txt = io.StringIO("This is just arbitrary text.\nNothing tabular here.\nEnd of story.")
    try:
        load_dataset_from_file_or_buffer(bad_txt, "random.txt")
        assert False, "Should have raised ValueError on non-tabular TXT"
    except ValueError as val_err:
        print(f"  [PASS] Caught expected error on non-tabular TXT: {val_err}")

    print("\n" + "=" * 70)
    print("ALL MULTI-FORMAT TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 70)

if __name__ == "__main__":
    run_multi_format_tests()
