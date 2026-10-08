"""
Comprehensive Verification Suite for Universal Dual-Engine Threat Detection.
Tests SIH-145 Multi-Threat Classifier, UNSW-NB15 Binary Classifier,
and the Universal Network Flow Adapter on custom user datasets.
"""

import os
import sys
import io
import json
import zipfile
import pandas as pd
import numpy as np
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from app import (
    load_threat_model,
    load_sih_threat_model,
    run_model_inference,
    run_universal_threat_inference,
    detect_best_engine,
    adapt_dataframe_for_sih,
    load_dataset_from_file_or_buffer
)

def run_tests():
    print("=" * 75)
    print("RUNNING COMPREHENSIVE UNIVERSAL DUAL-ENGINE VERIFICATION SUITE")
    print("=" * 75)

    # 1. Load models
    print("\n[TEST 1] Loading ML Model Engines...")
    unsw_pipeline, unsw_err = load_threat_model()
    sih_bundle, sih_err = load_sih_threat_model()

    assert unsw_err is None, f"UNSW Model failed to load: {unsw_err}"
    assert sih_err is None, f"SIH Model failed to load: {sih_err}"
    assert unsw_pipeline is not None
    assert sih_bundle is not None
    print("  [PASS] Both UNSW-NB15 and SIH-145 ML models loaded into memory successfully.")

    # 2. Test SIH-145 Dataset (User's uploaded sih_ps145_test.csv file!)
    print("\n[TEST 2] Testing User's SIH PS-145 Dataset (sih_ps145_test.csv)...")
    sih_test_path = Path("data/sih/sih_ps145_test.csv")
    assert sih_test_path.exists(), "SIH test file missing"
    df_sih = pd.read_csv(sih_test_path)

    # Auto-detect engine
    engine_detected = detect_best_engine(df_sih, sih_bundle, unsw_pipeline)
    assert engine_detected == "SIH-145", f"Expected SIH-145, got {engine_detected}"
    print(f"  [PASS] Smart Auto-Detect correctly identified engine as: {engine_detected}")

    # Run inference
    res_sih, err_sih = run_universal_threat_inference(df_sih, unsw_pipeline, sih_bundle, "Auto-Detect")
    assert err_sih is None, f"SIH inference returned error: {err_sih}"
    assert res_sih is not None
    assert res_sih["is_multiclass"] is True
    assert res_sih["total_records"] == len(df_sih)
    assert res_sih["threat_count"] == 5142
    assert res_sih["normal_count"] == 857
    assert res_sih["accuracy_data"]["has_label"] is True
    assert res_sih["accuracy_data"]["accuracy_percentage"] >= 99.0
    print(f"  [PASS] SIH Dataset processed 5,999 records:")
    print(f"         - Threats Detected: {res_sih['threat_count']} ({res_sih['threat_rate']:.2f}%)")
    print(f"         - Normal Traffic:   {res_sih['normal_count']} ({res_sih['normal_rate']:.2f}%)")
    print(f"         - Ground-Truth Accuracy: {res_sih['accuracy_data']['accuracy_percentage']:.2f}%")
    print(f"         - Attack Breakdown: {list(res_sih['attack_breakdown'].keys())}")

    # 3. Test UNSW-NB15 Dataset (sample_network_traffic.csv)
    print("\n[TEST 3] Testing UNSW-NB15 Benchmark Dataset (sample_network_traffic.csv)...")
    unsw_test_path = Path("data/sample/sample_network_traffic.csv")
    df_unsw = pd.read_csv(unsw_test_path)

    engine_detected_unsw = detect_best_engine(df_unsw, sih_bundle, unsw_pipeline)
    assert engine_detected_unsw == "UNSW-NB15", f"Expected UNSW-NB15, got {engine_detected_unsw}"
    print(f"  [PASS] Smart Auto-Detect correctly identified engine as: {engine_detected_unsw}")

    res_unsw, err_unsw = run_universal_threat_inference(df_unsw, unsw_pipeline, sih_bundle, "Auto-Detect")
    assert err_unsw is None
    assert res_unsw["total_records"] == len(df_unsw)
    assert res_unsw["is_multiclass"] is False
    assert res_unsw["threat_count"] == 288
    print(f"  [PASS] UNSW Dataset processed {res_unsw['total_records']} records successfully.")

    # 4. Test CUSTOM USER DATASET with only 5 columns (Universal Adapter)
    print("\n[TEST 4] Testing Real User Custom Dataset (5 arbitrary columns: sport, dport, proto, pkts, bytes)...")
    df_custom = pd.DataFrame({
        "sport": [443, 80, 53, 21, 8080],
        "dport": [52134, 80, 53, 21, 3128],
        "proto": ["tcp", "tcp", "udp", "tcp", "udp"],
        "pkts": [1500, 20, 2, 50000, 100],
        "bytes": [2000000, 1500, 128, 60000000, 50000]
    })

    res_custom, err_custom = run_universal_threat_inference(df_custom, unsw_pipeline, sih_bundle, "Auto-Detect")
    assert err_custom is None, f"Custom inference failed: {err_custom}"
    assert res_custom is not None
    assert res_custom["total_records"] == 5
    assert not res_custom["adapter_info"]["is_native"]
    assert res_custom["adapter_info"]["mapped_count"] >= 5
    print(f"  [PASS] Universal Adapter adapted custom dataset seamlessly:")
    print(f"         - Mapped columns: {res_custom['adapter_info']['mapped_columns']}")
    print(f"         - Predictions generated for all {len(df_custom)} records without any missing feature errors!")
    for i in range(len(res_custom["result_df"])):
        row = res_custom["result_df"].iloc[i]
        print(f"           • Record {i+1}: {row['Attack Type']} ({row['Status']}) - Confidence: {row['Confidence (%)']}%")

    # 5. Test SIH inside ZIP archive
    print("\n[TEST 5] Testing SIH dataset extracted from ZIP buffer...")
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("sih_sample.csv", df_sih.head(50).to_csv(index=False))
    zip_buf.seek(0)
    with zipfile.ZipFile(zip_buf) as zf:
        df_from_zip = pd.read_csv(zf.open("sih_sample.csv"))
    res_zip, err_zip = run_universal_threat_inference(df_from_zip, unsw_pipeline, sih_bundle, "Auto-Detect")
    assert err_zip is None
    assert res_zip["total_records"] == 50
    print("  [PASS] SIH dataset inside ZIP processed with 100% success.")

    # 6. Test SIH exported to Excel (XLSX)
    print("\n[TEST 6] Testing SIH dataset in Excel (XLSX) format...")
    xlsx_buf = io.BytesIO()
    df_sih.head(40).to_excel(xlsx_buf, index=False, engine="openpyxl")
    xlsx_buf.seek(0)
    df_from_xlsx = load_dataset_from_file_or_buffer(xlsx_buf, "sih_traffic.xlsx")
    res_xlsx, err_xlsx = run_universal_threat_inference(df_from_xlsx, unsw_pipeline, sih_bundle, "Auto-Detect")
    assert err_xlsx is None
    assert res_xlsx["total_records"] == 40
    print("  [PASS] SIH Excel spreadsheet processed with 100% success.")

    print("\n" + "=" * 75)
    print("ALL 6 UNIVERSAL DUAL-ENGINE VERIFICATION TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 75)

if __name__ == "__main__":
    run_tests()
