"""
Clean SSH brute force attack data.

Loads raw JSON data, explodes password arrays, filters bad data,
adds derived columns, and saves to CSV.
"""

import json
import pandas as pd
from datetime import datetime

# Constants
INPUT_PATH = "data/raw_brute_force/brute_force_data.json"
OUTPUT_PATH = "data/BruteForce_Clean.csv"

DEFAULT_CREDENTIALS = {
    ("root", "root"),
    ("admin", "admin"),
    ("root", "password"),
    ("admin", "password"),
    ("root", "123456"),
    ("admin", "123456"),
    ("root", "1234"),
    ("admin", "admin123"),
}


def parse_timestamp(ts_str: str) -> datetime:
    """Parse timestamp string like 'Mon Nov  5 08:31:18 2018'."""
    return datetime.strptime(ts_str, "%a %b %d %H:%M:%S %Y")


def classify_password_type(password: str) -> str:
    """Categorize password by character composition."""
    if password.isdigit():
        return "numeric"
    elif password.isalpha():
        return "alpha"
    elif password.isalnum():
        return "alphanumeric"
    else:
        return "special"


def load_raw_data(path: str) -> list:
    """Load JSON data, handling BOM if present."""
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def explode_and_clean(raw_data: list) -> tuple[pd.DataFrame, dict]:
    """
    Explode password arrays and clean data.

    Returns cleaned DataFrame and stats dictionary.
    """
    stats = {
        "raw_records": len(raw_data),
        "total_password_tries": 0,
        "filtered_unicode_null": 0,
        "filtered_empty": 0,
        "filtered_null_after": 0,
        "duplicates_removed": 0,
    }

    rows = []
    for record in raw_data:
        username = record.get("username")
        src_ip = record.get("foreign_ip")
        timestamp = record.get("timestamp")

        for password in record.get("passwords", []):
            stats["total_password_tries"] += 1

            # Filter: unicode null characters
            if password and chr(0) in password:
                stats["filtered_unicode_null"] += 1
                continue

            # Filter: empty or whitespace-only
            if not password or password.strip() == "":
                stats["filtered_empty"] += 1
                continue

            rows.append({
                "username": username,
                "password": password,
                "src_ip": src_ip,
                "timestamp": timestamp,
            })

    df = pd.DataFrame(rows)

    # Filter: null/empty username or password after initial cleaning
    before_null_filter = len(df)
    df = df.dropna(subset=["username", "password"])
    df = df[df["password"].str.strip() != ""]
    stats["filtered_null_after"] = before_null_filter - len(df)

    # Drop duplicates (username + password + src_ip)
    before_dedup = len(df)
    df = df.drop_duplicates(subset=["username", "password", "src_ip"])
    stats["duplicates_removed"] = before_dedup - len(df)

    return df, stats


def add_derived_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Add derived columns for analysis."""
    # password_length
    df["password_length"] = df["password"].str.len()

    # is_numeric
    df["is_numeric"] = df["password"].str.isdigit()

    # is_default_credential
    df["is_default_credential"] = df.apply(
        lambda r: (r["username"], r["password"]) in DEFAULT_CREDENTIALS, axis=1
    )

    # password_type
    df["password_type"] = df["password"].apply(classify_password_type)

    # Parse timestamp to datetime
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], format="%a %b %d %H:%M:%S %Y"
    )

    return df


def main():
    print(f"Loading raw data from {INPUT_PATH}...")
    raw_data = load_raw_data(INPUT_PATH)

    print("Exploding and cleaning data...")
    df, stats = explode_and_clean(raw_data)

    print("Adding derived columns...")
    df = add_derived_columns(df)

    # Reorder columns for final output
    final_columns = [
        "username",
        "password",
        "src_ip",
        "timestamp",
        "password_length",
        "is_numeric",
        "is_default_credential",
        "password_type",
    ]
    df = df[final_columns]

    # Save to CSV
    df.to_csv(OUTPUT_PATH, index=False)

    # Print summary
    print("\n" + "=" * 60)
    print("CLEANING SUMMARY")
    print("=" * 60)
    print(f"\nRaw records (grouped by username): {stats['raw_records']:,}")
    print(f"Total password entries before filtering: {stats['total_password_tries']:,}")
    print(f"\nRows removed:")
    print(f"  - Unicode null characters (\\u0000): {stats['filtered_unicode_null']:,}")
    print(f"  - Empty/whitespace passwords: {stats['filtered_empty']:,}")
    print(f"  - Null/empty after initial filter: {stats['filtered_null_after']:,}")
    print(f"  - Duplicates removed: {stats['duplicates_removed']:,}")
    print(f"\nFinal cleaned rows: {len(df):,}")
    print(f"\nFinal column names:")
    for col in final_columns:
        print(f"  - {col}")
    print(f"\nSample rows (first 5):")
    print(df.head().to_string())
    print(f"\nOutput saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
