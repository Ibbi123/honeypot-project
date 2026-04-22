import sqlite3
import pandas as pd


def load_logs(db_path: str = "honeypot.db") -> pd.DataFrame:
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM request_logs", conn)
    conn.close()
    return df


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    features = df.groupby("ip_address").agg(
        request_count=("id", "count"),
        unique_endpoints=("endpoint", "nunique"),
        get_requests=("method", lambda x: (x == "GET").sum()),
        post_requests=("method", lambda x: (x == "POST").sum()),
        query_request_count=("query_params", lambda x: x.fillna("").str.len().gt(0).sum()),
        body_request_count=("request_body", lambda x: x.fillna("").str.len().gt(0).sum()),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).reset_index()

    features["duration_seconds"] = (
        features["last_seen"] - features["first_seen"]
    ).dt.total_seconds()

    features["request_rate"] = features.apply(
        lambda row: row["request_count"] if row["duration_seconds"] == 0
        else row["request_count"] / row["duration_seconds"],
        axis=1
    )

    features["label"] = features.apply(
        lambda row: 1 if (
            row["request_count"] > 15 or
            row["unique_endpoints"] > 4 or
            row["request_rate"] > 0.01
        ) else 0,
        axis=1
    )

    return features


def main() -> None:
    df = load_logs()
    features = build_features(df)

    if features.empty:
        print("No data found.")
        return

    print(features)
    features.to_csv("features.csv", index=False)
    print("\nSaved features to features.csv")


if __name__ == "__main__":
    main()