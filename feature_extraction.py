import pandas as pd


def load_logs(csv_path: str = "dataset/logs_final.csv") -> pd.DataFrame:
    return pd.read_csv(csv_path)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    df["query_params"] = df["query_params"].fillna("")
    df["request_body"] = df["request_body"].fillna("")
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    features = df.groupby("ip_address").agg(
        request_count=("ip_address", "count"),
        unique_endpoints=("endpoint", "nunique"),
        get_requests=("method", lambda x: (x == "GET").sum()),
        post_requests=("method", lambda x: (x == "POST").sum()),
        query_request_count=("query_params", lambda x: x.str.len().gt(0).sum()),
        body_request_count=("request_body", lambda x: x.str.len().gt(0).sum()),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
    ).reset_index()

    features["duration_seconds"] = (
        features["last_seen"] - features["first_seen"]
    ).dt.total_seconds()

    features["request_rate"] = (
        features["request_count"] / features["duration_seconds"].replace(0, 1)
    )

    features["label"] = features.apply(
        lambda row: 1 if (
            row["request_count"] > 15 or
            row["unique_endpoints"] > 6 or
            row["request_rate"] > 1.5 or
            (row["post_requests"] > 10 and row["body_request_count"] > 5)
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

    print("Feature rows:", len(features))
    print("\nLabel distribution:")
    print(features["label"].value_counts())

    features.to_csv("features.csv", index=False)
    print("\nSaved features to features.csv")


if __name__ == "__main__":
    main()
