"""Robust NSL-KDD reader: handles files with NO header, tab or comma separators,
and files where every line is wrapped in quotes (the cause of the '0 features' error)."""
import csv
import io

import pandas as pd

KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
LABEL_NAMES = ("labels", "label", "class", "attack", "attack_type")


def _is_num(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


def read_kdd(path, nrows=None):
    with open(path, encoding="utf-8", errors="ignore") as fh:
        lines = []
        for l in fh:
            l = l.strip().strip('"').strip("'")
            if l:
                lines.append(l)
            if nrows and len(lines) > nrows + 1:
                break
    if not lines:
        raise ValueError("the file is empty")
    d = "\t" if lines[0].count("\t") > lines[0].count(",") else ","
    first = lines[0].split(d)
    header = not _is_num(first[0])
    df = pd.read_csv(io.StringIO("\n".join(lines)), sep=d, header=0 if header else None,
                     quoting=csv.QUOTE_NONE, low_memory=False)
    if header:
        df.columns = [str(c).strip().strip('"') for c in df.columns]
    else:
        n = df.shape[1]
        if n == 43:
            df.columns = KDD_COLUMNS + ["labels", "difficulty"]
        elif n == 42:
            df.columns = KDD_COLUMNS + ["labels"]
        else:
            raise ValueError(f"expected 41 features + label (42 or 43 columns) but found {n} columns")
    for c in df.columns:
        if not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = df[c].astype(str).str.strip().str.strip('"')
    return df.head(nrows) if nrows else df


def label_column(df):
    for c in LABEL_NAMES:
        if c in df.columns:
            return c
    return df.columns[-1]
