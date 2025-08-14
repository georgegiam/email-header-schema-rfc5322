import sys
import csv
import json
import email
import pandas as pd
import time
from email import policy
from email.parser import Parser
from jsonschema import validate, ValidationError
from concurrent.futures import ProcessPoolExecutor

# Allow large headers in CSV
csv.field_size_limit(sys.maxsize)

def extract_header_from_message(full_message):
    return full_message.split("\n\n", 1)[0].strip()

def parse_headers(header_text):
    msg = Parser(policy=policy.default).parsestr(header_text)
    parsed = {}
    x_headers = {}

    standard_keys = {
        "from", "to", "cc", "bcc", "reply-to", "subject", "date", "message-id",
        "in-reply-to", "references", "mime-version", "content-type",
        "content-transfer-encoding", "received"
    }

    for key in msg.keys():
        values = msg.get_all(key)
        if not values:
            continue
        key_lower = key.lower()
        val = values if len(values) > 1 else values[0]

        if key_lower in standard_keys:
            parsed[key_lower] = val
        else:
            x_headers[key_lower] = val

    if x_headers:
        parsed["x_headers"] = {
            k: str(v) if not isinstance(v, list) else "\n".join(v)
            for k, v in x_headers.items()
        }

    if "from" in parsed:
        name, addr = email.utils.parseaddr(parsed["from"])
        parsed["from"] = {"name": name, "email": addr}

    if "to" in parsed:
        addrs = email.utils.getaddresses(
            [parsed["to"]] if isinstance(parsed["to"], str) else parsed["to"]
        )
        parsed["to"] = [{"name": n, "email": e} for n, e in addrs]

    if "cc" in parsed:
        addrs = email.utils.getaddresses(
            [parsed["cc"]] if isinstance(parsed["cc"], str) else parsed["cc"]
        )
        parsed["cc"] = [{"name": n, "email": e} for n, e in addrs]

    if "bcc" in parsed:
        addrs = email.utils.getaddresses(
            [parsed["bcc"]] if isinstance(parsed["bcc"], str) else parsed["bcc"]
        )
        parsed["bcc"] = [{"name": n, "email": e} for n, e in addrs]

    if "reply-to" in parsed:
        addrs = email.utils.getaddresses(
            [parsed["reply-to"]] if isinstance(parsed["reply-to"], str) else parsed["reply-to"]
        )
        parsed["reply-to"] = [{"name": n, "email": e} for n, e in addrs]

    if "date" in parsed:
        try:
            dt = email.utils.parsedate_to_datetime(parsed["date"])
            parsed["date"] = dt.isoformat()
        except Exception:
            pass

    return parsed

def process_row(args):
    i, row, schema = args
    try:
        raw_email = row["message"]
        raw_header = extract_header_from_message(raw_email)
        parsed = parse_headers(raw_header)
        validate(instance=parsed, schema=schema)
        return {
            "index": i + 1,
            "valid": True,
            "parsed": parsed
        }
    except ValidationError as e:
        return {
            "index": i + 1,
            "valid": False,
            "error": str(e)
        }
    except Exception as e:
        return {
            "index": i + 1,
            "valid": False,
            "error": f"Other error: {str(e)}"
        }

def parse_and_validate_headers(csv_path, schema_path, max_workers=None):
    with open(schema_path, "r") as f:
        schema = json.load(f)

    df = pd.read_csv(csv_path).head(5)
    # df = pd.read_csv(csv_path)

    tasks = [(i, row, schema) for i, row in df.iterrows()]

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(process_row, tasks))

    with open("parser_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    return results

if __name__ == "__main__":
    start_time = time.time()

    csv_file = "emails.csv"
    schema_file = "schema.json"
    parse_and_validate_headers(csv_file, schema_file)

    elapsed = time.time() - start_time
    print(f"Total time: {elapsed:.2f} seconds")
