import sys, json, time, urllib.request, urllib.error
def cap(method, url, headers=None, data=None):
    headers = headers or {}
    if isinstance(data, str): data = data.encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=15)
        body = r.read(); status = r.status; hdrs = dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read(); status = e.code; hdrs = dict(e.headers)
    dt = round((time.time()-t0)*1000, 1)
    body_txt = body.decode('utf-8','replace')
    return {
        "status_code": status,
        "response_time_ms": dt,
        "response_size_bytes": len(body),
        "headers": {k: v for k,v in hdrs.items()},
        "content_type": hdrs.get("Content-Type"),
        "body_excerpt": body_txt[:600],
        "body_len_chars": len(body_txt),
    }
if __name__ == "__main__":
    spec = json.load(open(sys.argv[1]))
    print(json.dumps(cap(spec["method"], spec["url"], spec.get("headers"), spec.get("data")), indent=2))
