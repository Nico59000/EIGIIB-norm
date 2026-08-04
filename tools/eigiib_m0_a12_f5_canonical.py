import hashlib,json

def canonical_bytes(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
def digest_document(value): return hashlib.sha256(canonical_bytes(value)).hexdigest()
