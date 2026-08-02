from pathlib import Path

path = Path("independent/p1registry/adapter.go")
source = path.read_text(encoding="utf-8")
old_struct = '''\tvar tagsValue struct {
\t\tTags []string `json:"tags"`
\t}
'''
new_struct = '''\tvar tagsValue struct {
\t\tName string   `json:"name"`
\t\tTags []string `json:"tags"`
\t}
'''
old_check = '''\tif err := strictDecode(tagsBody, &tagsValue); err != nil {
\t\treturn PortableResult{}, err
\t}
\tfound := false
'''
new_check = '''\tif err := strictDecode(tagsBody, &tagsValue); err != nil {
\t\treturn PortableResult{}, err
\t}
\tif tagsValue.Name != RegistryRepository {
\t\treturn PortableResult{}, errors.New("registry tag listing repository mismatch")
\t}
\tfound := false
'''
for old, new, label in (
    (old_struct, new_struct, "tag list type"),
    (old_check, new_check, "repository check"),
):
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"unexpected {label} patch cardinality: {count}")
    source = source.replace(old, new, 1)
path.write_text(source, encoding="utf-8")
Path(__file__).unlink()
