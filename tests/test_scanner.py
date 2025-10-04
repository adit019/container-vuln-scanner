from scanner.dockerfile_parser import check
def test_copy_vs_add(tmp_path):
    d = tmp_path/'Dockerfile'; d.write_text('ADD src /app\n', encoding='utf-8'); assert check(d)==1
def test_clean(tmp_path):
    d = tmp_path/'Dockerfile'; d.write_text('FROM alpine:3.20\nCOPY . /app\nUSER app\n', encoding='utf-8'); assert check(d) in (0,1)
