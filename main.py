
def to_bytes(p):
    if p[:2] == '0x':
        p = p[2:]
    res = []
    for i in range(0, 64, 64//4):
        res.append('0x' + p[i:i+64//4])
    return str(res[::-1]).replace('\'', '')