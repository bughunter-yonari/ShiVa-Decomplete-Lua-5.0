import struct

class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0
    def bytes(self, n):
        b = self.data[self.pos:self.pos+n]; self.pos += n; return b
    def byte(self):
        b = self.data[self.pos]; self.pos += 1; return b
    def int32(self):
        v = struct.unpack_from('<i', self.data, self.pos)[0]; self.pos += 4; return v
    def uint32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def double(self):
        v = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8; return v
    def lstring(self):
        size = self.int32()
        if size == 0: return None
        raw = self.bytes(size)
        return raw[:-1].decode('latin1')

LUA_TNIL=0; LUA_TBOOL=1; LUA_TNUMBER=3; LUA_TSTRING=4

OPNAMES = [
 "MOVE","LOADK","LOADBOOL","LOADNIL","GETUPVAL","GETGLOBAL","GETTABLE","SETGLOBAL",
 "SETUPVAL","SETTABLE","NEWTABLE","SELF","ADD","SUB","MUL","DIV","POW","UNM","LEN",
 "CONCAT","JMP","EQ","LT","LE","TEST","CALL","TAILCALL","RETURN","FORLOOP",
 "TFORLOOP","TFORPREP","SETLIST","SETLISTO","CLOSE","CLOSURE"
]

def decode_instr(instr):
    op = instr & 0x3F
    a = (instr >> 24) & 0xFF
    mid18 = (instr >> 6) & 0x3FFFF
    c = mid18 & 0x1FF
    b = (mid18 >> 9) & 0x1FF
    bx = mid18
    sbx = bx - 131071
    return op, a, b, c, bx, sbx

RK_OFFSET = 250
def rk(val, consts, regfn):
    if val >= RK_OFFSET:
        idx = val - RK_OFFSET
        if 0 <= idx < len(consts):
            return luastr(consts[idx])
        return f"K[{idx}]"
    return regfn(val)


def parse_proto(r: Reader, parent_source=None):
    source = r.lstring() or parent_source
    line_defined = r.int32()
    nups = r.byte(); numparams = r.byte(); is_vararg = r.byte(); maxstack = r.byte()
    sizelineinfo = r.int32(); lineinfo = [r.int32() for _ in range(sizelineinfo)]
    sizelocvars = r.int32()
    locvars = []
    for i in range(sizelocvars):
        vn = r.lstring(); sp = r.int32(); ep = r.int32()
        locvars.append((vn, sp, ep))
    sizeupvalues = r.int32()
    upvalnames = [r.lstring() for _ in range(sizeupvalues)]
    sizek = r.int32()
    consts = []
    for i in range(sizek):
        t = r.byte()
        if t == LUA_TNIL: consts.append(None)
        elif t == LUA_TBOOL: consts.append(bool(r.byte()))
        elif t == LUA_TNUMBER: consts.append(r.double())
        elif t == LUA_TSTRING: consts.append(r.lstring())
        else: raise ValueError(f"bad const type {t}")
    sizep = r.int32()
    protos = [parse_proto(r, source) for _ in range(sizep)]
    sizecode = r.int32()
    code = [r.uint32() for _ in range(sizecode)]
    return dict(source=source, line_defined=line_defined, nups=nups, numparams=numparams,
                is_vararg=is_vararg, maxstack=maxstack, locvars=locvars, upvalnames=upvalnames,
                consts=consts, protos=protos, code=code)


def luastr(v):
    if isinstance(v, str):
        esc = v.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n')
        return f'"{esc}"'
    if v is None:
        return "nil"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        if v == int(v) and abs(v) < 1e15:
            return str(int(v))
        return repr(v)
    return str(v)


def decompile_proto(proto, depth=0, funcname="anonymous"):
    out = []
    ind = "  " * depth
    consts = proto['consts']
    code = proto['code']
    params = [f"p{i}" for i in range(proto['numparams'])]
    if proto['is_vararg']:
        params.append('...')
    out.append(f"{ind}function {funcname}({', '.join(params)})")

    reg = {}   # register index -> symbolic string expr
    for i in range(proto['numparams']):
        reg[i] = f"p{i}"

    def rd(r_idx):
        return reg.get(r_idx, f"r{r_idx}")

    proto_counter = [0]
    i = 0
    n = len(code)
    while i < n:
        instr = code[i]
        op, a, b, c, bx, sbx = decode_instr(instr)
        name = OPNAMES[op] if op < len(OPNAMES) else f"OP{op}"

        if name == "MOVE":
            reg[a] = rd(b)
        elif name == "LOADK":
            reg[a] = luastr(consts[bx]) if 0 <= bx < len(consts) else f"K[{bx}]"
        elif name == "LOADBOOL":
            reg[a] = "true" if b else "false"
        elif name == "LOADNIL":
            for rr in range(a, b+1):
                reg[rr] = "nil"
        elif name == "GETGLOBAL":
            reg[a] = consts[bx] if 0 <= bx < len(consts) else f"G[{bx}]"
        elif name == "SETGLOBAL":
            out.append(f"{ind}  {consts[bx] if 0<=bx<len(consts) else '?'} = {rd(a)}")
        elif name == "GETUPVAL":
            uv = proto['upvalnames']
            reg[a] = uv[b] if b < len(uv) else f"upval{b}"
        elif name == "SETUPVAL":
            uv = proto['upvalnames']
            out.append(f"{ind}  {uv[b] if b<len(uv) else f'upval{b}'} = {rd(a)}")
        elif name == "GETTABLE":
            reg[a] = f"{rd(b)}[{rk(c, consts, rd)}]"
        elif name == "SETTABLE":
            out.append(f"{ind}  {rd(a)}[{rk(b, consts, rd)}] = {rk(c, consts, rd)}")
        elif name == "NEWTABLE":
            reg[a] = "{}"
        elif name == "SELF":
            reg[a+1] = rd(b)
            reg[a] = f"{rd(b)}:{rk(c, consts, rd)}"
        elif name in ("ADD","SUB","MUL","DIV","POW"):
            sym = {"ADD":"+","SUB":"-","MUL":"*","DIV":"/","POW":"^"}[name]
            reg[a] = f"({rk(b, consts, rd)} {sym} {rk(c, consts, rd)})"
        elif name == "UNM":
            reg[a] = f"(-{rd(b)})"
        elif name == "LEN":
            reg[a] = f"(#{rd(b)})"
        elif name == "CONCAT":
            parts = [rd(x) for x in range(b, c+1)]
            reg[a] = "(" + " .. ".join(parts) + ")"
        elif name == "JMP":
            out.append(f"{ind}  goto L{i+1+sbx}")
        elif name in ("EQ","LT","LE"):
            sym = {"EQ":"==","LT":"<","LE":"<="}[name]
            cond = f"{rk(b, consts, rd)} {sym} {rk(c, consts, rd)}"
            if a == 0:
                out.append(f"{ind}  if not ({cond}) then goto L{i+2} end")
            else:
                out.append(f"{ind}  if ({cond}) then goto L{i+2} end")
        elif name == "TEST":
            out.append(f"{ind}  if not {rd(a)} then goto L{i+2} end")
        elif name in ("CALL","TAILCALL"):
            nargs = b-1
            args = [rd(a+1+k) for k in range(nargs)] if b>0 else [f"...args_from_{rd(a+1)}"]
            call = f"{rd(a)}({', '.join(args)})"
            if c == 1:
                out.append(f"{ind}  {call}")
            else:
                reg[a] = call
                if name == "TAILCALL":
                    out.append(f"{ind}  return {call}")
        elif name == "RETURN":
            if b == 1:
                out.append(f"{ind}  return")
            elif b == 0:
                out.append(f"{ind}  return {rd(a)}, ...")
            else:
                vals = [rd(a+k) for k in range(b-1)]
                out.append(f"{ind}  return {', '.join(vals)}")
        elif name == "FORLOOP":
            out.append(f"{ind}  -- forloop step, goto L{i+1+sbx} if continue")
        elif name in ("TFORLOOP","TFORPREP"):
            out.append(f"{ind}  -- {name} A={a} B={b} C={c} sBx={sbx}")
        elif name in ("SETLIST","SETLISTO"):
            out.append(f"{ind}  -- {name} on {rd(a)} (bulk array set)")
        elif name == "CLOSE":
            pass
        elif name == "CLOSURE":
            pidx = bx
            if pidx < len(proto['protos']):
                sub = decompile_proto(proto['protos'][pidx], depth+1, "")
                header = sub[0]
                header = header.replace("function  (", "function(").replace("function ()","function()")
                out.append(f"{ind}  r{a} = " + header.strip())
                out.extend(sub[1:])
            reg[a] = f"r{a}"
        else:
            out.append(f"{ind}  -- ??? {name} A={a} B={b} C={c} Bx={bx}")
        i += 1

    out.append(f"{ind}end")
    return out


def decompile(path):
    data = open(path, 'rb').read()
    r = Reader(data)
    sig = r.bytes(4); assert sig == b'\x1bLua'
    r.byte()  # version
    r.pos += 17  # rest of 22-byte header
    proto = parse_proto(r, None)
    lines = decompile_proto(proto, 0, "main")
    return "\n".join(lines)

if __name__ == '__main__':
    import sys
    print(decompile(sys.argv[1]))
