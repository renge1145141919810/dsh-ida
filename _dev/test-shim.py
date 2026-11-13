#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
用假 IDA 模块验证 _dev/ida-compat.py。

关键点：假模块**故意复现老 SDK 的残缺**——
  · 没有 ida_typeinf.PT_EMPTY
  · 没有 ida_typeinf.get_ordinal_limit（只有 get_ordinal_qty）
  · tinfo_t(decl, til, flags) 直接抛 TypeError
  · tinfo_t 没有 get_type_by_tid、没有 get_udm_by_tid
  · ida_nalt.get_tinfo 一律返回 False（用户遇到的「按地址取不到」）
  · get_type_by_name 的最后一步在旧 SDK 会抛异常

这些都和用户那份 IDA 的表现一致。补丁能过，才有资格拿去真机试。

    python _dev/test-shim.py
"""
import io
import os
import functools
import re
import sys
import types
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "ida-compat.py")

OK = []
BAD = []


def check(name, cond, detail=None):
    if cond:
        OK.append(name)
    else:
        BAD.append((name, detail))


class IDAError(Exception):
    pass


def parse_address(text):
    s = str(text).strip()
    neg = s.startswith("-")
    if neg:
        s = s[1:]
    value = int(s, 16) if s.lower().startswith("0x") else int(s, 16)
    return -value if neg else value


# ---------------------------------------------------------------- 假类型系统
class Udm:
    def __init__(self, name, offset_bits, size_bits, type_):
        self.name = name
        self.offset = offset_bits
        self.size = size_bits
        self.type = type_

    def is_gap(self):
        return not self.name


class udt_type_data_t:
    def __init__(self):
        self._members = []

    def __iter__(self):
        return iter(self._members)

    def size(self):
        return len(self._members)


TYPES = {
    1: {"kind": "udt", "name": "cfg_header", "size": 0x20},
    2: {"kind": "typedef", "name": "foo_t", "size": 4},
    3: None,
    4: {"kind": "udt", "name": "packet", "size": 0x10},
}


class tinfo_t(object):
    def __init__(self, *args):
        self._empty = True
        self._kind = None
        self._size = 0
        self._name = None
        self._members = []
        self._text = None
        if len(args) == 1 and isinstance(args[0], int):
            self._empty = False
            self._kind = "int"
            self._size = 4
        elif len(args) >= 2:
            # 老 SDK 的真实表现：这个构造函数不存在
            raise TypeError("tinfo_t(decl, til, flags) is not supported by this IDA")

    def empty(self):
        return self._empty

    def is_func(self):
        return self._kind == "func"

    def is_udt(self):
        return self._kind == "udt"

    def is_array(self):
        return self._kind == "array"

    def is_union(self):
        return False

    def get_array_element(self):
        return tinfo_t(1)

    def get_size(self):
        return self._size

    def get_type_name(self):
        return self._name

    def get_udt_details(self, udt):
        if self._kind != "udt":
            return False
        udt._members = list(self._members)
        return True

    def get_numbered_type(self, til, ordinal):
        entry = TYPES.get(ordinal)
        if not entry:
            return False
        self._empty = False
        self._kind = entry["kind"]
        self._size = entry.get("size", 0)
        self._name = entry.get("name")
        self._members = [Udm("magic", 0, 32, tinfo_t(1)), Udm("ver", 32, 16, tinfo_t(1))]
        return True

    def _print(self, til=None, flags=0):
        if self._kind == "udt":
            return "struct %s" % self._name
        if self._kind == "func":
            return self._text or "int f()"
        return self._text or "int"


BUILTIN = {
    "int", "char", "short", "long", "float", "double", "signed", "unsigned",
    "void", "struct", "union", "enum", "const", "size_t", "bool",
}
KNOWN_TYPES = {"cfg_header", "packet", "foo_t"}


def parse_decl(tif, til, decl, flags=0):
    text = str(decl).strip()
    if not text.endswith(";"):
        return False
    body = text[:-1].strip()
    if not body:
        return False
    # 真 IDA 的 C 解析器不认这三种东西，假解析器也得认账
    if re.search(r"\b_(BYTE|WORD|DWORD|QWORD|OWORD)\b", body):
        return False
    if "(" in body:
        head = body[: body.index("(")].strip()
        match = re.search(r"([A-Za-z_]\w*)$", head)
        if not match or match.group(1) in BUILTIN:
            return False
        if match.group(1) in ("__cdecl", "__stdcall", "__fastcall", "__thiscall"):
            return False
        tif._empty = False
        tif._kind = "func"
        tif._size = -1
        tif._text = body + ";"
        return True
    match = re.match(r"^(.*?\S)\s+([A-Za-z_]\w*)(\[[^\]]*\])?$", body)
    if not match:
        return False
    base = match.group(1).strip()
    head_word = base.split()[0]
    if head_word not in BUILTIN and base not in KNOWN_TYPES:
        return False
    size = 4
    if match.group(3):
        try:
            size = int(match.group(3)[1:-1])
        except ValueError:
            size = 1
    tif._empty = False
    tif._kind = "array" if match.group(3) else "var"
    tif._size = size
    tif._text = body + ";"
    return True


def make_module(name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


ida_typeinf = make_module(
    "ida_typeinf",
    tinfo_t=tinfo_t,
    udt_type_data_t=udt_type_data_t,
    parse_decl=parse_decl,
    get_idati=lambda: object(),
    get_ordinal_qty=lambda til=None: 5,
    apply_tinfo=lambda ea, tif, flags=0: (not tif.empty()),
    PT_SIL=0x0001,
    PT_TYP=0x0002,
    PRTYPE_1LINE=0x10,
    PRTYPE_TYPE=0x20,
    PRTYPE_SEMI=0x40,
    PRTYPE_MULTI=0x80,
    PRTYPE_DEF=0x100,
    PRTYPE_METHODS=0x200,
    PRTYPE_OFFSETS=0x400,
)

FUNCS = {0x401010: 0x401000, 0x401020: 0x402000}
NAMES = {0x403028: "byte_403028", 0x403018: "g_state_x"}


def _get_func(ea):
    start = FUNCS.get(ea)
    if start is None:
        if ea == 0x401000:
            start = 0x401000
        else:
            return None
    return types.SimpleNamespace(start_ea=start, end_ea=start + 0x100, frame=0x10)


def _get_name_ea(bad, name):
    for ea, value in NAMES.items():
        if value == name:
            return ea
    return bad


idaapi = make_module(
    "idaapi",
    BADADDR=0xFFFFFFFFFFFFFFFF,
    get_func=_get_func,
    get_name_ea=_get_name_ea,
    set_name=lambda ea, name: NAMES.__setitem__(ea, name) is None,
    get_strlit_contents=lambda ea, length, flags: b"hello",
)

MEM = {0x403018: b"\x01\x00\x00\x00", 0x40301C: b"\x4d\x5a\x90\x00"}


def _item_head(ea):
    for base in MEM:
        if base <= ea < base + len(MEM[base]):
            return base
    return ea


def _get_bytes(ea, size):
    base = _item_head(ea)
    data = MEM.get(base, b"")
    offset = ea - base
    return (data + b"\x00" * size)[offset: offset + size]


ida_bytes = make_module(
    "ida_bytes",
    is_loaded=lambda ea: True,
    get_item_head=_item_head,
    get_item_size=lambda ea: len(MEM.get(_item_head(ea), b"")) or 1,
    get_bytes=_get_bytes,
    get_byte=lambda ea: _get_bytes(ea, 1)[0],
    get_word=lambda ea: int.from_bytes(_get_bytes(ea, 2), "little"),
    get_dword=lambda ea: int.from_bytes(_get_bytes(ea, 4), "little"),
    get_qword=lambda ea: int.from_bytes(_get_bytes(ea, 8), "little"),
)

ida_nalt = make_module(
    "ida_nalt",
    # 用户遇到的原症状：0x403018 在这里就失败
    get_tinfo=lambda tif, ea: False,
)

XREFS = {0x403028: [0x401010, 0x401020, 0x401020]}


class _Xref(object):
    def __init__(self, frm):
        self.frm = frm


idautils = make_module(
    "idautils",
    XrefsTo=lambda ea: [_Xref(frm) for frm in XREFS.get(ea, [])],
    Functions=lambda: [0x401000, 0x402000],
)

DIRTY = []
ida_hexrays = make_module(
    "ida_hexrays",
    mark_cfunc_dirty=lambda ea, close=False: DIRTY.append(ea),
)

FRAME_MEMBERS = [
    Udm("var_8", -64, 32, tinfo_t(1)),
    Udm("arg_0", -32, 32, tinfo_t(1)),
]
STKVARS = []


def _get_func_frame(a, b=None):
    if b is None:
        out = tinfo_t()
        out._empty = False
        out._kind = "udt"
        out._name = "frame"
        out._members = FRAME_MEMBERS
        return out
    a._empty = False
    a._kind = "udt"
    a._name = "frame"
    a._members = FRAME_MEMBERS
    return True


ida_frame = make_module(
    "ida_frame",
    get_func_frame=_get_func_frame,
    is_funcarg_off=lambda func, offset: False,
    soff_to_fpoff=lambda func, offset: offset,
    define_stkvar=lambda func, name, sval, tif: STKVARS.append((name, sval)) is None,
    set_frame_member_type=lambda func, offset, tif: True,
    delete_frame_members=lambda func, start, end: True,
)

idc = make_module("idc", get_item_head=_item_head)


# ---------------------------------------------------------------- 宿主环境
REFRESH = []


def refresh_decompiler_ctext(address):
    REFRESH.append(address)


def get_type_by_name(type_name):
    """原版最后一步是 tinfo_t(type_name)，旧 SDK 抛 TypeError。"""
    if type_name in ("unsigned int", "int", "unsigned char", "char", "DWORD", "byte"):
        return tinfo_t(1)
    raise TypeError("tinfo_t(str) is not supported by this IDA")


def parse_decls_ctypes(decls, flags):
    if "{" in decls and "}" in decls:
        return 0, ["declared"]
    return 1, ["expected ';'"]


def idawrite(f):
    @functools.wraps(f)
    def wrapper(*a, **k):
        return f(*a, **k)
    wrapper._dsh_sync = "write"
    return wrapper


def idaread(f):
    @functools.wraps(f)
    def wrapper(*a, **k):
        return f(*a, **k)
    wrapper._dsh_sync = "read"
    return wrapper


RPCS = [
    "list_local_types", "declare_c_type", "set_function_prototype",
    "get_defined_structures", "search_structures",
    "get_global_variable_value_by_name", "get_global_variable_value_at_address",
    "rename_global_variable", "set_global_variable_type",
    "get_stack_frame_variables", "rename_stack_frame_variable",
    "set_stack_frame_variable_type", "delete_stack_frame_variable",
    "create_stack_frame_variable",
]


class Registry(object):
    def __init__(self):
        self.dummies = {name: (lambda *a, **k: None) for name in RPCS}
        self.methods = dict(self.dummies)
        self.unsafe = set()


rpc_registry = Registry()


def get_global_variable_value_internal(ea):
    raise NotImplementedError  # 会被补丁覆盖


NS = {
    "__name__": "mcp_plugin",
    "ida_typeinf": ida_typeinf,
    "idaapi": idaapi,
    "ida_bytes": ida_bytes,
    "ida_nalt": ida_nalt,
    "idautils": idautils,
    "ida_hexrays": ida_hexrays,
    "ida_frame": ida_frame,
    "idc": idc,
    "IDAError": IDAError,
    "parse_address": parse_address,
    "refresh_decompiler_ctext": refresh_decompiler_ctext,
    "get_type_by_name": get_type_by_name,
    "parse_decls_ctypes": parse_decls_ctypes,
    "rpc_registry": rpc_registry,
    "idawrite": idawrite,
    "idaread": idaread,
    "ida_major": 8,
    "ida_minor": 3,
    "get_global_variable_value_internal": get_global_variable_value_internal,
    "get_stack_frame_variables_internal": lambda ea, raise_error: [],
}

# 上游的三个包装方法用 exec 注入 NS，保证它们内部的名称解析也落在 NS 里
# （直接用本文件的函数会让 __globals__ 指向测试模块，测不到补丁后的实现）
WRAPPERS = """
def get_global_variable_value_by_name(variable_name):
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    if ea == idaapi.BADADDR:
        raise IDAError("Global variable %s not found" % variable_name)
    return get_global_variable_value_internal(ea)

def get_global_variable_value_at_address(address):
    return get_global_variable_value_internal(parse_address(address))

def get_stack_frame_variables(function_address):
    return get_stack_frame_variables_internal(parse_address(function_address), True)
"""
exec(compile(WRAPPERS, "<wrappers>", "exec"), NS)
for _name in ("get_global_variable_value_by_name", "get_global_variable_value_at_address", "get_stack_frame_variables"):
    NS[_name] = NS[_name]

source = io.open(SRC, encoding="utf-8").read()
try:
    exec(compile(source, SRC, "exec"), NS)
except Exception:
    traceback.print_exc()
    print("\n兼容层本身在 exec 阶段就崩了，不用往下测了。")
    sys.exit(1)


def call(name, *args):
    return NS[name](*args)


# ---------------------------------------------------------------- 断言
# 1. declare_c_type：PT_EMPTY 不存在也要能声明类型
try:
    message = call("declare_c_type", "struct cfg { int a; };")
    check("declare_c_type 在缺 PT_EMPTY 时可用", "success" in message, message)
    check("回执写明用了哪套标志", "PT_SIL|PT_TYP" in message and "PT_EMPTY" not in message, message)
except Exception as exc:
    check("declare_c_type 在缺 PT_EMPTY 时可用", False, exc)

try:
    call("declare_c_type", "this is not C")
    check("非法声明要报错", False, "没有抛异常")
except IDAError as exc:
    check("非法声明要报错", "Failed to parse type" in str(exc), exc)
except Exception as exc:
    check("非法声明要报错", False, "抛了非 IDAError：%r" % exc)

# 2. 结构体列表：get_ordinal_limit 缺失时靠 get_ordinal_qty
try:
    structures = call("get_defined_structures")
    names = [item["name"] for item in structures]
    check("get_defined_structures 不再依赖 get_ordinal_limit", names == ["cfg_header", "packet"], names)
    check("结构体带成员", structures[0]["members"][0]["name"] == "magic", structures[0])
    check("成员偏移按字节", structures[0]["members"][1]["offset"] == "0x4", structures[0]["members"][1])
except Exception as exc:
    check("get_defined_structures 不再依赖 get_ordinal_limit", False, exc)

try:
    found = call("search_structures", "cfg")
    check("search_structures 可按名字过滤", [item["name"] for item in found] == ["cfg_header"], found)
except Exception as exc:
    check("search_structures 可按名字过滤", False, exc)

try:
    rows = call("list_local_types")
    check("list_local_types 能列类型", any("cfg_header" in row for row in rows), rows[:3])
except Exception as exc:
    check("list_local_types 能列类型", False, exc)

# 3. 函数原型：构造器不可用时走 parse_decl
try:
    result = call("set_function_prototype", "0x401000", "int __cdecl f(_BYTE *s)")
    check("原型可设置（_BYTE 被换成标准类型）",
          result.get("ok") is True and "unsigned char" in result.get("applied", "")
          and result.get("attempts") == 2, result)
except Exception as exc:
    check("原型可设置（_BYTE 被换成标准类型）", False, exc)

try:
    result = call("set_function_prototype", "0x401000", "int __cdecl (char *s)")
    check("没有函数名时自动补占位名",
          result.get("ok") is True and "__dsh_fn" in result.get("applied", "")
          and result.get("attempts") == 2, result)
except Exception as exc:
    check("没有函数名时自动补占位名", False, exc)

try:
    call("set_function_prototype", "0x401000", "totally broken")
    check("原型失败时给出可操作提示", False, "没有抛异常")
except IDAError as exc:
    text = str(exc)
    check("原型失败时给出可操作提示",
          "Failed to parse prototype string" in text and "可用写法" in text, text)
except Exception as exc:
    check("原型失败时给出可操作提示", False, "抛了非 IDAError：%r" % exc)

# 4. 全局改名后按 xref 刷新伪代码
REFRESH[:] = []
DIRTY[:] = []
try:
    result = call("rename_global_variable", "byte_403028", "g_pw_blob")
    check("改名后刷新引用它的函数（去重后 2 个）",
          result.get("refreshed_functions") == 2, result)
    check("刷新的是函数起始地址而不是数据地址",
          sorted(REFRESH) == [0x401000, 0x402000], REFRESH)
    check("先标脏再刷新",
          sorted(DIRTY) == [0x401000, 0x402000], DIRTY)
except Exception as exc:
    check("改名后刷新引用它的函数（去重后 2 个）", False, exc)

try:
    call("rename_global_variable", "not_exists", "x")
    check("改名不存在的符号要报错", False, "没有抛异常")
except IDAError as exc:
    check("改名不存在的符号要报错", "not found" in str(exc), exc)

# 5. 全局取值：按地址也要能读
try:
    value = call("get_global_variable_value_at_address", "0x403018")
    check("按地址取全局值", value == "0x1", value)
except Exception as exc:
    check("按地址取全局值", False, exc)

try:
    value = call("get_global_variable_value_by_name", "g_state_x")
    check("按名字取全局值", value == "0x1", value)
except Exception as exc:
    check("按名字取全局值", False, exc)

# 6. 栈帧层：没有 get_type_by_tid / get_udm_by_tid 也要能用
try:
    members = NS["get_stack_frame_variables_internal"](0x401000, True)
    names = [item["name"] for item in members]
    check("栈帧变量能列出来", names == ["var_8", "arg_0"], names)
except Exception as exc:
    check("栈帧变量能列出来", False, exc)

try:
    result = call("rename_stack_frame_variable", "0x401000", "var_8", "buf_len")
    check("栈变量改名不再走 get_udm_by_tid", result.get("ok") is True and ("buf_len", -8) in STKVARS, result)
except Exception as exc:
    check("栈变量改名不再走 get_udm_by_tid", False, exc)

try:
    result = call("set_global_variable_type", "g_state_x", "unsigned int")
    check("全局改类型能解析类型串", result.get("ok") is True, result)
except Exception as exc:
    check("全局改类型能解析类型串", False, exc)

# 7. 重新绑定：参数注解必须和 dispatch 的期望一致
REWRITTEN = [name for name in RPCS if name not in (
    "get_global_variable_value_by_name",
    "get_global_variable_value_at_address",
    "get_stack_frame_variables",
)]

try:
    from typing import get_type_hints
    rebound = [name for name in REWRITTEN if rpc_registry.methods[name] is not rpc_registry.dummies[name]]
    check("11 个重写方法全部重新绑定", len(rebound) == len(REWRITTEN),
          sorted(set(REWRITTEN) - set(rebound)))
    undecorated = [name for name in REWRITTEN if not hasattr(rpc_registry.methods[name], "__wrapped__")]
    check("绑定后重新套上了线程调度装饰器（少了会坏库）", undecorated == [], undecorated)
    signature = get_type_hints(rpc_registry.methods["set_function_prototype"])
    check("绑定后的注解是 dispatch 能用的 str",
          signature == {"function_address": str, "prototype": str}, signature)
    empty = get_type_hints(rpc_registry.methods["get_defined_structures"])
    check("零参数方法注解为空", empty == {}, empty)
    writes = sorted(name for name in REWRITTEN
                    if getattr(rpc_registry.methods[name], "_dsh_sync", None) == "write")
    check("写库方法走 MFF_WRITE 通道", len(writes) == 8, writes)
except Exception as exc:
    check("11 个重写方法全部重新绑定", False, exc)

# 8. get_type_by_name 不再抛 TypeError
try:
    tif = call("get_type_by_name", "unsigned int")
    check("get_type_by_name 保持可用", not tif.empty(), tif)
except Exception as exc:
    check("get_type_by_name 保持可用", False, exc)

try:
    call("get_type_by_name", "cfg_header")
    check("未知类型名走 parse_decl 而不是抛 TypeError", True)
except IDAError:
    check("未知类型名走 parse_decl 而不是抛 TypeError", True)
except TypeError as exc:
    check("未知类型名走 parse_decl 而不是抛 TypeError", False, exc)

print("\n".join("  ✓ %s" % name for name in OK))
if BAD:
    print("")
    for name, detail in BAD:
        print("  ✗ %s" % name)
        if detail is not None:
            print("      %r" % (detail,))
    print("\n通过 %d，失败 %d" % (len(OK), len(BAD)))
    sys.exit(1)
print("\n通过 %d，失败 0" % len(OK))
