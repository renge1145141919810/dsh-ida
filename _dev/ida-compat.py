# ==== dsh-ida plugin compat layer (generated; do not edit here) ====
# 目的：让 ida-pro-mcp 的 mcp-plugin.py 在「老 SDK」的 IDA 上也能用。
# 背景：上游插件按 IDA 9.x 的 Python SDK 写，用到了 PT_EMPTY / get_ordinal_limit /
#      tinfo_t(decl, til, flags) / get_type_by_tid / get_udm_by_tid 这些新符号。
# 8.x 上这些要么不存在（AttributeError），要么构造失败，于是类型层、结构体层、
# 栈帧层整块失效。
#
# 这一层只做三件事：
#   1. 用 getattr 兜底 + 多种写法重试，把「新 SDK 专有」变成「两代都能跑」；
#   2. 改名/改类型后按交叉引用刷新伪代码缓存（原来把数据地址丢给 decompile_func）；
#   3. 返回值统一成 JSON 友好的 dict/list/str，不再返回 None 或裸对象。
#
# 所有新函数都以 _dsh_ 开头；被替换的 RPC 方法在文件末尾重新绑定进 rpc_registry。

import re as _dsh_re

_DSH_COMPAT_VERSION = "1.1"
_DSH_CALLING_CONVENTIONS = (
    "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall",
    "__usercall", "__userpurge", "__high", "__near", "__far", "__pascal",
)
_DSH_BUILTIN_WORDS = (
    "void", "char", "short", "int", "long", "float", "double", "signed",
    "unsigned", "struct", "union", "enum", "const", "volatile", "size_t",
    "bool", "_Bool",
)


def _dsh_say(message):
    try:
        print("[dsh-ida] %s" % message)
    except Exception:
        pass


def _dsh_flag(*names):
    """把若干个可能不存在的 PT_* 标志拼起来，缺哪个就跳过哪个。"""
    value = 0
    for name in names:
        value |= getattr(ida_typeinf, name, 0)
    return value


def _dsh_idati():
    try:
        return ida_typeinf.get_idati()
    except Exception:
        return None


def _dsh_ordinal_limit(til=None):
    """IDA 9 叫 get_ordinal_limit，更早的版本只有 get_ordinal_qty。

    两个都没有就返回 0，让调用方退化到「连续 miss 就停」的扫描模式 ——
    宁可多扫几十次 get_numbered_type，也不要因为一个函数名不存在就整块不可用。
    """
    for name in ("get_ordinal_limit", "get_ordinal_qty"):
        fn = getattr(ida_typeinf, name, None)
        if fn is None:
            continue
        if til is not None:
            try:
                value = int(fn(til))
                if value > 0:
                    return value
            except Exception:
                pass
        try:
            value = int(fn())
            if value > 0:
                return value
        except Exception:
            pass
        idati = _dsh_idati()
        if idati is not None:
            try:
                value = int(fn(idati))
                if value > 0:
                    return value
            except Exception:
                pass
    return 0


def _dsh_scan_ordinals(callback, limit=0, miss_budget=64):
    """遍历本地类型序号。callback 返回 False 表示这一号没有类型。"""
    total = limit or _dsh_ordinal_limit()
    if total and total > 1:
        for ordinal in range(1, total):
            callback(ordinal)
        return
    misses = 0
    for ordinal in range(1, 100000):
        try:
            hit = callback(ordinal)
        except Exception:
            hit = False
        if hit:
            misses = 0
        else:
            misses += 1
            if misses >= miss_budget:
                break


def _dsh_numbered_type(ordinal):
    tif = ida_typeinf.tinfo_t()
    for til in (_dsh_idati(), None):
        try:
            if tif.get_numbered_type(til, ordinal):
                break
        except Exception:
            continue
    try:
        if tif.empty():
            return None
    except Exception:
        return None
    return tif


def _dsh_type_text(tif):
    """tinfo_t → 可读的 C 类型串。旧版本 _print 的签名/可用标志不一样，逐个试。"""
    attempts = (
        lambda: tif._print(None, _dsh_flag("PRTYPE_1LINE", "PRTYPE_TYPE")),
        lambda: tif._print(None, _dsh_flag("PRTYPE_TYPE")),
        lambda: tif._print(),
        lambda: str(tif),
    )
    for call in attempts:
        try:
            value = call()
        except Exception:
            continue
        if value:
            return str(value).strip()
    return "?"


def _dsh_udt_members(tif):
    members = []
    udt = ida_typeinf.udt_type_data_t()
    try:
        if not tif.get_udt_details(udt):
            return members
    except Exception:
        return members
    for udm in udt:
        try:
            if udm.is_gap():
                continue
        except Exception:
            pass
        try:
            size_bits = int(getattr(udm, "size", 0) or 0)
        except Exception:
            size_bits = 0
        members.append({
            "name": getattr(udm, "name", "") or "",
            "offset": hex(int(getattr(udm, "offset", 0) or 0) // 8),
            "size": hex(size_bits // 8),
            "type": _dsh_type_text(getattr(udm, "type", None)),
        })
    return members


# ---------------------------------------------------------------- 类型解析

def _dsh_parse_decl(text):
    """parse_decl 是两代 SDK 都有的唯一入口。返回值用 empty() 判断更可靠 ——
    某些版本返回 bool，某些版本返回错误个数 0，直接 if 会被 0 骗到。"""
    if not text:
        return None
    tif = ida_typeinf.tinfo_t()
    try:
        ida_typeinf.parse_decl(tif, None, text, _dsh_flag("PT_SIL"))
    except Exception:
        return None
    try:
        if tif.empty():
            return None
    except Exception:
        return None
    return tif


def _dsh_parse_type(text):
    """把一个类型串变成 tinfo_t。

    三条路依次尝试：
      1. 新 SDK 的 tinfo_t(decl, til, flags) 构造函数；
      2. parse_decl + 补一个占位声明符（老 SDK 唯一可用的路）；
      3. 数组后缀单独挪位（unsigned char[13] → unsigned char __dsh_t[13]）。
    """
    raw = (text or "").strip()
    if not raw:
        return None
    body = raw.rstrip(";").strip()
    if not body:
        return None

    try:
        tif = ida_typeinf.tinfo_t(body, None, _dsh_flag("PT_SIL"))
        if not tif.empty():
            return tif
    except Exception:
        pass

    candidates = []
    array_match = _dsh_re.match(r"^(.*?)((?:\s*\[[^\]]*\])+)$", body)
    if array_match:
        candidates.append("%s __dsh_t%s;" % (array_match.group(1).strip(), array_match.group(2)))
    candidates.append("%s __dsh_t;" % body)
    candidates.append("%s;" % body)
    for candidate in candidates:
        tif = _dsh_parse_decl(candidate)
        if tif is not None:
            return tif
    return None


def _dsh_type_from_name(type_name):
    try:
        tif = _dsh_orig_type_by_name(type_name)
        if tif is not None and not tif.empty():
            return tif
    except Exception:
        pass
    return _dsh_parse_type(type_name)


def _dsh_inject_declarator(text):
    """`int __cdecl (char *)` 没有函数名，parse_decl 会拒绝；补一个占位名。"""
    match = _dsh_re.search(r"\(", text)
    if not match:
        return None
    head = text[:match.start()].rstrip()
    tokens = head.split()
    if not tokens:
        return None
    last = tokens[-1]
    if _dsh_re.match(r"^[A-Za-z_]\w*$", last) and last not in _DSH_BUILTIN_WORDS \
            and last not in _DSH_CALLING_CONVENTIONS and not last.startswith("__"):
        return None
    return head + " __dsh_fn" + text[match.start():]


def _dsh_proto_candidates(prototype):
    """函数原型可能失败的原因太多，这里把所有合理写法排成队列逐个试。"""
    raw = (prototype or "").strip().rstrip(";").strip()
    if not raw:
        return []
    variants = [raw]

    # Hex-Rays 伪代码里的类型名（_BYTE/_DWORD…）不在 C 语法里，换掉再试
    replaced = raw
    for pattern, repl in (
        (r"\b_BYTE\b", "unsigned char"),
        (r"\b_WORD\b", "unsigned short"),
        (r"\b_DWORD\b", "unsigned int"),
        (r"\b_QWORD\b", "unsigned __int64"),
        (r"\b_OWORD\b", "unsigned __int128"),
        (r"\b_BOOL\d*\b", "unsigned char"),
        (r"\b_(?:INT|UINT)\d+\b", "int"),
        (r"\b_SIZE_T\b", "size_t"),
        (r"\b_PVOID\b", "void *"),
    ):
        replaced = _dsh_re.sub(pattern, repl, replaced)
    if replaced != raw:
        variants.append(replaced)

    for base in list(variants):
        named = _dsh_inject_declarator(base)
        if named and named not in variants:
            variants.append(named)

    return [item if item.endswith(";") else item + ";" for item in variants]


# ---------------------------------------------------------------- 伪代码刷新

def _dsh_mark_dirty(ea):
    mark = getattr(ida_hexrays, "mark_cfunc_dirty", None)
    if mark is None:
        return
    try:
        mark(ea, False)
    except Exception:
        try:
            mark(ea)
        except Exception:
            pass


def _dsh_functions_using(ea, cap=200):
    found = []
    try:
        xrefs = idautils.XrefsTo(ea)
    except Exception:
        return found
    try:
        for xref in xrefs:
            try:
                fn = idaapi.get_func(xref.frm)
            except Exception:
                continue
            if fn and fn.start_ea not in found:
                found.append(fn.start_ea)
                if len(found) >= cap:
                    break
    except Exception:
        pass
    return found


def _dsh_refresh_for_data(ea):
    """数据项改名/改类型后，引用它的函数伪代码不会自己更新。

    上游把数据地址直接丢给 refresh_decompiler_ctext()，那里走的是
    decompile_func(addr)，对数据地址必然失败 —— 于是反汇编名字变了、伪代码还是旧名。
    """
    targets = _dsh_functions_using(ea)
    for start in targets:
        _dsh_mark_dirty(start)
        try:
            refresh_decompiler_ctext(start)
        except Exception:
            pass
    return len(targets)


def _dsh_mark_all_dirty(cap=50000):
    """改类型定义后，所有函数都可能受影响。mark_cfunc_dirty 只是失效缓存，很便宜。"""
    mark = getattr(ida_hexrays, "mark_cfunc_dirty", None)
    if mark is None:
        return 0
    count = 0
    try:
        for ea in idautils.Functions():
            _dsh_mark_dirty(ea)
            count += 1
            if count >= cap:
                break
    except Exception:
        pass
    return count


def _dsh_item_head(ea):
    for name in ("get_item_head",):
        fn = getattr(ida_bytes, name, None)
        if fn is None:
            continue
        try:
            return fn(ea)
        except Exception:
            pass
    try:
        return idc.get_item_head(ea)
    except Exception:
        return ea


# ---------------------------------------------------------------- RPC 替换

def list_local_types():
    """List all Local types in the database"""
    rows = []

    def visit(ordinal):
        tif = _dsh_numbered_type(ordinal)
        if tif is None:
            return False
        try:
            name = tif.get_type_name()
        except Exception:
            name = None
        rows.append("\nType #%d: %s" % (ordinal, name or "<Anonymous Type #%d>" % ordinal))
        try:
            if tif.is_udt():
                decl = tif._print(None, _dsh_flag(
                    "PRTYPE_MULTI", "PRTYPE_TYPE", "PRTYPE_SEMI",
                    "PRTYPE_DEF", "PRTYPE_METHODS", "PRTYPE_OFFSETS"))
                if decl:
                    rows.append("  C declaration:\n%s" % decl)
            else:
                decl = tif._print(None, _dsh_flag("PRTYPE_1LINE", "PRTYPE_TYPE", "PRTYPE_SEMI"))
                if decl:
                    rows.append("  Simple declaration:\n%s" % decl)
        except Exception as exc:
            rows.append("  (declaration unavailable: %s)" % exc)
        return True

    _dsh_scan_ordinals(visit)
    return rows


def declare_c_type(c_declaration: str):
    """Create or update a local type from a C declaration"""
    attempts = []
    full = _dsh_flag("PT_SIL", "PT_TYP", "PT_EMPTY")
    if full & getattr(ida_typeinf, "PT_EMPTY", 0):
        attempts.append(("PT_SIL|PT_TYP|PT_EMPTY", full))
    attempts.append(("PT_SIL|PT_TYP", _dsh_flag("PT_SIL", "PT_TYP")))
    attempts.append(("PT_SIL", _dsh_flag("PT_SIL")))

    last_error = None
    for label, flags in attempts:
        try:
            errors, messages = parse_decls_ctypes(c_declaration, flags)
        except Exception as exc:
            last_error = "%s → %s" % (label, exc)
            continue
        if not errors:
            dirty = _dsh_mark_all_dirty()
            body = "\n".join(messages) if messages else ""
            return "success\n\nInfo:\n%s\n(flags: %s, cfunc invalidated: %d)" % (body, label, dirty)
        last_error = "%s → %s" % (label, "\n".join(messages) if messages else "parse_decl returned errors")

    raise IDAError("Failed to parse type:\n%s\n\n%s" % (c_declaration, last_error))


def set_function_prototype(function_address: str, prototype: str):
    """Set a function's prototype"""
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError("No function found at address %s" % function_address)

    tried = []
    for text in _dsh_proto_candidates(prototype):
        tif = _dsh_parse_decl(text)
        if tif is None:
            tried.append("%s → parse failed" % text)
            continue
        try:
            is_func = tif.is_func()
        except Exception as exc:
            tried.append("%s → is_func() %s" % (text, exc))
            continue
        if not is_func:
            tried.append("%s → parsed, but not a function type" % text)
            continue
        try:
            applied = ida_typeinf.apply_tinfo(func.start_ea, tif, _dsh_flag("PT_SIL"))
        except Exception as exc:
            tried.append("%s → apply_tinfo raised %s" % (text, exc))
            continue
        if not applied:
            tried.append("%s → apply_tinfo rejected" % text)
            continue
        _dsh_mark_dirty(func.start_ea)
        try:
            refresh_decompiler_ctext(func.start_ea)
        except Exception:
            pass
        return {
            "ok": True,
            "function": hex(func.start_ea),
            "applied": text,
            "attempts": len(tried) + 1,
        }

    raise IDAError(
        "Failed to parse prototype string: %s\n" % prototype
        + "\n".join(tried)
        + "\n可用写法：int __cdecl f(char *s)　/　void __fastcall f(int a, int b)"
    )


def get_defined_structures():
    """ Returns a list of all defined structures """
    rv = []

    def visit(ordinal):
        tif = _dsh_numbered_type(ordinal)
        if tif is None:
            return False
        try:
            if not tif.is_udt():
                return True
        except Exception:
            return True
        try:
            name = tif.get_type_name() or "<anonymous #%d>" % ordinal
        except Exception:
            name = "<anonymous #%d>" % ordinal
        try:
            size = tif.get_size()
        except Exception:
            size = 0
        rv.append({
            "name": name,
            "size": hex(size),
            "members": _dsh_udt_members(tif),
        })
        return True

    _dsh_scan_ordinals(visit)
    return rv


def search_structures(filter: str):
    """Search for structures by name pattern"""
    needle = (filter or "").lower()
    results = []

    def visit(ordinal):
        tif = _dsh_numbered_type(ordinal)
        if tif is None:
            return False
        try:
            name = tif.get_type_name() or ""
        except Exception:
            name = ""
        if needle and needle not in name.lower():
            return True
        try:
            if not tif.is_udt():
                return True
        except Exception:
            return True
        members = _dsh_udt_members(tif)
        try:
            is_union = bool(tif.is_union())
        except Exception:
            is_union = False
        try:
            size = tif.get_size()
        except Exception:
            size = 0
        results.append({
            "name": name,
            "size": size,
            "member_count": len(members),
            "is_union": is_union,
            "ordinal": ordinal,
        })
        return True

    _dsh_scan_ordinals(visit)
    return results


def get_global_variable_value_internal(ea: int) -> str:
    ea = _dsh_item_head(ea)
    if not ida_bytes.is_loaded(ea):
        raise IDAError("No data at %#x (not loaded)" % ea)

    tif = ida_typeinf.tinfo_t()
    size = 0
    has_type = False
    try:
        has_type = bool(ida_nalt.get_tinfo(tif, ea))
    except Exception:
        has_type = False

    # 字符数组按字符串读（先判，别让它掉进下面的按字节分支）
    if has_type:
        try:
            if tif.is_array() and tif.get_array_element().is_decl_char():
                text = idaapi.get_strlit_contents(ea, -1, 0)
                if text:
                    return '"%s"' % text.decode("utf-8", "replace").strip()
        except Exception:
            pass
        try:
            size = int(tif.get_size())
        except Exception:
            size = 0

    if size <= 0:
        try:
            size = int(ida_bytes.get_item_size(ea))
        except Exception:
            size = 0
    if size <= 0:
        # 未定义字节：按 1 字节读，比直接报「没有类型信息」有用
        size = 1

    if size == 1:
        return hex(ida_bytes.get_byte(ea))
    if size == 2:
        return hex(ida_bytes.get_word(ea))
    if size == 4:
        return hex(ida_bytes.get_dword(ea))
    if size == 8:
        return hex(ida_bytes.get_qword(ea))
    raw = ida_bytes.get_bytes(ea, size) or b""
    return " ".join(hex(x) for x in raw)


def rename_global_variable(old_name: str, new_name: str):
    """Rename a global variable"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    if ea == idaapi.BADADDR:
        raise IDAError("Global variable %s not found" % old_name)
    if not idaapi.set_name(ea, new_name):
        raise IDAError("Failed to rename global variable %s to %s" % (old_name, new_name))
    touched = _dsh_refresh_for_data(ea)
    return {
        "ok": True,
        "address": hex(ea),
        "old": old_name,
        "new": new_name,
        "refreshed_functions": touched,
    }


def set_global_variable_type(variable_name: str, new_type: str):
    """Set a global variable's type"""
    ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)
    if ea == idaapi.BADADDR:
        raise IDAError("Global variable %s not found" % variable_name)
    tif = _dsh_type_from_name(new_type)
    if tif is None:
        raise IDAError("Failed to parse type: %s" % new_type)
    if not ida_typeinf.apply_tinfo(ea, tif, _dsh_flag("PT_SIL")):
        raise IDAError("Failed to apply type")
    touched = _dsh_refresh_for_data(ea)
    return {
        "ok": True,
        "address": hex(ea),
        "type": new_type,
        "refreshed_functions": touched,
    }


# ---------------------------------------------------------------- 栈帧层

def _dsh_frame_tif(func):
    """IDA 9 用 tif.get_type_by_tid(func.frame)；8.x 只能走 ida_frame.get_func_frame。"""
    tif = ida_typeinf.tinfo_t()
    getter = getattr(tif, "get_type_by_tid", None)
    if getter is not None:
        try:
            if getter(func.frame) and not tif.empty():
                return tif
        except Exception:
            pass

    frame_getter = getattr(ida_frame, "get_func_frame", None)
    if frame_getter is not None:
        try:
            out = ida_typeinf.tinfo_t()
            if frame_getter(out, func) and not out.empty():
                return out
        except Exception:
            pass
        try:
            out = frame_getter(func)
            if isinstance(out, ida_typeinf.tinfo_t) and not out.empty():
                return out
        except Exception:
            pass
    return None


def _dsh_udm_by_name(frame_tif, name):
    """get_udm_by_tid 是 9.0 才有的，直接遍历 udt 更稳。"""
    udt = ida_typeinf.udt_type_data_t()
    try:
        if not frame_tif.get_udt_details(udt):
            return None
    except Exception:
        return None
    for udm in udt:
        try:
            if udm.name == name:
                return udm
        except Exception:
            continue
    return None


def get_stack_frame_variables_internal(function_address: int, raise_error: bool):
    func = idaapi.get_func(function_address)
    if not func:
        if raise_error:
            raise IDAError("No function found at address %s" % hex(function_address))
        return []
    frame_tif = _dsh_frame_tif(func)
    if frame_tif is None:
        return []
    return _dsh_udt_members(frame_tif)


def rename_stack_frame_variable(function_address: str, old_name: str, new_name: str):
    """ Change the name of a stack variable for an IDA function """
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError("No function found at address %s" % function_address)
    frame_tif = _dsh_frame_tif(func)
    if frame_tif is None:
        raise IDAError("No frame returned.")
    udm = _dsh_udm_by_name(frame_tif, old_name)
    if udm is None:
        raise IDAError("%s not found." % old_name)
    offset = int(getattr(udm, "offset", 0)) // 8
    try:
        if ida_frame.is_funcarg_off(func, offset):
            raise IDAError("%s is an argument member. Will not change the name." % old_name)
    except IDAError:
        raise
    except Exception:
        pass
    try:
        sval = ida_frame.soff_to_fpoff(func, offset)
    except Exception:
        sval = offset
    if not ida_frame.define_stkvar(func, new_name, sval, udm.type):
        raise IDAError("failed to rename stack frame variable")
    try:
        refresh_decompiler_ctext(func.start_ea)
    except Exception:
        pass
    return {"ok": True, "old": old_name, "new": new_name}


def set_stack_frame_variable_type(function_address: str, variable_name: str, type_name: str):
    """ For a given disassembled function, set the type of a stack variable """
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError("No function found at address %s" % function_address)
    frame_tif = _dsh_frame_tif(func)
    if frame_tif is None:
        raise IDAError("No frame returned.")
    udm = _dsh_udm_by_name(frame_tif, variable_name)
    if udm is None:
        raise IDAError("%s not found." % variable_name)
    tif = _dsh_type_from_name(type_name)
    if tif is None:
        raise IDAError("Failed to parse type: %s" % type_name)
    offset = int(getattr(udm, "offset", 0)) // 8
    setter = getattr(ida_frame, "set_frame_member_type", None)
    if setter is not None:
        if not setter(func, offset, tif):
            raise IDAError("failed to set stack frame variable type")
    else:
        sval = ida_frame.soff_to_fpoff(func, offset)
        if not ida_frame.define_stkvar(func, variable_name, sval, tif):
            raise IDAError("failed to set stack frame variable type")
    try:
        refresh_decompiler_ctext(func.start_ea)
    except Exception:
        pass
    return {"ok": True, "variable": variable_name, "type": type_name}


def delete_stack_frame_variable(function_address: str, variable_name: str):
    """ Delete the named stack variable for a given function """
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError("No function found at address %s" % function_address)
    frame_tif = _dsh_frame_tif(func)
    if frame_tif is None:
        raise IDAError("No frame returned.")
    udm = _dsh_udm_by_name(frame_tif, variable_name)
    if udm is None:
        raise IDAError("%s not found." % variable_name)
    offset = int(getattr(udm, "offset", 0)) // 8
    size = max(1, int(getattr(udm, "size", 0) or 0) // 8)
    try:
        if ida_frame.is_funcarg_off(func, offset):
            raise IDAError("%s is an argument member. Will not delete." % variable_name)
    except IDAError:
        raise
    except Exception:
        pass
    if not ida_frame.delete_frame_members(func, offset, offset + size):
        raise IDAError("failed to delete stack frame variable")
    try:
        refresh_decompiler_ctext(func.start_ea)
    except Exception:
        pass
    return {"ok": True, "deleted": variable_name}


def create_stack_frame_variable(function_address: str, offset: str, variable_name: str, type_name: str):
    """ For a given function, create a stack variable at an offset and with a specific type """
    func = idaapi.get_func(parse_address(function_address))
    if not func:
        raise IDAError("No function found at address %s" % function_address)
    try:
        sval = parse_address(offset)
    except Exception:
        try:
            sval = int(str(offset), 0)
        except Exception:
            raise IDAError("Bad stack offset: %s" % offset)
    tif = _dsh_type_from_name(type_name)
    if tif is None:
        raise IDAError("Failed to parse type: %s" % type_name)
    if not ida_frame.define_stkvar(func, variable_name, sval, tif):
        raise IDAError("failed to define stack frame variable")
    try:
        refresh_decompiler_ctext(func.start_ea)
    except Exception:
        pass
    return {"ok": True, "variable": variable_name, "offset": str(offset), "type": type_name}


# ---------------------------------------------------------------- 重新绑定

_dsh_orig_type_by_name = get_type_by_name


def get_type_by_name(type_name: str):
    """原实现最后一步是 tinfo_t(type_name)，旧 SDK 会抛异常而不是返回空。"""
    return _dsh_type_from_name(type_name)


_DSH_REPLACEMENTS = {
    # (函数, 参数名, 是否写库)
    # 写库/读库必须重新套上 idawrite/idaread：它们把调用 schedule 到 IDA 主线程，
    # 少了这层就是在 HTTP 线程里直接调 IDA API，轻则报错重则坏库。
    "list_local_types": (list_local_types, (), False),
    "declare_c_type": (declare_c_type, ("c_declaration",), True),
    "set_function_prototype": (set_function_prototype, ("function_address", "prototype"), True),
    "get_defined_structures": (get_defined_structures, (), False),
    "search_structures": (search_structures, ("filter",), False),
    "rename_global_variable": (rename_global_variable, ("old_name", "new_name"), True),
    "set_global_variable_type": (set_global_variable_type, ("variable_name", "new_type"), True),
    "rename_stack_frame_variable": (rename_stack_frame_variable, ("function_address", "old_name", "new_name"), True),
    "set_stack_frame_variable_type": (set_stack_frame_variable_type, ("function_address", "variable_name", "type_name"), True),
    "delete_stack_frame_variable": (delete_stack_frame_variable, ("function_address", "variable_name"), True),
    "create_stack_frame_variable": (create_stack_frame_variable, ("function_address", "offset", "variable_name", "type_name"), True),
}


def _dsh_bind_replacement(name, fn, params, is_write):
    """重新绑定到 rpc_registry。

    两件事都不能漏：
      1. dispatch() 用 get_type_hints(func) 取参数名和类型，所以 __annotations__
         必须正好是这些参数名，否则位置传参会被判成参数个数不符；
      2. idawrite/idaread 是线程调度装饰器，不是日志装饰器 —— 必须在改完注解之后再套，
         否则注解会被旧的覆盖。
    """
    if name not in rpc_registry.methods:
        return False
    try:
        annotations = dict(getattr(fn, "__annotations__", {}) or {})
        for param in params:
            annotations.setdefault(param, str)
        fn.__annotations__ = {key: annotations[key] for key in params}

        decorator = idawrite if is_write else idaread
        try:
            bound = decorator(fn)
        except Exception:
            bound = fn
        rpc_registry.methods[name] = bound
        return True
    except Exception as exc:
        _dsh_say("failed to patch %s: %s" % (name, exc))
        return False


_dsh_bound = 0
for _dsh_name, (_dsh_fn, _dsh_params, _dsh_write) in _DSH_REPLACEMENTS.items():
    if _dsh_bind_replacement(_dsh_name, _dsh_fn, _dsh_params, _dsh_write):
        _dsh_bound += 1

# 这两个不是 RPC 方法，只是被上面的方法调用，改全局名就够了
get_global_variable_value_internal = get_global_variable_value_internal
get_stack_frame_variables_internal = get_stack_frame_variables_internal

_dsh_say("compat layer v%s active on IDA %s.%s (%d methods rebound)" % (
    _DSH_COMPAT_VERSION,
    globals().get("ida_major", "?"),
    globals().get("ida_minor", "?"),
    _dsh_bound,
))
