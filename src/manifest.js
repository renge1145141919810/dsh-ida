/**
 * 自动生成，不要手改 —— 由 _dev/gen-manifest.mjs 从真实的 mcp-plugin.py 抽取。
 * 生成时间：2026-11-10T09:13:19.110Z
 * 来源：<IDA_USER_DIR>/plugins/mcp-plugin.py
 *
 * 用途：ida_methods 自曝能力、ida_raw 的具名参数映射与拼写纠正。
 */

export const MANIFEST_GENERATED_AT = "2026-11-10T09:13:19.112Z"
export const MANIFEST_SOURCE = "<IDA_USER_DIR>/plugins/mcp-plugin.py"

/** @type {Array<{name:string,params:Array<{name:string,type:string,optional:boolean}>,returns:string|null,doc:string,write:boolean,unsafe:boolean}>} */
export const LEGACY_METHODS = [
  {
    "name": "get_metadata",
    "params": [],
    "returns": "Metadata",
    "doc": "Get metadata about the current IDB",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_function_by_name",
    "params": [
      {
        "name": "name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "Function",
    "doc": "Get a function by its name",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_function_by_address",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "Function",
    "doc": "Get a function by its address",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_current_address",
    "params": [],
    "returns": "str",
    "doc": "Get the address currently selected by the user",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_current_function",
    "params": [],
    "returns": "Optional[Function]",
    "doc": "Get the function currently selected by the user",
    "write": false,
    "unsafe": false
  },
  {
    "name": "convert_number",
    "params": [
      {
        "name": "text",
        "type": "str",
        "optional": false
      },
      {
        "name": "size",
        "type": "Optional[int]",
        "optional": false
      }
    ],
    "returns": "ConvertedNumber",
    "doc": "Convert a number (decimal, hexadecimal) to different representations",
    "write": false,
    "unsafe": false
  },
  {
    "name": "list_functions",
    "params": [
      {
        "name": "offset",
        "type": "int",
        "optional": false
      },
      {
        "name": "count",
        "type": "int",
        "optional": false
      }
    ],
    "returns": "Page[Function]",
    "doc": "List all functions in the database (paginated)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "list_globals_filter",
    "params": [
      {
        "name": "offset",
        "type": "int",
        "optional": false
      },
      {
        "name": "count",
        "type": "int",
        "optional": false
      },
      {
        "name": "filter",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "Page[Global]",
    "doc": "List matching globals in the database (paginated, filtered)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "list_globals",
    "params": [
      {
        "name": "offset",
        "type": "int",
        "optional": false
      },
      {
        "name": "count",
        "type": "int",
        "optional": false
      }
    ],
    "returns": "Page[Global]",
    "doc": "List all globals in the database (paginated)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "list_imports",
    "params": [
      {
        "name": "offset",
        "type": "int",
        "optional": false
      },
      {
        "name": "count",
        "type": "int",
        "optional": false
      }
    ],
    "returns": "Page[Import]",
    "doc": "List all imported symbols with their name and module (paginated)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "list_strings_filter",
    "params": [
      {
        "name": "offset",
        "type": "int",
        "optional": false
      },
      {
        "name": "count",
        "type": "int",
        "optional": false
      },
      {
        "name": "filter",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "Page[String]",
    "doc": "List matching strings in the database (paginated, filtered)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "list_strings",
    "params": [
      {
        "name": "offset",
        "type": "int",
        "optional": false
      },
      {
        "name": "count",
        "type": "int",
        "optional": false
      }
    ],
    "returns": "Page[String]",
    "doc": "List all strings in the database (paginated)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "list_local_types",
    "params": [],
    "returns": null,
    "doc": "List all Local types in the database",
    "write": false,
    "unsafe": false
  },
  {
    "name": "decompile_function",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "str",
    "doc": "Decompile a function at the given address",
    "write": false,
    "unsafe": false
  },
  {
    "name": "disassemble_function",
    "params": [
      {
        "name": "start_address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "DisassemblyFunction",
    "doc": "Get assembly code for a function (API-compatible with older IDA builds)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_xrefs_to",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "list[Xref]",
    "doc": "Get all cross references to the given address",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_xrefs_to_field",
    "params": [
      {
        "name": "struct_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "field_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "list[Xref]",
    "doc": "Get all cross references to a named struct field (member)",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_callees",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "list[dict[str,str]]",
    "doc": "Get all the functions called (callees) by the function at function_address",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_callers",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "list[Function]",
    "doc": "Get all callers of the given address",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_entry_points",
    "params": [],
    "returns": "list[Function]",
    "doc": "Get all entry points in the database",
    "write": false,
    "unsafe": false
  },
  {
    "name": "set_comment",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      },
      {
        "name": "comment",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Set a comment for a given address in the function disassembly and pseudocode",
    "write": true,
    "unsafe": false
  },
  {
    "name": "rename_local_variable",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "old_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "new_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Rename a local variable in a function",
    "write": true,
    "unsafe": false
  },
  {
    "name": "rename_global_variable",
    "params": [
      {
        "name": "old_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "new_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Rename a global variable",
    "write": true,
    "unsafe": false
  },
  {
    "name": "set_global_variable_type",
    "params": [
      {
        "name": "variable_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "new_type",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Set a global variable's type",
    "write": true,
    "unsafe": false
  },
  {
    "name": "patch_address_assembles",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      },
      {
        "name": "instructions",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "str",
    "doc": "",
    "write": true,
    "unsafe": false
  },
  {
    "name": "get_global_variable_value_by_name",
    "params": [
      {
        "name": "variable_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "str",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_global_variable_value_at_address",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "str",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "rename_function",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "new_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Rename a function",
    "write": true,
    "unsafe": false
  },
  {
    "name": "set_function_prototype",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "prototype",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Set a function's prototype",
    "write": true,
    "unsafe": false
  },
  {
    "name": "declare_c_type",
    "params": [
      {
        "name": "c_declaration",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Create or update a local type from a C declaration",
    "write": true,
    "unsafe": false
  },
  {
    "name": "set_local_variable_type",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "variable_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "new_type",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Set a local variable's type",
    "write": true,
    "unsafe": false
  },
  {
    "name": "get_stack_frame_variables",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "list[StackFrameVariable]",
    "doc": "Retrieve the stack frame variables for a given function",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_defined_structures",
    "params": [],
    "returns": "list[StructureDefinition]",
    "doc": "Returns a list of all defined structures",
    "write": false,
    "unsafe": false
  },
  {
    "name": "analyze_struct_detailed",
    "params": [
      {
        "name": "name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "dict",
    "doc": "Detailed analysis of a structure with all fields",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_struct_at_address",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      },
      {
        "name": "struct_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "dict",
    "doc": "Get structure field values at a specific address",
    "write": false,
    "unsafe": false
  },
  {
    "name": "get_struct_info_simple",
    "params": [
      {
        "name": "name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "dict",
    "doc": "Simple function to get basic structure information",
    "write": false,
    "unsafe": false
  },
  {
    "name": "search_structures",
    "params": [
      {
        "name": "filter",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "list[dict]",
    "doc": "Search for structures by name pattern",
    "write": false,
    "unsafe": false
  },
  {
    "name": "rename_stack_frame_variable",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "old_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "new_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Change the name of a stack variable for an IDA function",
    "write": true,
    "unsafe": false
  },
  {
    "name": "create_stack_frame_variable",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "offset",
        "type": "str",
        "optional": false
      },
      {
        "name": "variable_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "type_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "For a given function, create a stack variable at an offset and with a specific type",
    "write": true,
    "unsafe": false
  },
  {
    "name": "set_stack_frame_variable_type",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "variable_name",
        "type": "str",
        "optional": false
      },
      {
        "name": "type_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "For a given disassembled function, set the type of a stack variable",
    "write": true,
    "unsafe": false
  },
  {
    "name": "delete_stack_frame_variable",
    "params": [
      {
        "name": "function_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "variable_name",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Delete the named stack variable for a given function",
    "write": true,
    "unsafe": false
  },
  {
    "name": "read_memory_bytes",
    "params": [
      {
        "name": "memory_address",
        "type": "str",
        "optional": false
      },
      {
        "name": "size",
        "type": "int",
        "optional": false
      }
    ],
    "returns": "str",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "data_read_byte",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "int",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "data_read_word",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "int",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "data_read_dword",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "int",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "data_read_qword",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "int",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "data_read_string",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": "str",
    "doc": "",
    "write": false,
    "unsafe": false
  },
  {
    "name": "dbg_get_registers",
    "params": [],
    "returns": "list[ThreadRegisters]",
    "doc": "Get all registers and their values. This function is only available when debugging.",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_get_call_stack",
    "params": [],
    "returns": "list[dict[str,str]]",
    "doc": "Get the current call stack.",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_list_breakpoints",
    "params": [],
    "returns": null,
    "doc": "List all breakpoints in the program.",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_start_process",
    "params": [],
    "returns": null,
    "doc": "Start the debugger, returns the current instruction pointer",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_exit_process",
    "params": [],
    "returns": null,
    "doc": "Exit the debugger",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_continue_process",
    "params": [],
    "returns": "str",
    "doc": "Continue the debugger, returns the current instruction pointer",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_run_to",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Run the debugger to the specified address",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_set_breakpoint",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Set a breakpoint at the specified address",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_step_into",
    "params": [],
    "returns": null,
    "doc": "Step into the current instruction",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_step_over",
    "params": [],
    "returns": null,
    "doc": "Step over the current instruction",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_delete_breakpoint",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Delete a breakpoint at the specified address",
    "write": false,
    "unsafe": true
  },
  {
    "name": "dbg_enable_breakpoint",
    "params": [
      {
        "name": "address",
        "type": "str",
        "optional": false
      },
      {
        "name": "enable",
        "type": "bool",
        "optional": false
      }
    ],
    "returns": null,
    "doc": "Enable or disable a breakpoint at the specified address",
    "write": false,
    "unsafe": true
  }
]

export const LEGACY_METHOD_NAMES = LEGACY_METHODS.map((m) => m.name)
