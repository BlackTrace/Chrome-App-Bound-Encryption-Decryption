#!/usr/bin/env python3
"""
COMrade ABE - COM App-Bound Encryption Interface Analyzer
Discovers and analyzes COM interfaces for Chromium-based browser elevation services.
"""

import argparse
import ctypes
import io
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Configure stdout encoding for Windows
if sys.platform == "win32":
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

import comtypes
import comtypes.automation
import comtypes.typeinfo
import winreg

try:
    import pefile
except ImportError:
    pefile = None


def _supports_unicode() -> bool:
    """Check if terminal supports Unicode output."""
    if sys.platform != "win32":
        return True
    try:
        # Check if we're in Windows Terminal or other Unicode-capable terminal
        return os.environ.get("WT_SESSION") is not None or os.environ.get("TERM_PROGRAM") is not None
    except Exception:
        return False


# Use ASCII fallbacks if Unicode not supported
_USE_UNICODE = _supports_unicode()

# Constants
EMOJI = {
    "success": "[+]" if not _USE_UNICODE else "✅",
    "failure": "[-]" if not _USE_UNICODE else "❌",
    "info": "[i]" if not _USE_UNICODE else "ℹ️",
    "search": "[?]" if not _USE_UNICODE else "🔍",
    "gear": "[*]" if not _USE_UNICODE else "⚙️",
    "file": "[F]" if not _USE_UNICODE else "📄",
    "lightbulb": "[!]" if not _USE_UNICODE else "💡",
    "warning": "[!]" if not _USE_UNICODE else "⚠️"
}

START_TYPE_MAP = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}

# Known browser service patterns
BROWSER_SERVICES = {
    "chrome": ["GoogleChromeElevationService", "GoogleChromeCanaryElevationService",
               "GoogleChromeBetaElevationService", "GoogleChromeDevElevationService"],
    "edge": ["MicrosoftEdgeElevationService", "MicrosoftEdgeCanaryElevationService",
             "MicrosoftEdgeBetaElevationService", "MicrosoftEdgeDevElevationService"],
    "brave": ["BraveElevationService", "BraveBetaElevationService", "BraveNightlyElevationService"],
}

# Known interface IIDs for primary detection
KNOWN_PRIMARY_IIDS = {
    "chrome": "{463ABECF-410D-407F-8AF5-0DF35A005CC8}",
    "edge": "{C9C2B807-7731-4F34-81B7-44FF7779522B}",
    "brave": "{F396861E-0C8E-4C71-8256-2FAE6D759CE9}",
}


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class MethodDetail:
    name: str
    ret_type: str
    params: List[str]
    ovft: int
    memid: int
    index_in_interface: int


@dataclass
class InterfaceInfo:
    name: str
    iid: str
    type_info_obj: Any
    type_attr_obj: Any
    methods_defined: List[MethodDetail] = field(default_factory=list)
    base_interface_name: Optional[str] = None


@dataclass
class AnalyzedMethod:
    name: str
    ovft: int
    memid: int
    defining_interface_name: str
    defining_interface_iid: str


@dataclass
class AbeCandidate:
    clsid: str
    interface_name: str
    interface_iid: str
    methods: Dict[str, AnalyzedMethod]
    inheritance_chain_info: List[InterfaceInfo]


@dataclass
class VtableSlotInfo:
    method_name: str
    slot_index: int
    offset_x64: int
    offset_x86: int
    defining_interface: str
    memid: int = 0


@dataclass
class CoclassInfo:
    name: str
    clsid: str
    implemented_interfaces: List[Dict[str, Any]] = field(default_factory=list)
    threading_model: Optional[str] = None
    server_type: Optional[str] = None
    server_path: Optional[str] = None


@dataclass
class ProxyStubInfo:
    iid: str
    name: Optional[str] = None
    registered: bool = True
    marshaling_type: str = "unknown"
    proxy_stub_clsid: Optional[str] = None
    proxy_stub_dll: Optional[str] = None
    typelib_id: Optional[str] = None
    typelib_version: Optional[str] = None


@dataclass
class ComSecurityInfo:
    clsid: str
    appid: Optional[str] = None
    runas: Optional[str] = None
    dll_surrogate: Optional[str] = None
    local_service: Optional[str] = None
    has_launch_permission: bool = False
    has_access_permission: bool = False
    launch_permission_size: int = 0
    access_permission_size: int = 0
    launch_permission_sddl: Optional[str] = None
    access_permission_sddl: Optional[str] = None


@dataclass
class PeTypelibInfo:
    machine: Optional[str] = None
    machine_name: Optional[str] = None
    timestamp: Optional[str] = None
    has_embedded_typelib: bool = False
    typelib_count: int = 0
    uses_rpc: bool = False
    uses_ole: bool = False
    imports: List[str] = field(default_factory=list)
    hardening_apis: List[str] = field(default_factory=list)
    pe_error: Optional[str] = None


@dataclass
class ElevationServiceInfo:
    service_name: str
    display_name: Optional[str] = None
    executable_path: Optional[str] = None
    description: Optional[str] = None
    start_type: Optional[str] = None
    status: Optional[str] = None
    pid: Optional[int] = None
    browser_vendor: Optional[str] = None


@dataclass
class ServiceRuntimeInfo:
    service_name: str
    status: str = "unknown"
    pid: Optional[int] = None
    start_type: str = "unknown"
    can_stop: bool = False
    can_pause: bool = False
    dependencies: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class TypeLibRegistryInfo:
    typelib_id: str
    name: Optional[str] = None
    version: Optional[str] = None
    lcid: Optional[str] = None
    win32_path: Optional[str] = None
    win64_path: Optional[str] = None
    helpdir: Optional[str] = None
    flags: Optional[int] = None


# =============================================================================
# Registry Helpers
# =============================================================================

def reg_read_value(hkey: int, subkey: str, value_name: Optional[str] = None,
                   wow64_64: bool = True) -> Optional[Any]:
    """Read a single registry value, returning None if not found."""
    try:
        access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if wow64_64 else 0)
        with winreg.OpenKey(hkey, subkey, 0, access) as key:
            return winreg.QueryValueEx(key, value_name)[0]
    except (FileNotFoundError, OSError):
        return None


def reg_enum_subkeys(hkey: int, subkey: str, wow64_64: bool = True) -> List[str]:
    """Enumerate subkeys under a registry key."""
    result = []
    try:
        access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if wow64_64 else 0)
        with winreg.OpenKey(hkey, subkey, 0, access) as key:
            i = 0
            while True:
                try:
                    result.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, OSError):
        pass
    return result


def clean_executable_path(raw_path: str) -> str:
    """Extract executable path from ImagePath or LocalServer32 value."""
    if not raw_path:
        return ""
    path = raw_path.strip()
    if path.startswith('"'):
        parts = path.split('"')
        return os.path.normpath(parts[1]) if len(parts) > 1 else ""
    return os.path.normpath(path.split()[0])


# =============================================================================
# COM Type Helpers
# =============================================================================

def get_vt_name(vt_code: int, type_info_context=None, hreftype_or_tdesc=None) -> str:
    """Convert VARIANT type code to C++ type name."""
    VT_MAP = {
        comtypes.automation.VT_EMPTY: "void", comtypes.automation.VT_NULL: "void*",
        comtypes.automation.VT_I2: "SHORT", comtypes.automation.VT_I4: "LONG",
        comtypes.automation.VT_R4: "FLOAT", comtypes.automation.VT_R8: "DOUBLE",
        comtypes.automation.VT_CY: "CURRENCY", comtypes.automation.VT_DATE: "DATE",
        comtypes.automation.VT_BSTR: "BSTR", comtypes.automation.VT_DISPATCH: "IDispatch*",
        comtypes.automation.VT_ERROR: "SCODE", comtypes.automation.VT_BOOL: "VARIANT_BOOL",
        comtypes.automation.VT_VARIANT: "VARIANT", comtypes.automation.VT_UNKNOWN: "IUnknown*",
        comtypes.automation.VT_DECIMAL: "DECIMAL", comtypes.automation.VT_UI1: "BYTE",
        comtypes.automation.VT_I1: "CHAR", comtypes.automation.VT_UI2: "USHORT",
        comtypes.automation.VT_UI4: "ULONG", comtypes.automation.VT_I8: "hyper",
        comtypes.automation.VT_UI8: "uhyper", comtypes.automation.VT_INT: "INT",
        comtypes.automation.VT_UINT: "UINT", comtypes.automation.VT_VOID: "void",
        comtypes.automation.VT_HRESULT: "HRESULT", comtypes.automation.VT_PTR: "void*",
        comtypes.automation.VT_SAFEARRAY: "SAFEARRAY", comtypes.automation.VT_CARRAY: "CARRAY",
        comtypes.automation.VT_USERDEFINED: "USER_DEFINED",
        comtypes.automation.VT_LPSTR: "LPSTR", comtypes.automation.VT_LPWSTR: "LPWSTR",
        64: "FILETIME", 65: "BLOB",
    }

    is_byref = bool(vt_code & comtypes.automation.VT_BYREF)
    is_array = bool(vt_code & comtypes.automation.VT_ARRAY)
    base_vt = vt_code & ~(comtypes.automation.VT_BYREF | comtypes.automation.VT_ARRAY |
                          comtypes.automation.VT_VECTOR)
    name = VT_MAP.get(base_vt, f"Unknown_VT_0x{base_vt:X}")

    if base_vt == comtypes.automation.VT_USERDEFINED and type_info_context and isinstance(hreftype_or_tdesc, int):
        try:
            ref_ti = type_info_context.GetRefTypeInfo(hreftype_or_tdesc)
            udt_name, _, _, _ = ref_ti.GetDocumentation(-1)
            ref_attr = ref_ti.GetTypeAttr()
            name = udt_name
            ref_ti.ReleaseTypeAttr(ref_attr)
        except comtypes.COMError:
            name = f"UserDefined_hreftype_{hreftype_or_tdesc}"
    elif base_vt == comtypes.automation.VT_PTR and type_info_context:
        if hasattr(hreftype_or_tdesc, 'lptdesc') and hreftype_or_tdesc.lptdesc:
            pointed = hreftype_or_tdesc.lptdesc.contents
            next_arg = pointed.hreftype if pointed.vt == comtypes.automation.VT_USERDEFINED else pointed
            name = f"{get_vt_name(pointed.vt, type_info_context, next_arg)}*"

    if is_array:
        name = f"SAFEARRAY({name})"
    if is_byref and not name.endswith("*"):
        name = f"{name}*"
    return name


def get_param_flags_string(flags: int) -> str:
    """Convert parameter flags to string."""
    FLAG_MAP = {
        comtypes.typeinfo.PARAMFLAG_FIN: "in",
        comtypes.typeinfo.PARAMFLAG_FOUT: "out",
        comtypes.typeinfo.PARAMFLAG_FLCID: "lcid",
        comtypes.typeinfo.PARAMFLAG_FRETVAL: "retval",
        comtypes.typeinfo.PARAMFLAG_FOPT: "optional",
        comtypes.typeinfo.PARAMFLAG_FHASDEFAULT: "hasdefault",
    }
    active = [name for flag, name in FLAG_MAP.items() if flags & flag]
    return ", ".join(active) if active else f"none (0x{flags:X})"


def resolve_type_deep(type_info_context, tdesc, history: set = None, depth: int = 0) -> str:
    """
    Recursively resolve type definitions including struct/enum internals.

    For structs (TKIND_RECORD), returns: struct { field1_type field1; field2_type field2; }
    For enums (TKIND_ENUM), returns: enum EnumName
    For pointers, recursively resolves the pointed-to type.

    Args:
        type_info_context: ITypeInfo for resolving references
        tdesc: TYPEDESC structure describing the type
        history: Set of already-visited type names to prevent infinite recursion
        depth: Current recursion depth (max 3 to prevent excessive nesting)
    """
    if history is None:
        history = set()

    MAX_DEPTH = 3
    if depth > MAX_DEPTH:
        return "..."

    vt = tdesc.vt
    is_byref = bool(vt & comtypes.automation.VT_BYREF)
    base_vt = vt & ~(comtypes.automation.VT_BYREF | comtypes.automation.VT_ARRAY |
                     comtypes.automation.VT_VECTOR)

    # Basic type mapping
    VT_MAP = {
        comtypes.automation.VT_EMPTY: "void", comtypes.automation.VT_NULL: "void*",
        comtypes.automation.VT_I2: "SHORT", comtypes.automation.VT_I4: "LONG",
        comtypes.automation.VT_R4: "FLOAT", comtypes.automation.VT_R8: "DOUBLE",
        comtypes.automation.VT_BSTR: "BSTR", comtypes.automation.VT_DISPATCH: "IDispatch*",
        comtypes.automation.VT_BOOL: "VARIANT_BOOL", comtypes.automation.VT_UNKNOWN: "IUnknown*",
        comtypes.automation.VT_UI1: "BYTE", comtypes.automation.VT_I1: "CHAR",
        comtypes.automation.VT_UI2: "USHORT", comtypes.automation.VT_UI4: "ULONG",
        comtypes.automation.VT_I8: "LONGLONG", comtypes.automation.VT_UI8: "ULONGLONG",
        comtypes.automation.VT_INT: "INT", comtypes.automation.VT_UINT: "UINT",
        comtypes.automation.VT_VOID: "void", comtypes.automation.VT_HRESULT: "HRESULT",
        comtypes.automation.VT_LPSTR: "LPSTR", comtypes.automation.VT_LPWSTR: "LPWSTR",
    }

    # Handle pointer types
    if base_vt == comtypes.automation.VT_PTR:
        if hasattr(tdesc, 'lptdesc') and tdesc.lptdesc:
            pointed = tdesc.lptdesc.contents
            inner = resolve_type_deep(type_info_context, pointed, history, depth + 1)
            return f"{inner}*"
        return "void*"

    # Handle user-defined types (structs, enums, interfaces)
    if base_vt == comtypes.automation.VT_USERDEFINED:
        try:
            href = tdesc.hreftype
            ref_ti = type_info_context.GetRefTypeInfo(href)
            ref_attr = ref_ti.GetTypeAttr()
            udt_name, _, _, _ = ref_ti.GetDocumentation(-1)
            type_kind = ref_attr.typekind

            # Prevent infinite recursion for self-referential types
            if udt_name in history:
                ref_ti.ReleaseTypeAttr(ref_attr)
                suffix = "*" if is_byref else ""
                return f"{udt_name}{suffix} /*recursive*/"

            history_copy = history | {udt_name}

            # TKIND_RECORD = struct
            if type_kind == comtypes.typeinfo.TKIND_RECORD:
                fields = []
                for i in range(ref_attr.cVars):
                    try:
                        vardesc = ref_ti.GetVarDesc(i)
                        var_names = ref_ti.GetNames(vardesc.memid, 1)
                        var_name = var_names[0] if var_names else f"field{i}"
                        var_type = resolve_type_deep(ref_ti, vardesc.elemdescVar.tdesc,
                                                     history_copy, depth + 1)
                        fields.append(f"{var_type} {var_name}")
                        ref_ti.ReleaseVarDesc(vardesc)
                    except comtypes.COMError:
                        fields.append(f"? field{i}")

                ref_ti.ReleaseTypeAttr(ref_attr)
                if fields:
                    suffix = "*" if is_byref else ""
                    return f"struct {udt_name} {{ {'; '.join(fields)}; }}{suffix}"
                else:
                    suffix = "*" if is_byref else ""
                    return f"struct {udt_name}{suffix}"

            # TKIND_ENUM = enum
            elif type_kind == comtypes.typeinfo.TKIND_ENUM:
                # Just return enum name; values are rarely needed inline
                ref_ti.ReleaseTypeAttr(ref_attr)
                return f"enum {udt_name}"

            # TKIND_INTERFACE or TKIND_DISPATCH = interface pointer
            elif type_kind in (comtypes.typeinfo.TKIND_INTERFACE,
                               comtypes.typeinfo.TKIND_DISPATCH):
                ref_ti.ReleaseTypeAttr(ref_attr)
                return f"{udt_name}*"

            # TKIND_ALIAS = typedef
            elif type_kind == comtypes.typeinfo.TKIND_ALIAS:
                # Resolve the aliased type
                aliased = ref_attr.tdescAlias
                ref_ti.ReleaseTypeAttr(ref_attr)
                return resolve_type_deep(ref_ti, aliased, history_copy, depth + 1)

            # Other kinds - just return the name
            ref_ti.ReleaseTypeAttr(ref_attr)
            suffix = "*" if is_byref else ""
            return f"{udt_name}{suffix}"

        except comtypes.COMError:
            return f"UDT_hreftype_{tdesc.hreftype}"

    # Basic type lookup
    name = VT_MAP.get(base_vt, f"VT_0x{base_vt:X}")
    if is_byref and not name.endswith("*"):
        name = f"{name}*"
    return name


def format_guid_for_cpp(guid_str: Optional[str]) -> str:
    """Format GUID string as C++ initializer."""
    ZERO_GUID = "{0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}"
    if not guid_str or guid_str.lower().startswith("unknown"):
        return ZERO_GUID
    try:
        g = comtypes.GUID(guid_str)
        d4 = [g.Data4[i] & 0xFF for i in range(8)]
        return (f"{{0x{g.Data1:08X},0x{g.Data2:04X},0x{g.Data3:04X},"
                f"{{0x{d4[0]:02X},0x{d4[1]:02X},0x{d4[2]:02X},0x{d4[3]:02X},"
                f"0x{d4[4]:02X},0x{d4[5]:02X},0x{d4[6]:02X},0x{d4[7]:02X}}}}}")
    except (ValueError, Exception):
        return ZERO_GUID


def decode_sddl(sd_bytes: bytes) -> Optional[str]:
    """Convert binary security descriptor to SDDL string."""
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32
        sddl_ptr = ctypes.c_wchar_p()
        sddl_len = ctypes.c_ulong()
        # OWNER | GROUP | DACL
        if advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                ctypes.c_char_p(sd_bytes), 1, 0x7, ctypes.byref(sddl_ptr), ctypes.byref(sddl_len)):
            result = sddl_ptr.value
            kernel32.LocalFree(sddl_ptr)
            return result
    except Exception:
        pass
    return None


# =============================================================================
# Main Analyzer Class
# =============================================================================

class ComInterfaceAnalyzer:
    def __init__(self, executable_path: str = None, verbose: bool = False,
                 target_method_names: List[str] = None,
                 expected_decrypt_params: int = 3, expected_encrypt_params: int = 4,
                 log_file: str = None):
        self.executable_path = executable_path
        self.verbose = verbose
        self.type_lib = None
        self.results: List[AbeCandidate] = []
        self.discovered_clsid: Optional[str] = None
        self.browser_key: Optional[str] = None
        self.target_methods = target_method_names or ["DecryptData", "EncryptData"]
        self.expected_params = {"DecryptData": expected_decrypt_params,
                                "EncryptData": expected_encrypt_params}

        # Statistics
        self.start_time = None
        self.interfaces_scanned = 0
        self.interfaces_abe_capable = 0

        # Caches
        self.coclasses: List[CoclassInfo] = []
        self.proxy_stub_cache: Dict[str, ProxyStubInfo] = {}
        self.security_cache: Dict[str, ComSecurityInfo] = {}
        self.pe_info: Optional[PeTypelibInfo] = None

        # Setup logging
        self.logger = None
        if log_file:
            self.logger = logging.getLogger('ComradeABE')
            self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)
            handler = logging.FileHandler(log_file, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.logger.addHandler(handler)

    def _log(self, msg: str, indent: int = 0, verbose_only: bool = False, emoji: str = None):
        """Print and optionally log a message."""
        if verbose_only and not self.verbose:
            return
        prefix = f"{EMOJI.get(emoji, '')} " if emoji else ""
        print(f"{'  ' * indent}{prefix}{msg}")
        if self.logger:
            self.logger.log(logging.DEBUG if verbose_only else logging.INFO, msg)

    # -------------------------------------------------------------------------
    # Registry-based Discovery
    # -------------------------------------------------------------------------

    def find_service_details(self, browser_key: str) -> bool:
        """Find elevation service details from registry."""
        self.browser_key = browser_key.lower()
        self._log(f"Scanning registry for service details of '{self.browser_key}'...", emoji="search")

        # Find the actual service name
        candidates = BROWSER_SERVICES.get(self.browser_key, [browser_key])
        service_name = None
        for candidate in candidates:
            if reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                              rf"SYSTEM\CurrentControlSet\Services\{candidate}", "ImagePath"):
                service_name = candidate
                self._log(f"Found service: {candidate}", indent=1, verbose_only=True, emoji="info")
                break

        if not service_name:
            service_name = candidates[0] if candidates else browser_key
            self._log(f"No installed service found, trying: {service_name}", indent=1, verbose_only=True, emoji="warning")

        # Get executable path
        image_path = reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                                    rf"SYSTEM\CurrentControlSet\Services\{service_name}", "ImagePath")
        if image_path:
            self.executable_path = os.path.normpath(os.path.expandvars(clean_executable_path(image_path)))
            self._log(f"Service ImagePath: {self.executable_path}", indent=1, emoji="info")

        # Find CLSID via AppID LocalService
        self._find_clsid_for_service(service_name)

        if not self.executable_path:
            self._log(f"Failed to determine executable path for '{browser_key}'", indent=1, emoji="failure")
            return False
        return True

    def _find_clsid_for_service(self, service_name: str):
        """Find CLSID linked to a service via AppID."""
        self._log(f"Searching for CLSIDs linked to '{service_name}'...", indent=1, verbose_only=True, emoji="search")

        # Search AppID paths for LocalService match
        search_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\AppID"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Classes\AppID"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Classes\AppID"),
        ]

        for hkey, path in search_paths:
            for appid in reg_enum_subkeys(hkey, path):
                if not appid.startswith("{"):
                    continue
                local_svc = reg_read_value(hkey, rf"{path}\{appid}", "LocalService")
                if local_svc and local_svc.lower() == service_name.lower():
                    self.discovered_clsid = appid
                    self._log(f"Discovered CLSID: {self.discovered_clsid}", indent=1, emoji="success")
                    return

        # Fallback: search CLSID LocalServer32 for matching executable
        if self.executable_path:
            self._log("Fallback: searching CLSID LocalServer32...", indent=2, verbose_only=True)
            clsid_paths = [
                (winreg.HKEY_CLASSES_ROOT, "CLSID"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Classes\CLSID"),
            ]
            for hkey, path in clsid_paths:
                for clsid in reg_enum_subkeys(hkey, path):
                    if not clsid.startswith("{"):
                        continue
                    server_path = reg_read_value(hkey, rf"{path}\{clsid}\LocalServer32", None)
                    if server_path:
                        exe = clean_executable_path(server_path)
                        if exe.lower() == self.executable_path.lower():
                            self.discovered_clsid = clsid
                            self._log(f"Discovered CLSID via LocalServer32: {clsid}", indent=1, emoji="success")
                            return

    def discover_elevation_services(self) -> List[ElevationServiceInfo]:
        """Auto-discover all elevation services on the system."""
        self._log("Discovering all elevation services...", indent=1, emoji="search")
        services = []

        for svc_name in reg_enum_subkeys(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"):
            if "elevationservice" not in svc_name.lower():
                continue

            svc_path = rf"SYSTEM\CurrentControlSet\Services\{svc_name}"
            info = ElevationServiceInfo(service_name=svc_name)

            # Infer browser vendor
            name_lower = svc_name.lower()
            if "googlechrome" in name_lower:
                info.browser_vendor = "Chrome"
            elif "microsoftedge" in name_lower:
                info.browser_vendor = "Edge"
            elif "brave" in name_lower:
                info.browser_vendor = "Brave"
            elif "vivaldi" in name_lower:
                info.browser_vendor = "Vivaldi"
            elif "opera" in name_lower:
                info.browser_vendor = "Opera"
            else:
                info.browser_vendor = "Unknown"

            # Read service properties
            image_path = reg_read_value(winreg.HKEY_LOCAL_MACHINE, svc_path, "ImagePath")
            if image_path:
                info.executable_path = os.path.normpath(os.path.expandvars(clean_executable_path(image_path)))
            info.display_name = reg_read_value(winreg.HKEY_LOCAL_MACHINE, svc_path, "DisplayName")
            info.description = reg_read_value(winreg.HKEY_LOCAL_MACHINE, svc_path, "Description")
            start_val = reg_read_value(winreg.HKEY_LOCAL_MACHINE, svc_path, "Start")
            if start_val is not None:
                info.start_type = START_TYPE_MAP.get(start_val, f"Unknown({start_val})")

            # Get runtime status
            runtime = self.get_service_runtime_status(svc_name)
            info.status = runtime.status
            info.pid = runtime.pid

            services.append(info)
            self._log(f"Found: {svc_name} ({info.browser_vendor})", indent=2, emoji="success")

        self._log(f"Discovered {len(services)} elevation service(s)", indent=1, emoji="info")
        return services

    def get_service_runtime_status(self, service_name: str) -> ServiceRuntimeInfo:
        """Query service runtime status via SCM."""
        result = ServiceRuntimeInfo(service_name=service_name)
        try:
            advapi32 = ctypes.windll.advapi32
            SC_MANAGER_CONNECT = 0x0001
            SERVICE_QUERY_STATUS = 0x0004

            scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            if not scm:
                result.error = f"OpenSCManager failed: {ctypes.GetLastError()}"
                return result

            try:
                svc = advapi32.OpenServiceW(scm, service_name, SERVICE_QUERY_STATUS)
                if not svc:
                    result.error = f"OpenService failed: {ctypes.GetLastError()}"
                    return result

                try:
                    class SERVICE_STATUS_PROCESS(ctypes.Structure):
                        _fields_ = [
                            ("dwServiceType", ctypes.c_ulong),
                            ("dwCurrentState", ctypes.c_ulong),
                            ("dwControlsAccepted", ctypes.c_ulong),
                            ("dwWin32ExitCode", ctypes.c_ulong),
                            ("dwServiceSpecificExitCode", ctypes.c_ulong),
                            ("dwCheckPoint", ctypes.c_ulong),
                            ("dwWaitHint", ctypes.c_ulong),
                            ("dwProcessId", ctypes.c_ulong),
                            ("dwServiceFlags", ctypes.c_ulong),
                        ]

                    status = SERVICE_STATUS_PROCESS()
                    needed = ctypes.c_ulong()
                    if advapi32.QueryServiceStatusEx(svc, 0, ctypes.byref(status),
                                                      ctypes.sizeof(status), ctypes.byref(needed)):
                        state_map = {1: "stopped", 2: "start_pending", 3: "stop_pending",
                                     4: "running", 5: "continue_pending", 6: "pause_pending", 7: "paused"}
                        result.status = state_map.get(status.dwCurrentState, "unknown")
                        result.pid = status.dwProcessId if status.dwProcessId else None
                        result.can_stop = bool(status.dwControlsAccepted & 0x1)
                        result.can_pause = bool(status.dwControlsAccepted & 0x2)
                finally:
                    advapi32.CloseServiceHandle(svc)
            finally:
                advapi32.CloseServiceHandle(scm)
        except Exception as e:
            result.error = str(e)

        # Get start type from registry
        start_val = reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                                   rf"SYSTEM\CurrentControlSet\Services\{service_name}", "Start")
        if start_val is not None:
            result.start_type = START_TYPE_MAP.get(start_val, f"unknown({start_val})").lower()

        # Get dependencies
        deps = reg_read_value(winreg.HKEY_LOCAL_MACHINE,
                              rf"SYSTEM\CurrentControlSet\Services\{service_name}", "DependOnService")
        if deps:
            result.dependencies = list(deps) if isinstance(deps, (list, tuple)) else [deps]

        return result

    # -------------------------------------------------------------------------
    # TypeLib Search
    # -------------------------------------------------------------------------

    def search_typelibs_by_pattern(self, pattern: str) -> List[TypeLibRegistryInfo]:
        """Search for TypeLibs in registry matching a pattern."""
        self._log(f"Searching TypeLibs matching '{pattern}'...", indent=1, emoji="search")
        results = []
        pattern_lower = pattern.lower()

        for tl_id in reg_enum_subkeys(winreg.HKEY_CLASSES_ROOT, "TypeLib"):
            if not tl_id.startswith("{"):
                continue

            for version in reg_enum_subkeys(winreg.HKEY_CLASSES_ROOT, rf"TypeLib\{tl_id}"):
                name = reg_read_value(winreg.HKEY_CLASSES_ROOT, rf"TypeLib\{tl_id}\{version}", None)
                if not name or pattern_lower not in name.lower():
                    continue

                info = TypeLibRegistryInfo(typelib_id=tl_id, name=name, version=version)
                info.helpdir = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                              rf"TypeLib\{tl_id}\{version}", "HELPDIR")

                # Find paths
                for lcid in reg_enum_subkeys(winreg.HKEY_CLASSES_ROOT, rf"TypeLib\{tl_id}\{version}"):
                    if not lcid.isdigit():
                        continue
                    info.lcid = lcid
                    info.win32_path = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                     rf"TypeLib\{tl_id}\{version}\{lcid}\win32", None)
                    info.win64_path = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                     rf"TypeLib\{tl_id}\{version}\{lcid}\win64", None)
                    break

                results.append(info)
                self._log(f"Found: {name} ({tl_id} v{version})", indent=2, verbose_only=True, emoji="success")

        self._log(f"Found {len(results)} matching TypeLib(s)", indent=1, emoji="info")
        return results

    # -------------------------------------------------------------------------
    # COM Analysis
    # -------------------------------------------------------------------------

    def analyze_com_security(self, clsid: str) -> ComSecurityInfo:
        """Analyze COM security settings for a CLSID."""
        if clsid in self.security_cache:
            return self.security_cache[clsid]

        result = ComSecurityInfo(clsid=clsid)
        result.appid = reg_read_value(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}", "AppID")

        if result.appid:
            appid_path = rf"AppID\{result.appid}"
            result.runas = reg_read_value(winreg.HKEY_CLASSES_ROOT, appid_path, "RunAs")
            result.dll_surrogate = reg_read_value(winreg.HKEY_CLASSES_ROOT, appid_path, "DllSurrogate")
            result.local_service = reg_read_value(winreg.HKEY_CLASSES_ROOT, appid_path, "LocalService")

            # Read security descriptors
            try:
                access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, appid_path, 0, access) as key:
                    try:
                        perm = winreg.QueryValueEx(key, "LaunchPermission")[0]
                        result.has_launch_permission = True
                        result.launch_permission_size = len(perm)
                        result.launch_permission_sddl = decode_sddl(perm)
                    except FileNotFoundError:
                        pass
                    try:
                        perm = winreg.QueryValueEx(key, "AccessPermission")[0]
                        result.has_access_permission = True
                        result.access_permission_size = len(perm)
                        result.access_permission_sddl = decode_sddl(perm)
                    except FileNotFoundError:
                        pass
            except (FileNotFoundError, OSError):
                pass

        self.security_cache[clsid] = result
        return result

    def analyze_proxy_stub(self, iid: str) -> ProxyStubInfo:
        """Analyze proxy/stub registration for an interface."""
        if iid in self.proxy_stub_cache:
            return self.proxy_stub_cache[iid]

        result = ProxyStubInfo(iid=iid)
        iface_path = rf"Interface\{iid}"

        result.name = reg_read_value(winreg.HKEY_CLASSES_ROOT, iface_path, None)
        result.proxy_stub_clsid = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                  rf"{iface_path}\ProxyStubClsid32", None)

        if result.proxy_stub_clsid:
            result.marshaling_type = "custom"
            ps_path = rf"CLSID\{result.proxy_stub_clsid}\InprocServer32"
            result.proxy_stub_dll = reg_read_value(winreg.HKEY_CLASSES_ROOT, ps_path, None)
            if result.proxy_stub_dll and "oleaut32" in result.proxy_stub_dll.lower():
                result.marshaling_type = "oleautomation"
        else:
            # Check for TypeLib marshaling
            result.typelib_id = reg_read_value(winreg.HKEY_CLASSES_ROOT, rf"{iface_path}\TypeLib", None)
            if result.typelib_id:
                result.marshaling_type = "oleautomation"
                result.typelib_version = reg_read_value(winreg.HKEY_CLASSES_ROOT,
                                                        rf"{iface_path}\TypeLib", "Version")
            else:
                result.registered = False
                result.marshaling_type = "not registered"

        self.proxy_stub_cache[iid] = result
        return result

    def analyze_pe_typelib(self) -> PeTypelibInfo:
        """Analyze PE file for TypeLib resources."""
        result = PeTypelibInfo()
        if not pefile or not self.executable_path:
            return result

        try:
            pe = pefile.PE(self.executable_path, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'],
                                                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

            # Machine type
            machine_map = {0x8664: ("AMD64", "x64"), 0x14c: ("I386", "x86"),
                           0xaa64: ("ARM64", "ARM64"), 0x1c0: ("ARM", "ARM")}
            if pe.FILE_HEADER.Machine in machine_map:
                result.machine, result.machine_name = machine_map[pe.FILE_HEADER.Machine]
            else:
                result.machine = f"0x{pe.FILE_HEADER.Machine:04X}"
                result.machine_name = "Unknown"

            # Timestamp
            ts = pe.FILE_HEADER.TimeDateStamp
            result.timestamp = datetime.fromtimestamp(ts).isoformat() if ts else None

            # Check for TypeLib resource (RT_TYPELIB = 16)
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if entry.id == 16:
                        result.has_embedded_typelib = True
                        if hasattr(entry, 'directory'):
                            result.typelib_count = len(entry.directory.entries)
                        break

            # Check imports and detect hardening APIs
            # These APIs indicate how the service validates callers (path validation, signature checks)
            HARDENING_APIS = {
                "wintrust.dll": {
                    "WinVerifyTrust": "Code signature verification",
                    "WinVerifyTrustEx": "Extended signature verification",
                },
                "crypt32.dll": {
                    "CertGetCertificateChain": "Certificate chain validation",
                    "CertVerifyCertificateChainPolicy": "Certificate policy verification",
                    "CryptQueryObject": "Cryptographic object query",
                },
                "kernel32.dll": {
                    "GetModuleFileNameW": "Path retrieval (self)",
                    "GetModuleFileNameA": "Path retrieval (self)",
                    "K32GetModuleFileNameExW": "Path retrieval (external process)",
                    "K32GetModuleFileNameExA": "Path retrieval (external process)",
                    "GetProcessImageFileNameW": "Process image path",
                    "QueryFullProcessImageNameW": "Full process image path",
                    "QueryFullProcessImageNameA": "Full process image path",
                },
                "psapi.dll": {
                    "GetModuleFileNameExW": "Module path (external process)",
                    "GetModuleFileNameExA": "Module path (external process)",
                    "GetProcessImageFileNameW": "Process image path",
                    "GetProcessImageFileNameA": "Process image path",
                },
                "ntdll.dll": {
                    "NtQueryInformationProcess": "Process information query",
                    "ZwQueryInformationProcess": "Process information query (Zw)",
                },
                "advapi32.dll": {
                    "GetTokenInformation": "Token/privilege inspection",
                    "OpenProcessToken": "Process token access",
                    "CheckTokenMembership": "Token group membership check",
                },
            }

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore').lower()
                    result.imports.append(dll)
                    if 'rpcrt4' in dll:
                        result.uses_rpc = True
                    if 'ole32' in dll or 'oleaut32' in dll:
                        result.uses_ole = True

                    # Check for hardening APIs
                    if dll in HARDENING_APIS:
                        for imp in entry.imports:
                            if not imp.name:
                                continue
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            if func_name in HARDENING_APIS[dll]:
                                desc = HARDENING_APIS[dll][func_name]
                                result.hardening_apis.append(f"{dll}!{func_name} ({desc})")

            pe.close()
        except Exception as e:
            result.pe_error = str(e)

        self.pe_info = result
        return result

    def analyze_coclasses(self) -> List[CoclassInfo]:
        """Enumerate TKIND_COCLASS entries from TypeLib."""
        if not self.type_lib:
            return []

        self._log("Analyzing TKIND_COCLASS entries...", indent=1, emoji="gear")
        self.coclasses = []

        for i in range(self.type_lib.GetTypeInfoCount()):
            try:
                ti = self.type_lib.GetTypeInfo(i)
                attr = ti.GetTypeAttr()

                if attr.typekind != comtypes.typeinfo.TKIND_COCLASS:
                    ti.ReleaseTypeAttr(attr)
                    continue

                name, _, _, _ = ti.GetDocumentation(-1)
                clsid = str(attr.guid)

                coclass = CoclassInfo(name=name, clsid=clsid)

                # Get server info from registry
                for subkey in ["LocalServer32", "InprocServer32"]:
                    server_path = reg_read_value(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\{subkey}", None)
                    if server_path:
                        coclass.server_type = subkey
                        coclass.server_path = clean_executable_path(server_path)
                        coclass.threading_model = reg_read_value(
                            winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\{subkey}", "ThreadingModel")
                        break

                # Enumerate implemented interfaces
                for j in range(attr.cImplTypes):
                    try:
                        impl_flags = ti.GetImplTypeFlags(j)
                        ref_type = ti.GetRefTypeOfImplType(j)
                        impl_ti = ti.GetRefTypeInfo(ref_type)
                        impl_name, _, _, _ = impl_ti.GetDocumentation(-1)
                        impl_attr = impl_ti.GetTypeAttr()

                        coclass.implemented_interfaces.append({
                            "name": impl_name,
                            "iid": str(impl_attr.guid),
                            "is_default": bool(impl_flags & 0x1),
                            "is_source": bool(impl_flags & 0x2),
                        })
                        impl_ti.ReleaseTypeAttr(impl_attr)
                    except comtypes.COMError:
                        pass

                self.coclasses.append(coclass)
                ti.ReleaseTypeAttr(attr)

            except comtypes.COMError:
                pass

        self._log(f"Found {len(self.coclasses)} coclass(es)", indent=1, emoji="info")
        return self.coclasses

    # -------------------------------------------------------------------------
    # TypeLib Loading and Interface Analysis
    # -------------------------------------------------------------------------

    def load_type_library(self) -> bool:
        """Load type library from executable."""
        if not self.executable_path:
            self._log("No executable path specified", emoji="failure")
            return False

        self._log(f"Attempting to load type library from: {self.executable_path}", emoji="search")
        try:
            self.type_lib = comtypes.typeinfo.LoadTypeLibEx(self.executable_path)
            name, _, _, _ = self.type_lib.GetDocumentation(-1)
            self._log(f"Successfully loaded type library: '{name}'", emoji="success")
            return True
        except comtypes.COMError as e:
            self._log(f"Failed to load type library: {e}", emoji="failure")
            return False

    def get_inheritance_chain(self, ti: comtypes.typeinfo.ITypeInfo) -> List[InterfaceInfo]:
        """Build inheritance chain for an interface."""
        chain = []
        visited = set()

        def trace(type_info):
            try:
                attr = type_info.GetTypeAttr()
                iid = str(attr.guid)

                if iid in visited:
                    type_info.ReleaseTypeAttr(attr)
                    return
                visited.add(iid)

                name, _, _, _ = type_info.GetDocumentation(-1)

                # Get base interface
                base_name = "IUnknown"
                if attr.cImplTypes > 0:
                    try:
                        ref = type_info.GetRefTypeOfImplType(0)
                        base_ti = type_info.GetRefTypeInfo(ref)
                        base_name, _, _, _ = base_ti.GetDocumentation(-1)
                        trace(base_ti)
                    except comtypes.COMError:
                        pass

                # Parse methods
                methods = []
                for i in range(attr.cFuncs):
                    try:
                        fd = type_info.GetFuncDesc(i)
                        names = type_info.GetNames(fd.memid, fd.cParams + 1)
                        method_name = names[0] if names else f"Method{i}"

                        # Build parameter list with direction flags and deep type resolution
                        params = []
                        for p in range(fd.cParams):
                            pname = names[p + 1] if len(names) > p + 1 else f"p{p}"
                            tdesc = fd.lprgelemdescParam[p].tdesc
                            pflags = fd.lprgelemdescParam[p]._.paramdesc.wParamFlags
                            # Use deep type resolution to expand structs/enums
                            ptype = resolve_type_deep(type_info, tdesc)
                            flags_str = get_param_flags_string(pflags)
                            if flags_str:
                                params.append(f"[{flags_str}] {ptype} {pname}")
                            else:
                                params.append(f"{ptype} {pname}")

                        ret_tdesc = fd.elemdescFunc.tdesc
                        ret_type = resolve_type_deep(type_info, ret_tdesc)

                        methods.append(MethodDetail(
                            name=method_name, ret_type=ret_type, params=params,
                            ovft=fd.oVft, memid=fd.memid, index_in_interface=i
                        ))
                        type_info.ReleaseFuncDesc(fd)
                    except comtypes.COMError:
                        pass

                chain.append(InterfaceInfo(
                    name=name, iid=iid, type_info_obj=type_info, type_attr_obj=attr,
                    methods_defined=methods, base_interface_name=base_name
                ))

            except comtypes.COMError:
                pass

        trace(ti)
        return chain

    def check_method_signature(self, method_name: str, fd, ti) -> bool:
        """Check if a method matches expected ABE signature."""
        expected = self.expected_params.get(method_name)
        if expected is None:
            return True

        if fd.cParams != expected:
            return False
        if fd.elemdescFunc.tdesc.vt != comtypes.automation.VT_HRESULT:
            return False

        if method_name == "DecryptData" and fd.cParams == 3:
            # BSTR in, BSTR* out, ULONG* out
            p0 = fd.lprgelemdescParam[0]
            if p0.tdesc.vt != comtypes.automation.VT_BSTR:
                return False
            if not (p0._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FIN):
                return False
        elif method_name == "EncryptData" and fd.cParams == 4:
            # First param should be in
            p0 = fd.lprgelemdescParam[0]
            if not (p0._.paramdesc.wParamFlags & comtypes.typeinfo.PARAMFLAG_FIN):
                return False

        return True

    def analyze_interfaces(self):
        """Analyze all interfaces in the TypeLib for ABE capability."""
        if not self.type_lib:
            return

        self._log("Analyzing all TKIND_INTERFACE entries from TypeLib...", indent=1, emoji="gear")
        count = self.type_lib.GetTypeInfoCount()
        self._log(f"Found {count} type definitions to scan", indent=1, emoji="info")

        for i in range(count):
            try:
                ti = self.type_lib.GetTypeInfo(i)
                attr = ti.GetTypeAttr()

                if attr.typekind != comtypes.typeinfo.TKIND_INTERFACE:
                    ti.ReleaseTypeAttr(attr)
                    continue

                self.interfaces_scanned += 1
                name, _, _, _ = ti.GetDocumentation(-1)
                iid = str(attr.guid)

                self._log(f"Scanning Interface: '{name}' (IID: {iid})", indent=2, verbose_only=True)

                # Get inheritance chain and check for target methods
                chain = self.get_inheritance_chain(ti)
                found_methods = {}

                for iface in chain:
                    for method in iface.methods_defined:
                        if method.name in self.target_methods:
                            # Verify signature
                            for j in range(iface.type_attr_obj.cFuncs):
                                try:
                                    fd = iface.type_info_obj.GetFuncDesc(j)
                                    names = iface.type_info_obj.GetNames(fd.memid, 1)
                                    if names and names[0] == method.name:
                                        if self.check_method_signature(method.name, fd, iface.type_info_obj):
                                            found_methods[method.name] = AnalyzedMethod(
                                                name=method.name, ovft=method.ovft, memid=method.memid,
                                                defining_interface_name=iface.name,
                                                defining_interface_iid=iface.iid
                                            )
                                            self._log(f"'{method.name}' matched in '{iface.name}'",
                                                      indent=4, verbose_only=True, emoji="lightbulb")
                                    iface.type_info_obj.ReleaseFuncDesc(fd)
                                except comtypes.COMError:
                                    pass

                # Check if all target methods found
                if all(m in found_methods for m in self.target_methods):
                    self.interfaces_abe_capable += 1
                    self.results.append(AbeCandidate(
                        clsid=self.discovered_clsid or "Unknown",
                        interface_name=name, interface_iid=iid,
                        methods=found_methods, inheritance_chain_info=chain
                    ))
                    self._log(f"Found ABE-capable: '{name}' (IID: {iid})", indent=2, emoji="info")

                ti.ReleaseTypeAttr(attr)

            except comtypes.COMError:
                pass

    # -------------------------------------------------------------------------
    # Main Analysis Entry Point
    # -------------------------------------------------------------------------

    def analyze(self, scan_mode: bool = False, browser_key: str = None, user_clsid: str = None):
        """Main analysis entry point."""
        comtypes.CoInitialize()
        self.start_time = time.time()

        try:
            if scan_mode and browser_key:
                self._log(f"Scan mode enabled for: {browser_key}", emoji="gear")
                if not self.find_service_details(browser_key):
                    return

            if user_clsid:
                self.discovered_clsid = user_clsid

            # PE analysis
            if self.executable_path and pefile:
                self._log("Analyzing PE structure...", indent=1, emoji="gear")
                pe_info = self.analyze_pe_typelib()
                if pe_info.machine_name:
                    self._log(f"PE Architecture: {pe_info.machine_name}", indent=2, verbose_only=True, emoji="info")

            # Load TypeLib
            if not self.load_type_library():
                return

            # Analyze coclasses
            self.analyze_coclasses()

            # Analyze interfaces
            self.analyze_interfaces()

            # Analyze security
            if self.discovered_clsid:
                self._log("Analyzing COM security settings...", indent=1, emoji="gear")
                sec = self.analyze_com_security(self.discovered_clsid)
                if sec.local_service:
                    self._log(f"LocalService: {sec.local_service}", indent=2, verbose_only=True, emoji="info")

            # Analyze proxy/stub for results
            if self.results:
                self._log("Analyzing proxy/stub registration...", indent=1, emoji="gear")
                for r in self.results:
                    ps = self.analyze_proxy_stub(r.interface_iid)
                    self._log(f"{r.interface_name}: {ps.marshaling_type}", indent=2, verbose_only=True, emoji="info")

        finally:
            comtypes.CoUninitialize()

    # -------------------------------------------------------------------------
    # Output Methods
    # -------------------------------------------------------------------------

    def calculate_vtable_layout(self, chain: List[InterfaceInfo]) -> List[VtableSlotInfo]:
        """Calculate vtable layout from inheritance chain."""
        slots = []
        current_slot = 0

        for iface in reversed(chain):
            for method in iface.methods_defined:
                slots.append(VtableSlotInfo(
                    method_name=method.name, slot_index=current_slot,
                    offset_x64=current_slot * 8, offset_x86=current_slot * 4,
                    defining_interface=iface.name, memid=method.memid
                ))
                current_slot += 1

        return slots

    def export_to_json(self, output_file: str) -> bool:
        """Export analysis results to JSON."""
        if not self.results:
            self._log("No results to export", emoji="failure")
            return False

        try:
            data = {
                "metadata": {
                    "tool": "COMrade ABE Analyzer",
                    "version": "2.0.0",
                    "timestamp": datetime.now().isoformat(),
                    "duration_seconds": time.time() - self.start_time if self.start_time else 0,
                    "browser": self.browser_key or "unknown",
                    "executable": self.executable_path or "unknown"
                },
                "statistics": {
                    "interfaces_scanned": self.interfaces_scanned,
                    "abe_capable_found": self.interfaces_abe_capable,
                    "coclasses_found": len(self.coclasses),
                    "target_methods": self.target_methods
                },
                "discovered_clsid": self.discovered_clsid or "Unknown",
            }

            # PE info
            if self.pe_info:
                data["pe_info"] = {
                    "machine": self.pe_info.machine,
                    "machine_name": self.pe_info.machine_name,
                    "timestamp": self.pe_info.timestamp,
                    "has_typelib": self.pe_info.has_embedded_typelib,
                    "uses_rpc": self.pe_info.uses_rpc,
                    "uses_ole": self.pe_info.uses_ole,
                    "hardening_apis": self.pe_info.hardening_apis,
                }

            # Security info
            if self.discovered_clsid:
                sec = self.analyze_com_security(self.discovered_clsid)
                data["security_info"] = {
                    "appid": sec.appid,
                    "local_service": sec.local_service,
                    "runas": sec.runas,
                    "launch_permission_sddl": sec.launch_permission_sddl,
                    "access_permission_sddl": sec.access_permission_sddl,
                }

                if sec.local_service:
                    rt = self.get_service_runtime_status(sec.local_service)
                    data["service_runtime"] = {
                        "status": rt.status, "pid": rt.pid,
                        "start_type": rt.start_type, "dependencies": rt.dependencies,
                    }

            # Results
            data["results"] = []
            for r in self.results:
                vtable = self.calculate_vtable_layout(r.inheritance_chain_info)
                ps = self.analyze_proxy_stub(r.interface_iid)

                data["results"].append({
                    "interface_name": r.interface_name,
                    "interface_iid": r.interface_iid,
                    "clsid": r.clsid,
                    "methods": {name: {"vtable_offset": m.ovft, "memid": m.memid,
                                        "defining_interface": m.defining_interface_name}
                                for name, m in r.methods.items()},
                    "inheritance_chain": [{"name": i.name, "iid": i.iid,
                                           "base": i.base_interface_name,
                                           "methods_count": len(i.methods_defined)}
                                          for i in r.inheritance_chain_info],
                    "proxy_stub": {"type": ps.marshaling_type, "registered": ps.registered},
                    "vtable_slots": len(vtable),
                })

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            self._log(f"Exported to: {output_file}", emoji="file")
            return True

        except Exception as e:
            self._log(f"Export failed: {e}", emoji="failure")
            return False

    def generate_cpp_stubs(self, chain: List[InterfaceInfo], main_iid: str) -> str:
        """Generate C++ interface stubs."""
        output = ""
        processed = set()

        for iface in reversed(chain):
            if iface.iid in processed:
                continue
            processed.add(iface.iid)

            output += f'MIDL_INTERFACE("{iface.iid}") // {format_guid_for_cpp(iface.iid)}\n'
            output += f"{iface.name} : public {iface.base_interface_name}\n{{\npublic:\n"

            if not iface.methods_defined:
                if iface.name == "IUnknown":
                    output += "    // Standard IUnknown methods\n"
                else:
                    output += "    // No methods defined\n"
            else:
                for m in iface.methods_defined:
                    params = ", ".join(m.params) if m.params else "void"
                    output += f"    virtual {m.ret_type} STDMETHODCALLTYPE {m.name}({params}) = 0;\n"

            output += "};\n\n"

        return output

    def print_results(self, output_cpp_file: str = None, show_sddl: bool = False,
                      show_service_status: bool = False):
        """Print analysis results."""
        if not self.results:
            self._log("No ABE Interface candidates found.", emoji="failure")
            return

        browser = (self.browser_key or "unknown").capitalize()
        exe = self.executable_path or "N/A"
        clsid = self.results[0].clsid

        print(f"\n--- {EMOJI['lightbulb']} Analysis Summary ---")
        print(f"  Browser Target    : {browser}")
        print(f"  Service Executable: {exe}")
        print(f"  Discovered CLSID  : {clsid}")
        print(f"      (C++ Style)   : {format_guid_for_cpp(clsid)}")

        # Statistics
        if self.start_time:
            duration = time.time() - self.start_time
            print(f"\n  {EMOJI['gear']} Statistics:")
            print(f"    Analysis Duration : {duration:.2f} seconds")
            print(f"    Interfaces Scanned: {self.interfaces_scanned}")
            print(f"    ABE-Capable Found : {self.interfaces_abe_capable}")
            print(f"    Coclasses Found   : {len(self.coclasses)}")
            if self.interfaces_scanned > 0:
                print(f"    Success Rate      : {(self.interfaces_abe_capable / self.interfaces_scanned) * 100:.1f}%")

        # PE info
        if self.pe_info and not self.pe_info.pe_error:
            print(f"\n  {EMOJI['file']} PE Information:")
            print(f"    Architecture      : {self.pe_info.machine_name}")
            print(f"    Build Timestamp   : {self.pe_info.timestamp}")
            print(f"    Embedded TypeLib  : {'Yes' if self.pe_info.has_embedded_typelib else 'No'}")
            print(f"    Uses RPC Runtime  : {'Yes' if self.pe_info.uses_rpc else 'No'}")
            print(f"    Uses OLE/OleAut   : {'Yes' if self.pe_info.uses_ole else 'No'}")

            # Show hardening APIs (security validation mechanisms)
            if self.pe_info.hardening_apis:
                print(f"\n  {EMOJI['warning']} Hardening APIs Detected ({len(self.pe_info.hardening_apis)}):")
                for api in self.pe_info.hardening_apis:
                    print(f"    - {api}")

        # Security info
        if self.discovered_clsid:
            sec = self.analyze_com_security(self.discovered_clsid)
            if sec.appid or sec.local_service or sec.runas:
                print(f"\n  {EMOJI['gear']} COM Security Settings:")
                if sec.appid:
                    print(f"    AppID             : {sec.appid}")
                if sec.local_service:
                    print(f"    LocalService      : {sec.local_service}")
                    if show_service_status:
                        rt = self.get_service_runtime_status(sec.local_service)
                        status_emoji = EMOJI['success'] if rt.status == "running" else EMOJI['info']
                        pid_str = f" (PID: {rt.pid})" if rt.pid else ""
                        print(f"    Service Status    : {status_emoji} {rt.status}{pid_str}")
                        print(f"    Service Start Type: {rt.start_type}")
                if sec.runas:
                    print(f"    RunAs             : {sec.runas}")
                if sec.has_launch_permission:
                    print(f"    LaunchPermission  : Set ({sec.launch_permission_size} bytes)")
                    if show_sddl and sec.launch_permission_sddl:
                        print(f"      SDDL: {sec.launch_permission_sddl}")
                if sec.has_access_permission:
                    print(f"    AccessPermission  : Set ({sec.access_permission_size} bytes)")
                    if show_sddl and sec.access_permission_sddl:
                        print(f"      SDDL: {sec.access_permission_sddl}")

        # Coclasses
        if self.coclasses and self.verbose:
            print(f"\n  {EMOJI['gear']} Coclasses ({len(self.coclasses)}):")
            for cc in self.coclasses:
                print(f"    {cc.name}: {cc.clsid}")

        # Results
        print(f"\n  Found {len(self.results)} ABE-Capable Interface(s):")

        # Find primary candidate
        primary_iid = KNOWN_PRIMARY_IIDS.get(self.browser_key, "").lower()
        primary = self.results[0]
        for r in self.results:
            if r.interface_iid.lower() == primary_iid:
                primary = r
                break

        for i, r in enumerate(self.results):
            is_primary = r.interface_iid.lower() == primary.interface_iid.lower()
            marker = f" {EMOJI['lightbulb']} (Likely primary for tool)" if is_primary else ""
            print(f"\n  Candidate {i + 1}:{marker}")
            print(f"    Interface Name: {r.interface_name}")
            print(f"    IID           : {r.interface_iid}")
            print(f"      (C++ Style) : {format_guid_for_cpp(r.interface_iid)}")

        # Verbose details
        if self.verbose:
            print(f"\n--- {EMOJI['info']} Verbose Candidate Details ---")
            for i, r in enumerate(self.results):
                print(f"\n  --- Candidate {i + 1}: '{r.interface_name}' ---")
                print(f"    Methods (ABE):")
                for name, m in r.methods.items():
                    slot = m.ovft // 8
                    print(f"      - {name}: VTable Offset {m.ovft} (Slot ~{slot}), in '{m.defining_interface_name}'")
                print(f"    Inheritance: {' -> '.join(iface.name for iface in reversed(r.inheritance_chain_info))}")
                for iface in reversed(r.inheritance_chain_info):
                    print(f"      {iface.name} (IID: {iface.iid}) - {len(iface.methods_defined)} method(s)")
                    for m in iface.methods_defined:
                        params = ', '.join(m.params) if m.params else 'void'
                        print(f"        - {m.ret_type} {m.name}({params}) (oVft: {m.ovft})")
            print("--- End Verbose Details ---")

        # Generate C++ stubs
        if output_cpp_file:
            self._log(f"\nGenerating C++ stubs for '{primary.interface_name}'...", emoji="gear")
            header = f"// COM Stubs for {browser}\n// Generated by COMrade ABE Analyzer\n"
            header += f"// CLSID: {format_guid_for_cpp(primary.clsid)}\n"
            header += f"// IID: {format_guid_for_cpp(primary.interface_iid)}\n\n"
            content = self.generate_cpp_stubs(primary.inheritance_chain_info, primary.interface_iid)
            try:
                with open(output_cpp_file, 'w', encoding='utf-8') as f:
                    f.write(header + content)
                self._log(f"C++ stubs written to: {output_cpp_file}", emoji="success")
            except IOError as e:
                self._log(f"Error writing stubs: {e}", emoji="failure")

    def compare_interfaces(self, other_json: str) -> Dict[str, Any]:
        """Compare current results with a previous JSON export."""
        try:
            with open(other_json, 'r', encoding='utf-8') as f:
                other = json.load(f)
        except Exception as e:
            return {"error": str(e)}

        diff = {
            "added_interfaces": [], "removed_interfaces": [],
            "method_changes": [], "vtable_offset_changes": []
        }

        current = {r.interface_iid.lower(): r for r in self.results}
        other_results = {r["interface_iid"].lower(): r for r in other.get("results", [])}

        for iid, r in current.items():
            if iid not in other_results:
                diff["added_interfaces"].append({"name": r.interface_name, "iid": r.interface_iid})

        for iid, r in other_results.items():
            if iid not in current:
                diff["removed_interfaces"].append({"name": r["interface_name"], "iid": r["interface_iid"]})

        return diff


# =============================================================================
# CLI Entry Point
# =============================================================================

def print_banner():
    print(r"""
-------------------------------------------------------------------------------------------

_________  ________      _____                    .___          _____ _____________________
\_   ___ \ \_____  \    /     \____________     __| _/____     /  _  \\______   \_   _____/
/    \  \/  /   |   \  /  \ /  \_  __ \__  \   / __ |/ __ \   /  /_\  \|    |  _/|    __)_
\     \____/    |    \/    Y    \  | \// __ \_/ /_/ \  ___/  /    |    \    |   \|        \
 \______  /\_______  /\____|__  /__|  (____  /\____ |\___  > \____|__  /______  /_______  /
        \/         \/         \/           \/      \/    \/          \/       \/        \/

                  by Alexander 'xaitax' Hagenah
-------------------------------------------------------------------------------------------
    """)


def main():
    print_banner()

    examples = """
Examples:
  %(prog)s chrome                    Analyze Chrome elevation service
  %(prog)s edge -d                   Analyze Edge with SDDL + service details
  %(prog)s brave -v -o out.json      Verbose analysis, export to JSON
  %(prog)s discover                  List all elevation services
  %(prog)s search Google             Search TypeLibs by name
  %(prog)s chrome --compare old.json Compare with previous analysis
  %(prog)s "C:\\path\\to\\exe"         Analyze specific executable
"""

    parser = argparse.ArgumentParser(
        usage="%(prog)s <target> [options]",
        description="COMrade ABE: Discover and analyze COM ABE interfaces in Chromium browsers.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=examples
    )

    # Positional arguments
    parser.add_argument("target", metavar="TARGET",
                        help="chrome|edge|brave, 'discover', 'search', or path to executable")
    parser.add_argument("pattern", nargs="?", default=None,
                        help="Search pattern (only used with 'search' command)")

    # Common options
    parser.add_argument("-d", "--details", action="store_true",
                        help="Show SDDL and service status details")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Export results to JSON")
    parser.add_argument("--cpp", metavar="FILE",
                        help="Generate C++ interface stubs")
    parser.add_argument("--compare", metavar="FILE",
                        help="Compare with previous JSON export")
    parser.add_argument("--clsid", metavar="CLSID",
                        help="Manually specify CLSID")
    parser.add_argument("--log", metavar="FILE",
                        help="Write logs to file")

    # Advanced options (hidden from main help)
    advanced = parser.add_argument_group("advanced options")
    advanced.add_argument("--methods", default="DecryptData,EncryptData",
                          help=argparse.SUPPRESS)
    advanced.add_argument("--decrypt-params", type=int, default=3,
                          help=argparse.SUPPRESS)
    advanced.add_argument("--encrypt-params", type=int, default=4,
                          help=argparse.SUPPRESS)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if sys.platform != "win32":
        print(f"{EMOJI['failure']} This script requires Windows.")
        sys.exit(1)

    print(f"{EMOJI['gear']} COM ABE Interface Analyzer Initializing...")

    analyzer = ComInterfaceAnalyzer(
        verbose=args.verbose,
        target_method_names=[m.strip() for m in args.methods.split(',')],
        expected_decrypt_params=args.decrypt_params,
        expected_encrypt_params=args.encrypt_params,
        log_file=args.log
    )

    target_lower = args.target.lower()
    browser_keys = ["chrome", "edge", "brave"]

    # Command: discover
    if target_lower == "discover":
        print(f"\n{EMOJI['search']} Discovering all elevation services...")
        comtypes.CoInitialize()
        try:
            services = analyzer.discover_elevation_services()
            if services:
                print(f"\n{EMOJI['success']} Found {len(services)} elevation service(s):\n")
                for svc in services:
                    print(f"  {EMOJI['gear']} {svc.service_name}")
                    print(f"      Browser Vendor : {svc.browser_vendor}")
                    if svc.display_name:
                        print(f"      Display Name   : {svc.display_name}")
                    if svc.executable_path:
                        print(f"      Executable     : {svc.executable_path}")
                    if svc.start_type:
                        print(f"      Start Type     : {svc.start_type}")
                    if svc.status:
                        emoji = EMOJI['success'] if svc.status == "running" else EMOJI['info']
                        pid = f" (PID: {svc.pid})" if svc.pid else ""
                        print(f"      Status         : {emoji} {svc.status}{pid}")
                    print()
            else:
                print(f"{EMOJI['warning']} No elevation services found.")
        finally:
            comtypes.CoUninitialize()
        print(f"{EMOJI['success']} Discovery complete.")
        sys.exit(0)

    # Command: search <pattern>
    if target_lower == "search":
        if not args.pattern:
            parser.error("'search' requires a pattern. Usage: comrade_abe.py search <pattern>")
        print(f"\n{EMOJI['search']} Searching TypeLibs matching '{args.pattern}'...")
        comtypes.CoInitialize()
        try:
            typelibs = analyzer.search_typelibs_by_pattern(args.pattern)
            if typelibs:
                print(f"\n{EMOJI['success']} Found {len(typelibs)} matching TypeLib(s):\n")
                for tl in typelibs:
                    print(f"  {EMOJI['file']} {tl.name}")
                    print(f"      TypeLib ID : {tl.typelib_id}")
                    print(f"      Version    : {tl.version}")
                    if tl.win64_path:
                        print(f"      Win64 Path : {tl.win64_path}")
                    elif tl.win32_path:
                        print(f"      Win32 Path : {tl.win32_path}")
                    print()
            else:
                print(f"{EMOJI['warning']} No TypeLibs found matching '{args.pattern}'.")
        finally:
            comtypes.CoUninitialize()
        print(f"{EMOJI['success']} TypeLib search complete.")
        sys.exit(0)

    # Browser scan (chrome/edge/brave)
    if target_lower in browser_keys:
        analyzer.analyze(scan_mode=True, browser_key=args.target, user_clsid=args.clsid)
    # Direct executable path
    elif os.path.exists(args.target):
        analyzer.executable_path = args.target
        if args.clsid:
            analyzer.discovered_clsid = args.clsid
            analyzer.browser_key = "manual"
        analyzer.analyze(user_clsid=args.clsid)
    else:
        parser.error(f"Unknown target '{args.target}'. Use chrome|edge|brave, 'discover', 'search', or a valid path.")

    # Print results
    analyzer.print_results(
        output_cpp_file=args.cpp,
        show_sddl=args.details,
        show_service_status=args.details
    )

    # Export JSON
    if args.output and analyzer.results:
        analyzer.export_to_json(args.output)

    # Compare with previous
    if args.compare and analyzer.results:
        print(f"\n{EMOJI['search']} Comparing with: {args.compare}")
        if os.path.exists(args.compare):
            diff = analyzer.compare_interfaces(args.compare)
            if "error" in diff:
                print(f"  {EMOJI['failure']} Error: {diff['error']}")
            elif not any(diff.values()):
                print(f"  {EMOJI['success']} No changes detected.")
            else:
                print(f"\n  {EMOJI['warning']} Changes detected:")
                for iface in diff.get("added_interfaces", []):
                    print(f"    + {iface['name']} ({iface['iid']})")
                for iface in diff.get("removed_interfaces", []):
                    print(f"    - {iface['name']} ({iface['iid']})")
        else:
            print(f"  {EMOJI['failure']} File not found: {args.compare}")

    print(f"\n{EMOJI['success']} Analysis complete.")


if __name__ == "__main__":
    main()
