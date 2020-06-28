# pylint: disable=C0301,C0103

# ==============================================================================
# AfxMSGMap plugin for IDA
# Copyright (c) 2018
# Snow 85703533
# Port to IDA 7x by HTC - VinCSS (a member of Vingroup)
# All rights reserved.
#
# ==============================================================================

import idautils
import idaapi
import idc
import ida_segment
import ida_struct
import ida_nalt
import ida_typeinf

plugin_initialized = False

class AFXMSGMAPSearchResultChooser(idaapi.Choose):
    def __init__(self, title, items, flags=0, width=None, height=None, embedded=False):
        idaapi.Choose.__init__(self,
                               title,
                               [["Index", idaapi.Choose.CHCOL_PLAIN|6],
                                ["Address", idaapi.Choose.CHCOL_HEX|20],
                                ["Name", idaapi.Choose.CHCOL_HEX|40],
                                ["Entry Num", idaapi.Choose.CHCOL_HEX|10],],
            flags=flags,
            width=width,
            height=height,
            embedded=embedded)
        self.items = items
        self.selcount = 0
        self.n = len(items)

    def OnClose(self):
        return

    def OnSelectLine(self, n):
        self.selcount += 1
        idc.jumpto(self.items[n][1])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [str(res[0]), int(res[1]), res[2], str(res[3])]
        return res

    def OnGetSize(self):
        n = len(self.items)
        return n

    def show(self):
        return self.Show() >= 0


class AfxMSGMap(object):

    def __init__(self):
        self.cmin = 0
        self.cmax = 0
        self.rmin = 0
        self.rmax = 0
        self.dmin = 0
        self.dmax = 0
        self.msg_enum = 0
        self.MSGStructSize = 24
        self.USize = 4
        if idc.__EA64__:
            self.MSGStructSize = 32
            self.USize = 8

    @staticmethod
    def mt_rva():
        ri = ida_nalt.refinfo_t()
        if idc.__EA64__:
            ri.flags = idc.REF_OFF64
        else:
            ri.flags = idc.REF_OFF32
        ri.target = idc.BADADDR
        mt = ida_nalt.opinfo_t()
        mt.ri = ri
        return mt

    @staticmethod
    def mt_ascii():
        ri = ida_nalt.refinfo_t()
        ri.flags = ida_nalt.STRTYPE_C
        ri.target = idc.BADADDR
        mt = ida_nalt.opinfo_t()
        mt.ri = ri
        return mt

    def AddMSGMAPStruct(self):
        name = "AFX_MSGMAP_ENTRY"
        idx = idaapi.get_struc_id(name)
        stru = idaapi.get_struc(idx)
        if idx != idc.BADADDR:
            idaapi.del_struc(stru)

        idx = idaapi.add_struc(idc.BADADDR, name)
        stru = idaapi.get_struc(idx)

        idaapi.add_struc_member(stru, "nMessage", 0, idc.FF_DATA | idc.FF_DWORD, None, 4)
        idaapi.add_struc_member(stru, "nCode", 4, idc.FF_DATA | idc.FF_DWORD, None, 4)
        idaapi.add_struc_member(stru, "nID", 8, idc.FF_DATA | idc.FF_DWORD, None, 4)
        idaapi.add_struc_member(stru, "nLastID", 12, idc.FF_DATA | idc.FF_DWORD, None, 4)

        if idc.__EA64__:
            idaapi.add_struc_member(stru, "nSig", 16, idc.FF_DATA | idc.FF_QWORD, None, 8)
            idaapi.add_struc_member(stru, "pfn", 24, idc.FF_DATA | idc.FF_DWORD | idc.FF_0OFF, self.mt_rva(), 8)
        else:
            idaapi.add_struc_member(stru, "nSig", 16, idc.FF_DATA | idc.FF_DWORD, None, 4)
            idaapi.add_struc_member(stru, "pfn", 20, idc.FF_DATA | idc.FF_DWORD | idc.FF_0OFF, self.mt_rva(), 4)

        return 0

    @staticmethod
    def GetMsgName(msgid):
        MSG_TABLES = {
            0x0000: "WM_NULL",
            0x0001: "WM_CREATE",
            0x0002: "WM_DESTROY",
            0x0003: "WM_MOVE",
            0x0004: "WM_SIZEWAIT",
            0x0005: "WM_SIZE",
            0x0006: "WM_ACTIVATE",
            0x0007: "WM_SETFOCUS",
            0x0008: "WM_KILLFOCUS",
            0x0009: "WM_SETVISIBLE",
            0x000a: "WM_ENABLE",
            0x000b: "WM_SETREDRAW",
            0x000c: "WM_SETTEXT",
            0x000d: "WM_GETTEXT",
            0x000e: "WM_GETTEXTLENGTH",
            0x000f: "WM_PAINT",
            0x0010: "WM_CLOSE",
            0x0011: "WM_QUERYENDSESSION",
            0x0012: "WM_QUIT",
            0x0013: "WM_QUERYOPEN",
            0x0014: "WM_ERASEBKGND",
            0x0015: "WM_SYSCOLORCHANGE",
            0x0016: "WM_ENDSESSION",
            0x0017: "WM_SYSTEMERROR",
            0x0018: "WM_SHOWWINDOW",
            0x0019: "WM_CTLCOLOR",
            0x001a: "WM_WININICHANGE",
            0x001b: "WM_DEVMODECHANGE",
            0x001c: "WM_ACTIVATEAPP",
            0x001d: "WM_FONTCHANGE",
            0x001e: "WM_TIMECHANGE",
            0x001f: "WM_CANCELMODE",
            0x0020: "WM_SETCURSOR",
            0x0021: "WM_MOUSEACTIVATE",
            0x0022: "WM_CHILDACTIVATE",
            0x0023: "WM_QUEUESYNC",
            0x0024: "WM_GETMINMAXINFO",
            0x0025: "WM_LOGOFF",
            0x0026: "WM_PAINTICON",
            0x0027: "WM_ICONERASEBKGND",
            0x0028: "WM_NEXTDLGCTL",
            0x0029: "WM_ALTTABACTIVE",
            0x002a: "WM_SPOOLERSTATUS",
            0x002b: "WM_DRAWITEM",
            0x002c: "WM_MEASUREITEM",
            0x002d: "WM_DELETEITEM",
            0x002e: "WM_VKEYTOITEM",
            0x002f: "WM_CHARTOITEM",
            0x0030: "WM_SETFONT",
            0x0031: "WM_GETFONT",
            0x0032: "WM_SETHOTKEY",
            0x0033: "WM_GETHOTKEY",
            0x0034: "WM_FILESYSCHANGE",
            0x0035: "WM_ISACTIVEICON",
            0x0036: "WM_QUERYPARKICON",
            0x0037: "WM_QUERYDRAGICON",
            0x0038: "WM_WINHELP",
            0x0039: "WM_COMPAREITEM",
            0x003a: "WM_FULLSCREEN",
            0x003b: "WM_CLIENTSHUTDOWN",
            0x003c: "WM_DDEMLEVENT",
            0x003d: "WM_GETOBJECT",
            0x003e: "WM_CAP_SEQUENCE",
            0x003f: "WM_CALCSCROLL",
            0x0040: "WM_TESTING",
            0x0041: "WM_COMPACTING",
            0x0042: "WM_OTHERWINDOWCREATED",
            0x0043: "WM_OTHERWINDOWDESTROYED",
            0x0044: "WM_COMMNOTIFY",
            0x0045: "WM_MEDIASTATUSCHANGE",
            0x0046: "WM_WINDOWPOSCHANGING",
            0x0047: "WM_WINDOWPOSCHANGED",
            0x0048: "WM_POWER",
            0x0049: "WM_COPYGLOBALDATA",
            0x004a: "WM_COPYDATA",
            0x004b: "WM_CANCELJOURNAL",
            0x004c: "WM_LOGONNOTIFY",
            0x004d: "WM_KEYF1",
            0x004e: "WM_NOTIFY",
            0x004f: "WM_ACCESS_WINDOW",
            0x0050: "WM_INPUTLANGCHANGEREQUEST",
            0x0051: "WM_INPUTLANGCHANGE",
            0x0052: "WM_TCARD",
            0x0053: "WM_HELP",
            0x0054: "WM_USERCHANGED",
            0x0055: "WM_NOTIFYFORMAT",
            0x0056: "EM_GETUNDONAME",
            0x0057: "EM_GETREDONAME",
            0x0058: "EM_STOPGROUPTYPING",
            0x0059: "EM_SETTEXTMODE",
            0x005a: "EM_GETTEXTMODE",
            0x005b: "EM_AUTOURLDETECT",
            0x005c: "EM_GETAUTOURLDETECT",
            0x005d: "EM_SETPALETTE",
            0x005e: "EM_GETTEXTEX",
            0x005f: "EM_GETTEXTLENGTHEX",
            0x0060: "WM_UNDEF_0x0060",
            0x0061: "WM_UNDEF_0x0061",
            0x0062: "WM_UNDEF_0x0062",
            0x0063: "WM_UNDEF_0x0063",
            0x0064: "WM_UNDEF_0x0064",
            0x0065: "WM_UNDEF_0x0065",
            0x0066: "WM_UNDEF_0x0066",
            0x0067: "WM_UNDEF_0x0067",
            0x0068: "WM_UNDEF_0x0068",
            0x0069: "WM_UNDEF_0x0069",
            0x006a: "WM_UNDEF_0x006a",
            0x006b: "WM_UNDEF_0x006b",
            0x006c: "WM_UNDEF_0x006c",
            0x006d: "WM_UNDEF_0x006d",
            0x006e: "WM_UNDEF_0x006e",
            0x006f: "WM_UNDEF_0x006f",
            0x0070: "WM_FINALDESTROY",
            0x0071: "WM_MEASUREITEM_CLIENTDATA",
            0x0072: "WM_TASKACTIVATED",
            0x0073: "WM_TASKDEACTIVATED",
            0x0074: "WM_TASKCREATED",
            0x0075: "WM_TASKDESTROYED",
            0x0076: "WM_TASKUICHANGED",
            0x0077: "WM_TASKVISIBLE",
            0x0078: "WM_TASKNOTVISIBLE",
            0x0079: "WM_SETCURSORINFO",
            0x007a: "WM_UNDEF_0x007a",
            0x007b: "WM_CONTEXTMENU",
            0x007c: "WM_STYLECHANGING",
            0x007d: "WM_STYLECHANGED",
            0x007e: "WM_DISPLAYCHANGE",
            0x007f: "WM_GETICON",
            0x0080: "WM_SETICON",
            0x0081: "WM_NCCREATE",
            0x0082: "WM_NCDESTROY",
            0x0083: "WM_NCCALCSIZE",
            0x0084: "WM_NCHITTEST",
            0x0085: "WM_NCPAINT",
            0x0086: "WM_NCACTIVATE",
            0x0087: "WM_GETDLGCODE",
            0x0088: "WM_SYNCPAINT",
            0x0089: "WM_SYNCTASK",
            0x008a: "WM_UNDEF_0x008a",
            0x008b: "WM_KLUDGEMINRECT",
            0x008c: "WM_LPKDRAWSWITCHWND",
            0x008d: "WM_UNDEF_0x008d",
            0x008e: "WM_UNDEF_0x008e",
            0x008f: "WM_UNDEF_0x008f",
            0x0090: "WM_UNDEF_0x0090",
            0x0091: "WM_UNDEF_0x0091",
            0x0092: "WM_UNDEF_0x0092",
            0x0093: "WM_UNDEF_0x0093",
            0x0094: "WM_UNDEF_0x0094",
            0x0095: "WM_UNDEF_0x0095",
            0x0096: "WM_UNDEF_0x0096",
            0x0097: "WM_UNDEF_0x0097",
            0x0098: "WM_UNDEF_0x0098",
            0x0099: "WM_UNDEF_0x0099",
            0x009a: "WM_UNDEF_0x009a",
            0x009b: "WM_UNDEF_0x009b",
            0x009c: "WM_UNDEF_0x009c",
            0x009d: "WM_UNDEF_0x009d",
            0x009e: "WM_UNDEF_0x009e",
            0x009f: "WM_UNDEF_0x009f",
            0x00A0: "WM_NCMOUSEMOVE",
            0x00A1: "WM_NCLBUTTONDOWN",
            0x00A2: "WM_NCLBUTTONUP",
            0x00A3: "WM_NCLBUTTONDBLCLK",
            0x00A4: "WM_NCRBUTTONDOWN",
            0x00A5: "WM_NCRBUTTONUP",
            0x00A6: "WM_NCRBUTTONDBLCLK",
            0x00A7: "WM_NCMBUTTONDOWN",
            0x00A8: "WM_NCMBUTTONUP",
            0x00A9: "WM_NCMBUTTONDBLCLK",
            0x00AA: "WM_UNDEF_0x00AA",
            0x00AB: "WM_NCXBUTTONDOWN",
            0x00AC: "WM_NCXBUTTONUP",
            0x00AD: "WM_NCXBUTTONDBLCLK",
            0x00AE: "WM_NCUAHDRAWCAPTION",
            0x00AF: "WM_NCUAHDRAWFRAME",
            0x00b0: "EM_GETSEL32",
            0x00b1: "EM_SETSEL32",
            0x00b2: "EM_GETRECT32",
            0x00b3: "EM_SETRECT32",
            0x00b4: "EM_SETRECTNP32",
            0x00b5: "EM_SCROLL32",
            0x00b6: "EM_LINESCROLL32",
            0x00b7: "EM_SCROLLCARET32",
            0x00b8: "EM_GETMODIFY32",
            0x00b9: "EM_SETMODIFY32",
            0x00ba: "EM_GETLINECOUNT32",
            0x00bb: "EM_LINEINDEX32",
            0x00bc: "EM_SETHANDLE32",
            0x00bd: "EM_GETHANDLE32",
            0x00be: "EM_GETTHUMB32",
            0x00bf: "WM_UNDEF_0x00bf",
            0x00c0: "WM_UNDEF_0x00c0",
            0x00c1: "EM_LINELENGTH32",
            0x00c2: "EM_REPLACESEL32",
            0x00c3: "EM_SETFONT",
            0x00c4: "EM_GETLINE32",
            0x00c5: "EM_LIMITTEXT32",
            0x00c6: "EM_CANUNDO32",
            0x00c7: "EM_UNDO32",
            0x00c8: "EM_FMTLINES32",
            0x00c9: "EM_LINEFROMCHAR32",
            0x00ca: "EM_SETWORDBREAK",
            0x00cb: "EM_SETTABSTOPS32",
            0x00cc: "EM_SETPASSWORDCHAR32",
            0x00cd: "EM_EMPTYUNDOBUFFER32",
            0x00ce: "EM_GETFIRSTVISIBLELINE32",
            0x00cf: "EM_SETREADONLY32",
            0x00d0: "EM_SETWORDBREAKPROC32",
            0x00d1: "EM_GETWORDBREAKPROC32",
            0x00d2: "EM_GETPASSWORDCHAR32",
            0x00d3: "EM_SETMARGINS32",
            0x00d4: "EM_GETMARGINS32",
            0x00d5: "EM_GETLIMITTEXT32",
            0x00d6: "EM_POSFROMCHAR32",
            0x00d7: "EM_CHARFROMPOS32",
            0x00D8: "EM_SETIMESTATUS",
            0x00D9: "EM_GETIMESTATUS",
            0x00DA: "EM_MSGMAX",
            0x00DB: "WM_UNDEF_0x00DB",
            0x00DC: "WM_UNDEF_0x00DC",
            0x00DD: "WM_UNDEF_0x00DD",
            0x00DE: "WM_UNDEF_0x00DE",
            0x00DF: "WM_UNDEF_0x00DF",
            0x00e0: "SBM_SETPOS32",
            0x00e1: "SBM_GETPOS32",
            0x00e2: "SBM_SETRANGE32",
            0x00e3: "SBM_GETRANGE32",
            0x00e4: "SBM_ENABLE_ARROWS32",
            0x00e5: "WM_UNDEF_0x00e5",
            0x00e6: "SBM_SETRANGEREDRAW32",
            0x00e7: "WM_UNDEF_0x00e7",
            0x00e8: "WM_UNDEF_0x00e8",
            0x00e9: "SBM_SETSCROLLINFO32",
            0x00ea: "SBM_GETSCROLLINFO32",
            0x00eb: "WM_UNDEF_0x00eb",
            0x00ec: "WM_UNDEF_0x00ec",
            0x00ed: "WM_UNDEF_0x00ed",
            0x00ee: "WM_UNDEF_0x00ee",
            0x00ef: "WM_UNDEF_0x00ef",
            0x00f0: "BM_GETCHECK32",
            0x00f1: "BM_SETCHECK32",
            0x00f2: "BM_GETSTATE32",
            0x00f3: "BM_SETSTATE32",
            0x00f4: "BM_SETSTYLE32",
            0x00f5: "BM_CLICK32",
            0x00f6: "BM_GETIMAGE32",
            0x00f7: "BM_SETIMAGE32",
            0x00f8: "WM_UNDEF_0x00f8",
            0x00f9: "WM_UNDEF_0x00f9",
            0x00fa: "WM_UNDEF_0x00fa",
            0x00fb: "WM_UNDEF_0x00fb",
            0x00fc: "WM_UNDEF_0x00fc",
            0x00fd: "WM_UNDEF_0x00fd",
            0x00fe: "WM_UNDEF_0x00fe",
            0x00ff: "WM_INPUT",
            0x0100: "WM_KEYDOWN",
            0x0101: "WM_KEYUP",
            0x0102: "WM_CHAR",
            0x0103: "WM_DEADCHAR",
            0x0104: "WM_SYSKEYDOWN",
            0x0105: "WM_SYSKEYUP",
            0x0106: "WM_SYSCHAR",
            0x0107: "WM_SYSDEADCHAR",
            0x0108: "WM_YOMICHAR",
            0x0109: "WM_UNICHAR",
            0x010a: "WM_CONVERTREQUEST",
            0x010b: "WM_CONVERTRESULT",
            0x010c: "WM_INTERIM",
            0x010d: "WM_IME_STARTCOMPOSITION",
            0x010e: "WM_IME_ENDCOMPOSITION",
            0x010f: "WM_IME_COMPOSITION",
            0x0110: "WM_INITDIALOG",
            0x0111: "WM_COMMAND",
            0x0112: "WM_SYSCOMMAND",
            0x0113: "WM_TIMER",
            0x0114: "WM_HSCROLL",
            0x0115: "WM_VSCROLL",
            0x0116: "WM_INITMENU",
            0x0117: "WM_INITMENUPOPUP",
            0x0118: "WM_SYSTIMER",
            0x0119: "WM_UNDEF_0x0119",
            0x011a: "WM_UNDEF_0x011a",
            0x011b: "WM_UNDEF_0x011b",
            0x011c: "WM_UNDEF_0x011c",
            0x011d: "WM_UNDEF_0x011d",
            0x011e: "WM_UNDEF_0x011e",
            0x011f: "WM_MENUSELECT",
            0x0120: "WM_MENUCHAR",
            0x0121: "WM_ENTERIDLE",
            0x0122: "WM_MENURBUTTONUP",
            0x0123: "WM_MENUDRAG",
            0x0124: "WM_MENUGETOBJECT",
            0x0125: "WM_UNINITMENUPOPUP",
            0x0126: "WM_MENUCOMMAND",
            0x0127: "WM_CHANGEUISTATE",
            0x0128: "WM_UPDATEUISTATE",
            0x0129: "WM_QUERYUISTATE",
            0x012a: "WM_UNDEF_0x012a",
            0x012b: "WM_UNDEF_0x012b",
            0x012c: "WM_UNDEF_0x012c",
            0x012d: "WM_UNDEF_0x012d",
            0x012e: "WM_UNDEF_0x012e",
            0x012f: "WM_UNDEF_0x012f",
            0x0130: "WM_UNDEF_0x0130",
            0x0131: "WM_LBTRACKPOINT",
            0x0132: "WM_CTLCOLORMSGBOX",
            0x0133: "WM_CTLCOLOREDIT",
            0x0134: "WM_CTLCOLORLISTBOX",
            0x0135: "WM_CTLCOLORBTN",
            0x0136: "WM_CTLCOLORDLG",
            0x0137: "WM_CTLCOLORSCROLLBAR",
            0x0138: "WM_CTLCOLORSTATIC",
            0x0139: "WM_UNDEF_0x0139",
            0x013a: "WM_UNDEF_0x013a",
            0x013b: "WM_UNDEF_0x013b",
            0x013c: "WM_UNDEF_0x013c",
            0x013d: "WM_UNDEF_0x013d",
            0x013e: "WM_UNDEF_0x013e",
            0x013f: "WM_UNDEF_0x013f",
            0x0140: "CB_GETEDITSEL32",
            0x0141: "CB_LIMITTEXT32",
            0x0142: "CB_SETEDITSEL32",
            0x0143: "CB_ADDSTRING32",
            0x0144: "CB_DELETESTRING32",
            0x0145: "CB_DIR32",
            0x0146: "CB_GETCOUNT32",
            0x0147: "CB_GETCURSEL32",
            0x0148: "CB_GETLBTEXT32",
            0x0149: "CB_GETLBTEXTLEN32",
            0x014a: "CB_INSERTSTRING32",
            0x014b: "CB_RESETCONTENT32",
            0x014c: "CB_FINDSTRING32",
            0x014d: "CB_SELECTSTRING32",
            0x014e: "CB_SETCURSEL32",
            0x014f: "CB_SHOWDROPDOWN32",
            0x0150: "CB_GETITEMDATA32",
            0x0151: "CB_SETITEMDATA32",
            0x0152: "CB_GETDROPPEDCONTROLRECT32",
            0x0153: "CB_SETITEMHEIGHT32",
            0x0154: "CB_GETITEMHEIGHT32",
            0x0155: "CB_SETEXTENDEDUI32",
            0x0156: "CB_GETEXTENDEDUI32",
            0x0157: "CB_GETDROPPEDSTATE32",
            0x0158: "CB_FINDSTRINGEXACT32",
            0x0159: "CB_SETLOCALE32",
            0x015a: "CB_GETLOCALE32",
            0x015b: "CB_GETTOPINDEX32",
            0x015c: "CB_SETTOPINDEX32",
            0x015d: "CB_GETHORIZONTALEXTENT32",
            0x015e: "CB_SETHORIZONTALEXTENT32",
            0x015f: "CB_GETDROPPEDWIDTH32",
            0x0160: "CB_SETDROPPEDWIDTH32",
            0x0161: "CB_INITSTORAGE32",
            0x0162: "WM_UNDEF_0x0162",
            0x0163: "CB_MULTIPLEADDSTRING",
            0x0164: "CB_GETCOMBOBOXINFO",
            0x0165: "WM_UNDEF_0x0165",
            0x0166: "WM_UNDEF_0x0166",
            0x0167: "WM_UNDEF_0x0167",
            0x0168: "WM_UNDEF_0x0168",
            0x0169: "WM_UNDEF_0x0169",
            0x016a: "WM_UNDEF_0x016a",
            0x016b: "WM_UNDEF_0x016b",
            0x016c: "WM_UNDEF_0x016c",
            0x016d: "WM_UNDEF_0x016d",
            0x016e: "WM_UNDEF_0x016e",
            0x016f: "WM_UNDEF_0x016f",
            0x0170: "STM_SETICON32",
            0x0171: "STM_GETICON32",
            0x0172: "STM_SETIMAGE32",
            0x0173: "STM_GETIMAGE32",
            0x0174: "STM_MSGMAX",
            0x0175: "WM_UNDEF_0x0175",
            0x0176: "WM_UNDEF_0x0176",
            0x0177: "WM_UNDEF_0x0177",
            0x0178: "WM_UNDEF_0x0178",
            0x0179: "WM_UNDEF_0x0179",
            0x017a: "WM_UNDEF_0x017a",
            0x017b: "WM_UNDEF_0x017b",
            0x017c: "WM_UNDEF_0x017c",
            0x017d: "WM_UNDEF_0x017d",
            0x017e: "WM_UNDEF_0x017e",
            0x017f: "WM_UNDEF_0x017f",
            0x0180: "LB_ADDSTRING32",
            0x0181: "LB_INSERTSTRING32",
            0x0182: "LB_DELETESTRING32",
            0x0183: "LB_SELITEMRANGEEX32",
            0x0184: "LB_RESETCONTENT32",
            0x0185: "LB_SETSEL32",
            0x0186: "LB_SETCURSEL32",
            0x0187: "LB_GETSEL32",
            0x0188: "LB_GETCURSEL32",
            0x0189: "LB_GETTEXT32",
            0x018a: "LB_GETTEXTLEN32",
            0x018b: "LB_GETCOUNT32",
            0x018c: "LB_SELECTSTRING32",
            0x018d: "LB_DIR32",
            0x018e: "LB_GETTOPINDEX32",
            0x018f: "LB_FINDSTRING32",
            0x0190: "LB_GETSELCOUNT32",
            0x0191: "LB_GETSELITEMS32",
            0x0192: "LB_SETTABSTOPS32",
            0x0193: "LB_GETHORIZONTALEXTENT32",
            0x0194: "LB_SETHORIZONTALEXTENT32",
            0x0195: "LB_SETCOLUMNWIDTH32",
            0x0196: "LB_ADDFILE32",
            0x0197: "LB_SETTOPINDEX32",
            0x0198: "LB_GETITEMRECT32",
            0x0199: "LB_GETITEMDATA32",
            0x019a: "LB_SETITEMDATA32",
            0x019b: "LB_SELITEMRANGE32",
            0x019c: "LB_SETANCHORINDEX32",
            0x019d: "LB_GETANCHORINDEX32",
            0x019e: "LB_SETCARETINDEX32",
            0x019f: "LB_GETCARETINDEX32",
            0x01a0: "LB_SETITEMHEIGHT32",
            0x01a1: "LB_GETITEMHEIGHT32",
            0x01a2: "LB_FINDSTRINGEXACT32",
            0x01a3: "LB_CARETON32",
            0x01a4: "LB_CARETOFF32",
            0x01a5: "LB_SETLOCALE32",
            0x01a6: "LB_GETLOCALE32",
            0x01a7: "LB_SETCOUNT32",
            0x01a8: "LB_INITSTORAGE32",
            0x01a9: "LB_ITEMFROMPOINT32",
            0x01aa: "LB_INSERTSTRINGUPPER",
            0x01ab: "LB_INSERTSTRINGLOWER",
            0x01ac: "LB_ADDSTRINGUPPER",
            0x01ad: "LB_ADDSTRINGLOWER",
            0x01ae: "LBCB_STARTTRACK",
            0x01af: "LBCB_ENDTRACK",
            0x01B0: "WM_UNDEF_0x01B0",
            0x01b1: "LB_MULTIPLEADDSTRING",
            0x01b2: "LB_GETLISTBOXINFO",
            0x01b3: "WM_UNDEF_0x01b3",
            0x01b4: "WM_UNDEF_0x01b4",
            0x01b5: "WM_UNDEF_0x01b5",
            0x01b6: "WM_UNDEF_0x01b6",
            0x01b7: "WM_UNDEF_0x01b7",
            0x01b8: "WM_UNDEF_0x01b8",
            0x01b9: "WM_UNDEF_0x01b9",
            0x01ba: "WM_UNDEF_0x01ba",
            0x01bb: "WM_UNDEF_0x01bb",
            0x01bc: "WM_UNDEF_0x01bc",
            0x01bd: "WM_UNDEF_0x01bd",
            0x01be: "WM_UNDEF_0x01be",
            0x01bf: "WM_UNDEF_0x01bf",
            0x01C0: "WM_UNDEF_0x01C0",
            0x01c1: "WM_UNDEF_0x01c1",
            0x01c2: "WM_UNDEF_0x01c2",
            0x01c3: "WM_UNDEF_0x01c3",
            0x01c4: "WM_UNDEF_0x01c4",
            0x01c5: "WM_UNDEF_0x01c5",
            0x01c6: "WM_UNDEF_0x01c6",
            0x01c7: "WM_UNDEF_0x01c7",
            0x01c8: "WM_UNDEF_0x01c8",
            0x01c9: "WM_UNDEF_0x01c9",
            0x01ca: "WM_UNDEF_0x01ca",
            0x01cb: "WM_UNDEF_0x01cb",
            0x01cc: "WM_UNDEF_0x01cc",
            0x01cd: "WM_UNDEF_0x01cd",
            0x01ce: "WM_UNDEF_0x01ce",
            0x01cf: "WM_UNDEF_0x01cf",
            0x01D0: "WM_UNDEF_0x01D0",
            0x01d1: "WM_UNDEF_0x01d1",
            0x01d2: "WM_UNDEF_0x01d2",
            0x01d3: "WM_UNDEF_0x01d3",
            0x01d4: "WM_UNDEF_0x01d4",
            0x01d5: "WM_UNDEF_0x01d5",
            0x01d6: "WM_UNDEF_0x01d6",
            0x01d7: "WM_UNDEF_0x01d7",
            0x01d8: "WM_UNDEF_0x01d8",
            0x01d9: "WM_UNDEF_0x01d9",
            0x01da: "WM_UNDEF_0x01da",
            0x01db: "WM_UNDEF_0x01db",
            0x01dc: "WM_UNDEF_0x01dc",
            0x01dd: "WM_UNDEF_0x01dd",
            0x01de: "WM_UNDEF_0x01de",
            0x01df: "WM_UNDEF_0x01df",
            0x01E0: "WM_UNDEF_0x01E0",
            0x01e1: "WM_UNDEF_0x01e1",
            0x01e2: "WM_UNDEF_0x01e2",
            0x01e3: "MN_SETHMENU",
            0x01e4: "MN_GETHMENU",
            0x01e5: "MN_SIZEWINDOW",
            0x01e6: "MN_OPENHIERARCHY",
            0x01e7: "MN_CLOSEHIERARCHY",
            0x01e8: "MN_SELECTITEM",
            0x01e9: "MN_CANCELMENUS",
            0x01ea: "MN_SELECTFIRSTVALIDITEM",
            0x01eb: "WM_UNDEF_0x01eb",
            0x01ec: "WM_UNDEF_0x01ec",
            0x01ed: "WM_UNDEF_0x01ed",
            0x01ee: "MN_FINDMENUWINDOWFROMPOINT",
            0x01ef: "MN_SHOWPOPUPWINDOW",
            0x01f0: "MN_BUTTONUP",
            0x01f1: "MN_SETTIMERTOOPENHIERARCHY",
            0x01f2: "MN_DBLCLK",
            0x01f3: "MN_ACTIVEPOPUP",
            0x01f4: "MN_ENDMENU",
            0x01f5: "MN_DODRAGDROP",
            0x01f6: "WM_UNDEF_0x01f6",
            0x01f7: "WM_UNDEF_0x01f7",
            0x01f8: "WM_UNDEF_0x01f8",
            0x01f9: "WM_UNDEF_0x01f9",
            0x01fa: "WM_UNDEF_0x01fa",
            0x01fb: "WM_UNDEF_0x01fb",
            0x01fc: "WM_UNDEF_0x01fc",
            0x01fd: "WM_UNDEF_0x01fd",
            0x01fe: "WM_UNDEF_0x01fe",
            0x01ff: "WM_UNDEF_0x01ff",
            0x0200: "WM_MOUSEMOVE",
            0x0201: "WM_LBUTTONDOWN",
            0x0202: "WM_LBUTTONUP",
            0x0203: "WM_LBUTTONDBLCLK",
            0x0204: "WM_RBUTTONDOWN",
            0x0205: "WM_RBUTTONUP",
            0x0206: "WM_RBUTTONDBLCLK",
            0x0207: "WM_MBUTTONDOWN",
            0x0208: "WM_MBUTTONUP",
            0x0209: "WM_MBUTTONDBLCLK",
            0x020a: "WM_MOUSEWHEEL",
            0x020b: "WM_XBUTTONDOWN",
            0x020c: "WM_XBUTTONUP",
            0x020d: "WM_XBUTTONDBLCLK",
            0x020e: "WM_UNDEF_0x020e",
            0x020f: "WM_UNDEF_0x020f",
            0x0210: "WM_PARENTNOTIFY",
            0x0211: "WM_ENTERMENULOOP",
            0x0212: "WM_EXITMENULOOP",
            0x0213: "WM_NEXTMENU",
            0x0214: "WM_SIZING",
            0x0215: "WM_CAPTURECHANGED",
            0x0216: "WM_MOVING",
            0x0217: "WM_UNDEF_0x0217",
            0x0218: "WM_POWERBROADCAST",
            0x0219: "WM_DEVICECHANGE",
            0x021a: "WM_UNDEF_0x021a",
            0x021b: "WM_UNDEF_0x021b",
            0x021c: "WM_UNDEF_0x021c",
            0x021d: "WM_UNDEF_0x021d",
            0x021e: "WM_UNDEF_0x021e",
            0x021f: "WM_UNDEF_0x021f",
            0x0220: "WM_MDICREATE",
            0x0221: "WM_MDIDESTROY",
            0x0222: "WM_MDIACTIVATE",
            0x0223: "WM_MDIRESTORE",
            0x0224: "WM_MDINEXT",
            0x0225: "WM_MDIMAXIMIZE",
            0x0226: "WM_MDITILE",
            0x0227: "WM_MDICASCADE",
            0x0228: "WM_MDIICONARRANGE",
            0x0229: "WM_MDIGETACTIVE",
            0x022a: "WM_DROPOBJECT",
            0x022b: "WM_QUERYDROPOBJECT",
            0x022c: "WM_BEGINDRAG",
            0x022d: "WM_DRAGLOOP",
            0x022e: "WM_DRAGSELECT",
            0x02af: "WM_DRAGMOVE",
            0x0230: "WM_MDISETMENU",
            0x0231: "WM_ENTERSIZEMOVE",
            0x0232: "WM_EXITSIZEMOVE",
            0x0233: "WM_DROPFILES",
            0x0234: "WM_MDIREFRESHMENU",
            0x0235: "WM_UNDEF_0x0235",
            0x0236: "WM_UNDEF_0x0236",
            0x0237: "WM_UNDEF_0x0237",
            0x0238: "WM_UNDEF_0x0238",
            0x0239: "WM_UNDEF_0x0239",
            0x023a: "WM_UNDEF_0x023a",
            0x023b: "WM_UNDEF_0x023b",
            0x023c: "WM_UNDEF_0x023c",
            0x023d: "WM_UNDEF_0x023d",
            0x023e: "WM_UNDEF_0x023e",
            0x023f: "WM_UNDEF_0x023f",
            0x0240: "WM_UNDEF_0x0240",
            0x0241: "WM_UNDEF_0x0241",
            0x0242: "WM_UNDEF_0x0242",
            0x0243: "WM_UNDEF_0x0243",
            0x0244: "WM_UNDEF_0x0244",
            0x0245: "WM_UNDEF_0x0245",
            0x0246: "WM_UNDEF_0x0246",
            0x0247: "WM_UNDEF_0x0247",
            0x0248: "WM_UNDEF_0x0248",
            0x0249: "WM_UNDEF_0x0249",
            0x024a: "WM_UNDEF_0x024a",
            0x024b: "WM_UNDEF_0x024b",
            0x024c: "WM_UNDEF_0x024c",
            0x024d: "WM_UNDEF_0x024d",
            0x024e: "WM_UNDEF_0x024e",
            0x024f: "WM_UNDEF_0x024f",
            0x0250: "WM_UNDEF_0x0250",
            0x0251: "WM_UNDEF_0x0251",
            0x0252: "WM_UNDEF_0x0252",
            0x0253: "WM_UNDEF_0x0253",
            0x0254: "WM_UNDEF_0x0254",
            0x0255: "WM_UNDEF_0x0255",
            0x0256: "WM_UNDEF_0x0256",
            0x0257: "WM_UNDEF_0x0257",
            0x0258: "WM_UNDEF_0x0258",
            0x0259: "WM_UNDEF_0x0259",
            0x025a: "WM_UNDEF_0x025a",
            0x025b: "WM_UNDEF_0x025b",
            0x025c: "WM_UNDEF_0x025c",
            0x025d: "WM_UNDEF_0x025d",
            0x025e: "WM_UNDEF_0x025e",
            0x025f: "WM_UNDEF_0x025f",
            0x0260: "WM_UNDEF_0x0260",
            0x0261: "WM_UNDEF_0x0261",
            0x0262: "WM_UNDEF_0x0262",
            0x0263: "WM_UNDEF_0x0263",
            0x0264: "WM_UNDEF_0x0264",
            0x0265: "WM_UNDEF_0x0265",
            0x0266: "WM_UNDEF_0x0266",
            0x0267: "WM_UNDEF_0x0267",
            0x0268: "WM_UNDEF_0x0268",
            0x0269: "WM_UNDEF_0x0269",
            0x026a: "WM_UNDEF_0x026a",
            0x026b: "WM_UNDEF_0x026b",
            0x026c: "WM_UNDEF_0x026c",
            0x026d: "WM_UNDEF_0x026d",
            0x026e: "WM_UNDEF_0x026e",
            0x026f: "WM_UNDEF_0x026f",
            0x0270: "WM_UNDEF_0x0270",
            0x0271: "WM_UNDEF_0x0271",
            0x0272: "WM_UNDEF_0x0272",
            0x0273: "WM_UNDEF_0x0273",
            0x0274: "WM_UNDEF_0x0274",
            0x0275: "WM_UNDEF_0x0275",
            0x0276: "WM_UNDEF_0x0276",
            0x0277: "WM_UNDEF_0x0277",
            0x0278: "WM_UNDEF_0x0278",
            0x0279: "WM_UNDEF_0x0279",
            0x027a: "WM_UNDEF_0x027a",
            0x027b: "WM_UNDEF_0x027b",
            0x027c: "WM_UNDEF_0x027c",
            0x027d: "WM_UNDEF_0x027d",
            0x027e: "WM_UNDEF_0x027e",
            0x027f: "WM_UNDEF_0x027f",
            0x0280: "WM_KANJIFIRST",
            0x0281: "WM_IME_SETCONTENT",
            0x0282: "WM_IME_NOTIFY",
            0x0283: "WM_IME_CONTROL",
            0x0284: "WM_IME_COMPOSITIONFULL",
            0x0285: "WM_IME_SELECT",
            0x0286: "WM_IME_CHAR",
            0x0287: "WM_IME_SYSTEM",
            0x0288: "WM_IME_REQUEST",
            0x0289: "WM_UNDEF_0x0289",
            0x028a: "WM_UNDEF_0x028a",
            0x028b: "WM_UNDEF_0x028b",
            0x028c: "WM_UNDEF_0x028c",
            0x028d: "WM_UNDEF_0x028d",
            0x028e: "WM_UNDEF_0x028e",
            0x028f: "WM_UNDEF_0x028f",
            0x0290: "WM_IME_KEYDOWN",
            0x0291: "WM_IME_KEYUP",
            0x0292: "WM_UNDEF_0x0292",
            0x0293: "WM_UNDEF_0x0293",
            0x0294: "WM_UNDEF_0x0294",
            0x0295: "WM_UNDEF_0x0295",
            0x0296: "WM_UNDEF_0x0296",
            0x0297: "WM_UNDEF_0x0297",
            0x0298: "WM_UNDEF_0x0298",
            0x0299: "WM_UNDEF_0x0299",
            0x029a: "WM_UNDEF_0x029a",
            0x029b: "WM_UNDEF_0x029b",
            0x029c: "WM_UNDEF_0x029c",
            0x029d: "WM_UNDEF_0x029d",
            0x029e: "WM_UNDEF_0x029E",
            0x029f: "WM_KANJILAST",
            0x02a0: "WM_NCMOUSEHOVER",
            0x02a1: "WM_MOUSEHOVER",
            0x02a2: "WM_NCMOUSELEAVE",
            0x02a3: "WM_MOUSELEAVE",
            0x02a4: "WM_UNDEF_0x02a4",
            0x02a5: "WM_UNDEF_0x02a5",
            0x02a6: "WM_UNDEF_0x02a6",
            0x02a7: "WM_UNDEF_0x02a7",
            0x02a8: "WM_UNDEF_0x02a8",
            0x02a9: "WM_UNDEF_0x02a9",
            0x02aa: "WM_UNDEF_0x02aa",
            0x02ab: "WM_UNDEF_0x02ab",
            0x02ac: "WM_UNDEF_0x02ac",
            0x02ad: "WM_UNDEF_0x02ad",
            0x02ae: "WM_UNDEF_0x02ae",
            0x02b0: "WM_UNDEF_0x02b0",
            0x02b1: "WM_UNDEF_0x02b1",
            0x02b2: "WM_UNDEF_0x02b2",
            0x02b3: "WM_UNDEF_0x02b3",
            0x02b4: "WM_UNDEF_0x02b4",
            0x02b5: "WM_UNDEF_0x02b5",
            0x02b6: "WM_UNDEF_0x02b6",
            0x02b7: "WM_UNDEF_0x02b7",
            0x02b8: "WM_UNDEF_0x02b8",
            0x02b9: "WM_UNDEF_0x02b9",
            0x02ba: "WM_UNDEF_0x02ba",
            0x02bb: "WM_UNDEF_0x02bb",
            0x02bc: "WM_UNDEF_0x02bc",
            0x02bd: "WM_UNDEF_0x02bd",
            0x02be: "WM_UNDEF_0x02be",
            0x02bf: "WM_UNDEF_0x02bf",
            0x02c0: "WM_UNDEF_0x02c0",
            0x02c1: "WM_UNDEF_0x02c1",
            0x02c2: "WM_UNDEF_0x02c2",
            0x02c3: "WM_UNDEF_0x02c3",
            0x02c4: "WM_UNDEF_0x02c4",
            0x02c5: "WM_UNDEF_0x02c5",
            0x02c6: "WM_UNDEF_0x02c6",
            0x02c7: "WM_UNDEF_0x02c7",
            0x02c8: "WM_UNDEF_0x02c8",
            0x02c9: "WM_UNDEF_0x02c9",
            0x02ca: "WM_UNDEF_0x02ca",
            0x02cb: "WM_UNDEF_0x02cb",
            0x02cc: "WM_UNDEF_0x02cc",
            0x02cd: "WM_UNDEF_0x02cd",
            0x02ce: "WM_UNDEF_0x02ce",
            0x02cf: "WM_UNDEF_0x02cf",
            0x02d0: "WM_UNDEF_0x02d0",
            0x02d1: "WM_UNDEF_0x02d1",
            0x02d2: "WM_UNDEF_0x02d2",
            0x02d3: "WM_UNDEF_0x02d3",
            0x02d4: "WM_UNDEF_0x02d4",
            0x02d5: "WM_UNDEF_0x02d5",
            0x02d6: "WM_UNDEF_0x02d6",
            0x02d7: "WM_UNDEF_0x02d7",
            0x02d8: "WM_UNDEF_0x02d8",
            0x02d9: "WM_UNDEF_0x02d9",
            0x02da: "WM_UNDEF_0x02da",
            0x02db: "WM_UNDEF_0x02db",
            0x02dc: "WM_UNDEF_0x02dc",
            0x02dd: "WM_UNDEF_0x02dd",
            0x02de: "WM_UNDEF_0x02de",
            0x02df: "WM_UNDEF_0x02df",
            0x02e0: "WM_UNDEF_0x02e0",
            0x02e1: "WM_UNDEF_0x02e1",
            0x02e2: "WM_UNDEF_0x02e2",
            0x02e3: "WM_UNDEF_0x02e3",
            0x02e4: "WM_UNDEF_0x02e4",
            0x02e5: "WM_UNDEF_0x02e5",
            0x02e6: "WM_UNDEF_0x02e6",
            0x02e7: "WM_UNDEF_0x02e7",
            0x02e8: "WM_UNDEF_0x02e8",
            0x02e9: "WM_UNDEF_0x02e9",
            0x02ea: "WM_UNDEF_0x02ea",
            0x02eb: "WM_UNDEF_0x02eb",
            0x02ec: "WM_UNDEF_0x02ec",
            0x02ed: "WM_UNDEF_0x02ed",
            0x02ee: "WM_UNDEF_0x02ee",
            0x02ef: "WM_UNDEF_0x02ef",
            0x02f0: "WM_UNDEF_0x02f0",
            0x02f1: "WM_UNDEF_0x02f1",
            0x02f2: "WM_UNDEF_0x02f2",
            0x02f3: "WM_UNDEF_0x02f3",
            0x02f4: "WM_UNDEF_0x02f4",
            0x02f5: "WM_UNDEF_0x02f5",
            0x02f6: "WM_UNDEF_0x02f6",
            0x02f7: "WM_UNDEF_0x02f7",
            0x02f8: "WM_UNDEF_0x02f8",
            0x02f9: "WM_UNDEF_0x02f9",
            0x02fa: "WM_UNDEF_0x02fa",
            0x02fb: "WM_UNDEF_0x02fb",
            0x02fc: "WM_UNDEF_0x02fc",
            0x02fd: "WM_UNDEF_0x02fd",
            0x02fe: "WM_UNDEF_0x02fe",
            0x02ff: "WM_UNDEF_0x02ff",
            0x0300: "WM_CUT",
            0x0301: "WM_COPY",
            0x0302: "WM_PASTE",
            0x0303: "WM_CLEAR",
            0x0304: "WM_UNDO",
            0x0305: "WM_RENDERFORMAT",
            0x0306: "WM_RENDERALLFORMATS",
            0x0307: "WM_DESTROYCLIPBOARD",
            0x0308: "WM_DRAWCLIPBOARD",
            0x0309: "WM_PAINTCLIPBOARD",
            0x030a: "WM_VSCROLLCLIPBOARD",
            0x030b: "WM_SIZECLIPBOARD",
            0x030c: "WM_ASKCBFORMATNAME",
            0x030d: "WM_CHANGECBCHAIN",
            0x030e: "WM_HSCROLLCLIPBOARD",
            0x030f: "WM_QUERYNEWPALETTE",
            0x0310: "WM_PALETTEISCHANGING",
            0x0311: "WM_PALETTECHANGED",
            0x0312: "WM_HOTKEY",
            0x0313: "WM_HOOKMSG",
            0x0314: "WM_SYSMENU",
            0x0315: "WM_EXITPROCESS",
            0x0316: "WM_WAKETHREAD",
            0x0317: "WM_PRINT",
            0x0318: "WM_PRINTCLIENT",
            0x0319: "WM_APPCOMMAND",
            0x031a: "WM_THEMECHANGED",
            0x031b: "WM_UAHINIT",
            0x031c: "WM_UNDEF_0x031c",
            0x031d: "WM_UNDEF_0x031d",
            0x031e: "WM_UNDEF_0x031e",
            0x031f: "WM_UNDEF_0x031f",
            0x0320: "WM_UNDEF_0x0320",
            0x0321: "WM_UNDEF_0x0321",
            0x0322: "WM_UNDEF_0x0322",
            0x0323: "WM_UNDEF_0x0323",
            0x0324: "WM_UNDEF_0x0324",
            0x0325: "WM_UNDEF_0x0325",
            0x0326: "WM_UNDEF_0x0326",
            0x0327: "WM_UNDEF_0x0327",
            0x0328: "WM_UNDEF_0x0328",
            0x0329: "WM_UNDEF_0x0329",
            0x032a: "WM_UNDEF_0x032a",
            0x032b: "WM_UNDEF_0x032b",
            0x032c: "WM_UNDEF_0x032c",
            0x032d: "WM_UNDEF_0x032d",
            0x032e: "WM_UNDEF_0x032e",
            0x032f: "WM_UNDEF_0x032f",
            0x0330: "WM_UNDEF_0x0330",
            0x0331: "WM_UNDEF_0x0331",
            0x0332: "WM_UNDEF_0x0332",
            0x0333: "WM_UNDEF_0x0333",
            0x0334: "WM_UNDEF_0x0334",
            0x0335: "WM_UNDEF_0x0335",
            0x0336: "WM_UNDEF_0x0336",
            0x0337: "WM_UNDEF_0x0337",
            0x0338: "WM_UNDEF_0x0338",
            0x0339: "WM_UNDEF_0x0339",
            0x033a: "WM_UNDEF_0x033a",
            0x033b: "WM_UNDEF_0x033b",
            0x033c: "WM_UNDEF_0x033c",
            0x033d: "WM_UNDEF_0x033d",
            0x033e: "WM_UNDEF_0x033e",
            0x033f: "WM_UNDEF_0x033f",
            0x0340: "WM_NOTIFYWOW",
            0x0341: "WM_UNDEF_0x0341",
            0x0342: "WM_UNDEF_0x0342",
            0x0343: "WM_UNDEF_0x0343",
            0x0344: "WM_UNDEF_0x0344",
            0x0345: "WM_UNDEF_0x0345",
            0x0346: "WM_UNDEF_0x0346",
            0x0347: "WM_UNDEF_0x0347",
            0x0348: "WM_UNDEF_0x0348",
            0x0349: "WM_UNDEF_0x0349",
            0x034a: "WM_UNDEF_0x034a",
            0x034b: "WM_UNDEF_0x034b",
            0x034c: "WM_UNDEF_0x034c",
            0x034d: "WM_UNDEF_0x034d",
            0x034e: "WM_UNDEF_0x034e",
            0x034f: "WM_UNDEF_0x034f",
            0x0350: "WM_UNDEF_0x0350",
            0x0351: "WM_UNDEF_0x0351",
            0x0352: "WM_UNDEF_0x0352",
            0x0353: "WM_UNDEF_0x0353",
            0x0354: "WM_UNDEF_0x0354",
            0x0355: "WM_UNDEF_0x0355",
            0x0356: "WM_UNDEF_0x0356",
            0x0357: "WM_UNDEF_0x0357",
            0x0358: "WM_UNDEF_0x0358",
            0x0359: "WM_UNDEF_0x0359",
            0x035a: "WM_UNDEF_0x035a",
            0x035b: "WM_UNDEF_0x035b",
            0x035c: "WM_UNDEF_0x035c",
            0x035d: "WM_UNDEF_0x035d",
            0x035e: "WM_UNDEF_0x035e",
            0x035f: "WM_UNDEF_0x035f",
            0x0360: "WM_QUERYAFXWNDPROC",
            0x0361: "WM_SIZEPARENT",
            0x0362: "WM_SETMESSAGESTRING",
            0x0363: "WM_IDLEUPDATECMDUI",
            0x0364: "WM_INITIALUPDATE",
            0x0365: "WM_COMMANDHELP",
            0x0366: "WM_HELPHITTEST",
            0x0367: "WM_EXITHELPMODE",
            0x0368: "WM_RECALCPARENT",
            0x0369: "WM_SIZECHILD",
            0x036A: "WM_KICKIDLE",
            0x036B: "WM_QUERYCENTERWND",
            0x036C: "WM_DISABLEMODAL",
            0x036D: "WM_FLOATSTATUS",
            0x036E: "WM_ACTIVATETOPLEVEL",
            0x036F: "WM_QUERY3DCONTROLS",
            0x0370: "WM_UNDEF_0x0370",
            0x0371: "WM_UNDEF_0x0371",
            0x0372: "WM_UNDEF_0x0372",
            0x0373: "WM_SOCKET_NOTIFY",
            0x0374: "WM_SOCKET_DEAD",
            0x0375: "WM_POPMESSAGESTRING",
            0x0376: "WM_OCC_LOADFROMSTREAM",
            0x0377: "WM_OCC_LOADFROMSTORAGE",
            0x0378: "WM_OCC_INITNEW",
            0x0379: "WM_QUEUE_SENTINEL",
            0x037A: "WM_OCC_LOADFROMSTREAM_EX",
            0x037B: "WM_OCC_LOADFROMSTORAGE_EX",
            0x037c: "WM_UNDEF_0x037c",
            0x037d: "WM_UNDEF_0x037d",
            0x037e: "WM_UNDEF_0x037e",
            0x037f: "WM_UNDEF_0x037f",
            0x0380: "WM_PENWINFIRST",
            0x0381: "WM_RCRESULT",
            0x0382: "WM_HOOKRCRESULT",
            0x0383: "WM_GLOBALRCCHANGE",
            0x0384: "WM_SKB",
            0x0385: "WM_HEDITCTL",
            0x0386: "WM_UNDEF_0x0386",
            0x0387: "WM_UNDEF_0x0387",
            0x0388: "WM_UNDEF_0x0388",
            0x0389: "WM_UNDEF_0x0389",
            0x038a: "WM_UNDEF_0x038a",
            0x038b: "WM_UNDEF_0x038b",
            0x038c: "WM_UNDEF_0x038c",
            0x038d: "WM_UNDEF_0x038d",
            0x038e: "WM_UNDEF_0x038e",
            0x038f: "WM_PENWINLAST",
            0x0390: "WM_COALESCE_FIRST",
            0x0391: "WM_UNDEF_0x0391",
            0x0392: "WM_UNDEF_0x0392",
            0x0393: "WM_UNDEF_0x0393",
            0x0394: "WM_UNDEF_0x0394",
            0x0395: "WM_UNDEF_0x0395",
            0x0396: "WM_UNDEF_0x0396",
            0x0397: "WM_UNDEF_0x0397",
            0x0398: "WM_UNDEF_0x0398",
            0x0399: "WM_UNDEF_0x0399",
            0x039a: "WM_UNDEF_0x039a",
            0x039b: "WM_UNDEF_0x039b",
            0x039c: "WM_UNDEF_0x039c",
            0x039d: "WM_UNDEF_0x039d",
            0x039e: "WM_UNDEF_0x039e",
            0x039f: "WM_COALESCE_LAST",
            0x03a0: "MM_JOY1MOVE",
            0x03a1: "MM_JOY2MOVE",
            0x03a2: "MM_JOY1ZMOVE",
            0x03a3: "MM_JOY2ZMOVE",
            0x03a4: "WM_UNDEF_0x03a4",
            0x03a5: "WM_UNDEF_0x03a5",
            0x03a6: "WM_UNDEF_0x03a6",
            0x03a7: "WM_UNDEF_0x03a7",
            0x03a8: "WM_UNDEF_0x03a8",
            0x03a9: "WM_UNDEF_0x03a9",
            0x03aa: "WM_UNDEF_0x03aa",
            0x03ab: "WM_UNDEF_0x03ab",
            0x03ac: "WM_UNDEF_0x03ac",
            0x03ad: "WM_UNDEF_0x03ad",
            0x03ae: "WM_UNDEF_0x03ae",
            0x03af: "WM_UNDEF_0x03af",
            0x03b0: "WM_UNDEF_0x03b0",
            0x03b1: "WM_UNDEF_0x03b1",
            0x03b2: "WM_UNDEF_0x03b2",
            0x03b3: "WM_UNDEF_0x03b3",
            0x03b4: "WM_UNDEF_0x03b4",
            0x03b5: "MM_JOY1BUTTONDOWN",
            0x03b6: "MM_JOY2BUTTONDOWN",
            0x03b7: "MM_JOY1BUTTONUP",
            0x03b8: "MM_JOY2BUTTONUP",
            0x03b9: "MM_MCINOTIFY",
            0x03ba: "WM_UNDEF_0x03ba",
            0x03bb: "MM_WOM_OPEN",
            0x03bc: "MM_WOM_CLOSE",
            0x03bd: "MM_WOM_DONE",
            0x03be: "MM_WIM_OPEN",
            0x03bf: "MM_WIM_CLOSE",
            0x03c0: "MM_WIM_DATA",
            0x03c1: "MM_MIM_OPEN",
            0x03c2: "MM_MIM_CLOSE",
            0x03c3: "MM_MIM_DATA",
            0x03c4: "MM_MIM_LONGDATA",
            0x03c5: "MM_MIM_ERROR",
            0x03c6: "MM_MIM_LONGERROR",
            0x03c7: "MM_MOM_OPEN",
            0x03c8: "MM_MOM_CLOSE",
            0x03c9: "MM_MOM_DONE",
            0x03ca: "WM_UNDEF_0x03ca",
            0x03cb: "WM_UNDEF_0x03cb",
            0x03cc: "WM_UNDEF_0x03cc",
            0x03cd: "WM_UNDEF_0x03cd",
            0x03ce: "WM_UNDEF_0x03ce",
            0x03cf: "WM_UNDEF_0x03cf",
            0x03d0: "WM_UNDEF_0x03d0",
            0x03d1: "WM_UNDEF_0x03d1",
            0x03d2: "WM_UNDEF_0x03d2",
            0x03d3: "WM_UNDEF_0x03d3",
            0x03d4: "WM_UNDEF_0x03d4",
            0x03d5: "WM_UNDEF_0x03d5",
            0x03d6: "WM_UNDEF_0x03d6",
            0x03d7: "WM_UNDEF_0x03d7",
            0x03d8: "WM_UNDEF_0x03d8",
            0x03d9: "WM_UNDEF_0x03d9",
            0x03da: "WM_UNDEF_0x03da",
            0x03db: "WM_UNDEF_0x03db",
            0x03dc: "WM_UNDEF_0x03dc",
            0x03dd: "WM_UNDEF_0x03dd",
            0x03de: "WM_UNDEF_0x03de",
            0x03df: "WM_MM_RESERVED_LAST",
            0x03E0: "WM_DDE_INITIATE",
            0x03E1: "WM_DDE_TERMINATE",
            0x03E2: "WM_DDE_ADVISE",
            0x03E3: "WM_DDE_UNADVISE",
            0x03E4: "WM_DDE_ACK",
            0x03E5: "WM_DDE_DATA",
            0x03E6: "WM_DDE_REQUEST",
            0x03E7: "WM_DDE_POKE",
            0x03E8: "WM_DDE_EXECUTE",
            0x03e9: "WM_UNDEF_0x03e9",
            0x03ea: "WM_UNDEF_0x03ea",
            0x03eb: "WM_UNDEF_0x03eb",
            0x03ec: "WM_UNDEF_0x03ec",
            0x03ed: "WM_UNDEF_0x03ed",
            0x03ee: "WM_UNDEF_0x03ee",
            0x03ef: "WM_UNDEF_0x03ef",
            0x03f0: "WM_CBT_RESERVED_FIRST",
            0x03f1: "WM_UNDEF_0x03f1",
            0x03f2: "WM_UNDEF_0x03f2",
            0x03f3: "WM_UNDEF_0x03f3",
            0x03f4: "WM_UNDEF_0x03f4",
            0x03f5: "WM_UNDEF_0x03f5",
            0x03f6: "WM_UNDEF_0x03f6",
            0x03f7: "WM_UNDEF_0x03f7",
            0x03f8: "WM_UNDEF_0x03f8",
            0x03f9: "WM_UNDEF_0x03f9",
            0x03fa: "WM_UNDEF_0x03fa",
            0x03fb: "WM_UNDEF_0x03fb",
            0x03fc: "WM_UNDEF_0x03fc",
            0x03fd: "WM_UNDEF_0x03fd",
            0x03fe: "WM_UNDEF_0x03fe",
            0x03ff: "WM_CBT_RESERVED_LAST",
            0x0400: "WM_USER"
        }

        return MSG_TABLES.get(msgid, "WM_USER_%#04LX" % msgid)

    def CheckMSGEntry_attr(self, entry):
        if entry == idc.BADADDR:
            return 0
        if idaapi.get_dword(entry + 8) > 65535:
            return 0
        if idaapi.get_dword(entry + 12) > 65535:
            return 0
        Sig = self.getAword(entry + 16)
        if Sig > 100: #Sig
            if Sig < self.dmin or Sig > self.dmax: # point message
                return 0

        return 1

    @staticmethod
    def getAword(addr, offset=0):
        return idaapi.get_qword(addr + offset * 8) if idc.__EA64__ else idaapi.get_dword(addr + offset * 4)

    @staticmethod
    def get_pfn(addr):
        return idaapi.get_qword(addr + 24) if idc.__EA64__ else idaapi.get_dword(addr + 20)

    def CheckMSGMAP(self, addr):
        addrGetThisMessageMap = self.getAword(addr, 0)
        addrMsgEntry = self.getAword(addr, 1)

        if self.CheckMSGEntry_attr(addrMsgEntry) == 0:
            return 0

        if self.cmax == 0 or self.rmax == 0 or self.dmax == 0:
            snum = ida_segment.get_segm_qty()

            for i in range(0, snum):
                s = ida_segment.getnseg(i)
                segname = ida_segment.get_segm_name(s)

                if segname == ".text":
                    self.cmin = s.start_ea
                    self.cmax = s.end_ea

                if segname == ".rdata":
                    self.rmin = s.start_ea
                    self.rmax = s.end_ea

                if segname == ".data":
                    self.dmin = s.start_ea
                    self.dmax = s.end_ea

        if self.cmin == self.cmax or self.cmax == 0:
            return 0
        if self.rmin == self.rmax or self.rmax == 0:
            return 0

        if addrGetThisMessageMap < self.cmin or addrGetThisMessageMap > self.cmax:
            #如果是静态连接的, 这里直接指向父消息表地址
            if addrGetThisMessageMap < self.rmin or addrGetThisMessageMap > self.rmax:
                return 0

        if addrMsgEntry < self.rmin or addrMsgEntry > self.rmax:
            return 0

        if idaapi.get_dword(addrMsgEntry + 0) == 0 and \
            (idaapi.get_dword(addrMsgEntry + 4) != 0 or
             idaapi.get_dword(addrMsgEntry + 8) != 0 or
             idaapi.get_dword(addrMsgEntry + 12) != 0 or
             self.getAword(addrMsgEntry + 16) != 0 or
             self.get_pfn(addrMsgEntry) != 0):
            return 0

        if idaapi.get_name(addr) == "":
            if idaapi.get_name(addrGetThisMessageMap) == "":
                return 0
            return -1

        if idaapi.get_name(addrGetThisMessageMap)[0:18] == "?GetThisMessageMap":
            return 1

        while addrMsgEntry != idc:
            if  idaapi.get_dword(addrMsgEntry + 0) == 0 and \
                idaapi.get_dword(addrMsgEntry + 4) == 0 and \
                idaapi.get_dword(addrMsgEntry + 8) == 0 and \
                idaapi.get_dword(addrMsgEntry + 12) == 0 and \
                self.getAword(addrMsgEntry + 16) == 0 and \
                self.get_pfn(addrMsgEntry) == 0:
                return 1

            if self.CheckMSGEntry_attr(addrMsgEntry) == 0:
                return 0

            msgfun_addr = self.get_pfn(addrMsgEntry)
            if msgfun_addr < self.cmin or msgfun_addr > self.cmax:
                return 0

            addrMsgEntry = addrMsgEntry + self.MSGStructSize

        return 0

    @staticmethod
    def MakeOffset(addr):
        if idc.__EA64__:
            idc.create_data(addr, idc.FF_0OFF | idc.FF_REF | idc.FF_QWORD, 8, idc.BADADDR)
        else:
            idc.create_data(addr, idc.FF_0OFF | idc.FF_REF | idc.FF_DWORD, 4, idc.BADADDR)

    def MakeAfxMSG(self, addr):
        if idc.__EA64__:
            self.MakeOffset(addr)
            self.MakeOffset(addr + 8)
        else:
            self.MakeOffset(addr)
            self.MakeOffset(addr + 4)

    def MakeMSG_ENTRY(self, addr):
        msgmapSize = 0
        addrGetThisMessageMap = self.getAword(addr, 0)
        addrMsgEntry = self.getAword(addr, 1)

        self.MakeAfxMSG(addr)
        if idc.get_name(addr) == ("off_%lX" % (addr)) or idc.get_name(addr) == "":
            idc.set_name(addr, "msgEntries_%lX" % (addr))

        pEntry = addrMsgEntry
        while idaapi.get_dword(pEntry) != 0:
            idc.MakeUnknown(pEntry, self.MSGStructSize, DELIT_SIMPLE)
            if idc.MakeStructEx(pEntry, self.MSGStructSize, "AFX_MSGMAP_ENTRY") == 0:
                print "Create AFX_MSGMAP_ENTRY failed at %X" % (pEntry)
                return 0

            msgName = self.GetMsgName(Dword(pEntry + 0))

            str_funcmt = "MSG function:" + msgName
            str_funcmt += "\n   MSG:  " + hex(Dword(pEntry + 0)).upper()
            str_funcmt += "\n  Code:  " + str(Dword(pEntry + 4))
            str_funcmt += "\n    Id:  " + str(Dword(pEntry + 8)) + " - " + str(Dword(pEntry + 12))

            func_startEa = self.get_pfn(pEntry)
            pfn = ida_funcs.get_func(func_startEa)
            if pfn is None:
                MakeUnkn(func_startEa, DELIT_SIMPLE)
                ida_funcs.add_func(func_startEa)
                pfn = ida_funcs.get_func(func_startEa)

            ida_funcs.set_func_cmt(pfn, str_funcmt, 0)
            oldname = ida_funcs.get_func_name(func_startEa)
            if oldname == "sub_%lX" % (func_startEa):
                newname = ""
                if Dword(pEntry + 8) == Dword(pEntry + 12):
                    if Dword(pEntry + 8) != 0:
                        newname = "On_%s_%X_%u" % (msgName, func_startEa, Dword(pEntry + 8))
                    else:
                        newname = "On_%s_%X" % (msgName, func_startEa)
                else:
                    newname = "On_%s_%X_%u_to_%u" % (msgName, func_startEa, Dword(pEntry + 8), Dword(pEntry + 12))

                idc.MakeName(func_startEa, newname)

            pEntry = pEntry + self.MSGStructSize

        #AFX_MSG_END
        MakeUnknown(pEntry, self.MSGStructSize, DELIT_SIMPLE)
        MakeStructEx(pEntry, self.MSGStructSize, "AFX_MSGMAP_ENTRY")
        msgmapSize = pEntry - addrMsgEntry + self.MSGStructSize
        return msgmapSize

    # Search All AFX_MSGMAP
    def Search_MSGMAP(self):
        snum = ida_segment.get_segm_qty()

        for i in range(0, snum):
            s = ida_segment.getnseg(i)
            segname = ida_segment.get_segm_name(s)

            if segname == ".text":
                self.cmin = s.start_ea
                self.cmax = s.end_ea

            if segname == ".rdata":
                self.rmin = s.start_ea
                self.rmax = s.end_ea

        if self.cmin == self.cmax or self.cmax == 0:
            return 0
        if self.rmin == self.rmax or self.rmax == 0:
            return 0

        totalCount = 0
        parseCount = 0
        addr = self.rmin

        try:
            idaapi.show_wait_box("Search for AFX_MSGMAP...")
            values = list()
            while addr != idc.BADADDR:
                ret = self.CheckMSGMAP(addr)
                MSGMAPSize = 0
                if ret > 0:
                    totalCount += 1
                    strfind = "Find AFX_MSGMAP at 0x%X\n" % (addr)
                    idaapi.replace_wait_box(strfind)

                    if idc.Name(addr) == "off_%lX" % (addr):
                        parseCount += 1

                    MSGMAPSize = self.MakeMSG_ENTRY(addr)

                    value = [
                        totalCount-1,
                        addr,
                        idc.Name(addr),
                        (MSGMAPSize-self.MSGStructSize)/self.MSGStructSize
                    ]
                    values.append(value)

                addr += MSGMAPSize + self.USize

                MSGMAPSize = 0
                if addr > self.rmax:
                    break
        finally:
            idaapi.hide_wait_box()

        c = AFXMSGMAPSearchResultChooser("SearchAFX_MSGMAP results", values)
        r = c.show()
        msg("===== Search complete, total %lu, new resolution %lu=====\n" % (totalCount, parseCount))


class Kp_Menu_Context(idaapi.action_handler_t):
    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        # dummy method
        return 1

    @classmethod
    def update(self, ctx):
        try:
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            else:
                return idaapi.AST_DISABLE_FOR_FORM
        except:
            # Add exception for main menu on >= IDA 7.0
            return idaapi.AST_ENABLE_ALWAYS

# context menu for Patcher
class Kp_MC_Make_MSGMAP(Kp_Menu_Context):
    def activate(self, ctx):
        self.plugin.make_msgmap()
        return 1

# context menu for Fill Range
class Kp_MC_Find_MSGMAP(Kp_Menu_Context):
    def activate(self, ctx):
        self.plugin.search_msgmap()
        return 1


# hooks for popup menu
class Hooks(idaapi.UI_Hooks):
    # IDA >= 700 right click widget popup
    def finish_populating_widget_popup(self, form, popup):
        if idaapi.get_widget_type(form) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(form, popup, Kp_MC_Make_MSGMAP.get_name(), 'AFX_MSGMAP/')
            idaapi.attach_action_to_popup(form, popup, Kp_MC_Find_MSGMAP.get_name(), 'AFX_MSGMAP/')


class AfxMsgMapPlugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_HIDE
    comment = "AFX_MSGMAP identify"
    help = ""
    wanted_name = "AFX_MSGMAP Find"
    wanted_hotkey = ""

    def __init__(self):
        self.afxmsgmap = AfxMSGMap()

    def init(self):
        global plugin_initialized

        # register popup menu handlers
        Kp_MC_Make_MSGMAP.register(self, "Make as AFX_MSGMAP")
        Kp_MC_Find_MSGMAP.register(self, "Search AFX_MSGMAP")

        if not plugin_initialized:
            plugin_initialized = True
            idaapi.attach_action_to_menu("Search/AFX_MSGMAP/", Kp_MC_Make_MSGMAP.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu("Search/AFX_MSGMAP/", Kp_MC_Find_MSGMAP.get_name(), idaapi.SETMENU_APP)

        # setup popup menu
        self.hooks = Hooks()
        self.hooks.hook()
        self.afxmsgmap.AddMSGMAPStruct()

        if idaapi.init_hexrays_plugin():
            addon = idaapi.addon_info_t()
            addon.id = "snow.afxmsgmap"
            addon.name = "AfxMSGMap"
            addon.producer = "Snow & HTC (VinCSS)"
            addon.url = ""
            addon.version = "7.00"
            idaapi.register_addon(addon)

            print("%s plugin installed" % self.wanted_name)
            print "    write by snow<85703533> & HTC (VinCSS)"

            return idaapi.PLUGIN_KEEP

        return idaapi.PLUGIN_SKIP

    def run(self, arg=0):
        return

    def term(self):
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None
        print("%s plugin terminated." % self.wanted_name)

    # null handler
    def make_msgmap(self):
        address = idc.get_screen_ea()
        if self.afxmsgmap.CheckMSGMAP(address) > 0:
            self.afxmsgmap.MakeMSG_ENTRY(address)
        else:
            print("This is not a AFX_MSGMAP\n")

    # handler for About menu
    def search_msgmap(self):
        self.afxmsgmap.Search_MSGMAP()

def PLUGIN_ENTRY():
    return AfxMsgMapPlugin_t()
