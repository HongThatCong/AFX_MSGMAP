# AFX_MSGMAP
IDAPython plugin to parse AFX_MSG in VC++ MFC application

Code ban đầu của Snow 85703533

Port lên IDAPython IDA 7.x

Add some internal MFC structs

Code chưa finish nhé mọi người, chưa port xong :D

# TODO
- Viết lại các hàm xác định và parse AFX_MSGMAP, AFX_MSGMAP_ENTRY
- Parse CRuntimeClass, add popup menu and context menu handler
- Pase các AFX_XXXMAP và AFX_XXXMAP_ENTRY còn lại, quan trong nhất là AFX_INTERFACEMAP
- Flow Graph cho các CRuntimeClass của các class.
