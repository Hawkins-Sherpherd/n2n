MessageIdTypedef=DWORD

SeverityNames=(Success=0x0:STATUS_SEVERITY_SUCCESS
    Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning=0x2:STATUS_SEVERITY_WARNING
    Error=0x3:STATUS_SEVERITY_ERROR
    )


FacilityNames=(System=0x0:FACILITY_SYSTEM
    Runtime=0x2:FACILITY_RUNTIME
    Stubs=0x3:FACILITY_STUBS
    Io=0x4:FACILITY_IO_ERROR_CODE
)

LanguageNames=(Neutral=0x0000:MSG00000)

; // The following are message definitions.

; // Just provide the message contents no extras,
; // Message contains
; //   %1: Service name, i.e. edge or supernode
; //   %2: Message

MessageId=0x0
Severity=Informational
Facility=Runtime
SymbolicName=SVC_MESSAGE
Language=Neutral
%2
.
