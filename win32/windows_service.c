#include "../n2n.h"
#include "n2n_win32.h"

extern int main(int argc, char* argv[]);

int scm_start_service(DWORD, LPWSTR*);

SERVICE_TABLE_ENTRYW dispatch_table[] =
{
	{ L"edge", (LPSERVICE_MAIN_FUNCTIONW) scm_start_service },
	{ NULL, NULL }
};

static SERVICE_STATUS_HANDLE service_status_handle;
static SERVICE_STATUS service_status;

static bool scm_startup_complete = false;

int scm_startup() {
    if (scm_startup_complete) {
        return 0;
    }

    scm_startup_complete = true;

    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            /* not running as a service */
            return 0;
        } else {
            exit(1);
        }
    }

    return 1;
}

static VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
	service_status.dwCurrentState = dwCurrentState;
	service_status.dwWin32ExitCode = dwWin32ExitCode;
	service_status.dwWaitHint = dwWaitHint;

	if (dwCurrentState == SERVICE_START_PENDING)
		service_status.dwControlsAccepted = 0;
	else
		service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
		service_status.dwCheckPoint = 0;
	else
		service_status.dwCheckPoint = 1;

	SetServiceStatus(service_status_handle, &service_status);
}

static VOID WINAPI service_handler(DWORD dwControl) {
	switch (dwControl) {
	case SERVICE_CONTROL_STOP: {
		ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 500);
		ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}

	ReportSvcStatus(service_status.dwCurrentState, NO_ERROR, 0);
}

int scm_start_service(DWORD num, LPWSTR* args) {
	service_status_handle = RegisterServiceCtrlHandlerW(L"edge", service_handler);
	ZeroMemory(&service_status, sizeof(service_status));
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 300);
	ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
    /* TODO read arguments from Registry */
    char* argv[] =
	{
		"edge.exe",
		"@edge.txt",
		NULL
	};
	return main(2, argv);
}
