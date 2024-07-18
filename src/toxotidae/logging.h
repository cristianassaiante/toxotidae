#pragma once
#include "pin.H"

// #define WIN7 1

#ifdef WIN7
#define LOGPATH "C:\\pin35\\"
#else
#define LOGPATH "C:\\pin-3.19\\pin-3.19\\"
#endif
#define LOGNAME "toxotidae-log.log"
#define LOG_BUILD 1

#define LOG_AR(fmt, ...) \
	do { \
		if (!LOG_BUILD) break; \
		Logging::logMain(fmt"\n", __VA_ARGS__); \
	} while (0)


class Logging
{
public:
	static FILE* mainLog;

	static VOID Init();
	static VOID Shutdown();
	static VOID logMain(const char * fmt, ...);
};