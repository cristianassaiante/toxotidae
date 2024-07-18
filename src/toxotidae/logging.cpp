#include "logging.h"

#include <iostream>

using namespace std;

FILE* Logging::mainLog;

std::string getCurDateAndTime()
{
	time_t rawtime;
	struct tm * timeinfo;
	char buffer[80];
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buffer, 80, "%Y_%m_%d_%I_%M_%S", timeinfo);
	return std::string(buffer);
}

VOID Logging::Init()
{
	std::string path = std::string(LOGPATH);
	mainLog = fopen(path.append(LOGNAME).c_str(), "w");
}

VOID Logging::Shutdown()
{
	fclose(Logging::mainLog);
}

VOID Logging::logMain(const char* fmt, ...)
{

	if (!Logging::mainLog) return; // TODO shall we quit Pin instead?
	va_list args;
	va_start(args, fmt);
	vfprintf(Logging::mainLog, fmt, args);
	va_end(args);

	fflush(Logging::mainLog);
}
