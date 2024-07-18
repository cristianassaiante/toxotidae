#include "toxotidae.h"
#include "hooks.h"
#include "hooks_parser.h"

namespace Toxotidae
{
	ADDRINT mainExecutableLow;
	ADDRINT mainExecutableHigh;

	std::vector<std::string> supported_dll;

	VOID setMainExecutable(ADDRINT low, ADDRINT high)
	{
		mainExecutableLow = low;
		mainExecutableHigh = high;
	}

	BOOL isInsMainExecutable(ADDRINT addr)
	{
		return (addr >= mainExecutableLow && addr <= mainExecutableHigh);
	}

	VOID init()
	{
		supported_dll.push_back(std::string("ws2_32.dll"));
		supported_dll.push_back(std::string("advapi32.dll"));
		supported_dll.push_back(std::string("kernelbase.dll"));
		supported_dll.push_back(std::string("kernel32.dll"));
		supported_dll.push_back(std::string("crypt32.dll"));
		supported_dll.push_back(std::string("oleaut32.dll"));
		supported_dll.push_back(std::string("ole32.dll"));
		supported_dll.push_back(std::string("shell32.dll"));
		supported_dll.push_back(std::string("user32.dll"));
		supported_dll.push_back(std::string("wininet.dll"));

#ifdef PARAMS
		HooksParser::init_registersmap();
#endif // PARAMS
	}

	BOOL is_supported(std::string &dllname)
	{
		return find(supported_dll.begin(), supported_dll.end(), dllname) != supported_dll.end();
	}
}