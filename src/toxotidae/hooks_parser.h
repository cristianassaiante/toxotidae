#pragma once

#include "pin.H"

namespace HooksParser
{
	extern std::map<std::string, LEVEL_BASE::REG> registers;

	VOID init_registersmap();

	VOID parse_parameters(const std::string &filename);
}