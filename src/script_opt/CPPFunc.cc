// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/script_opt/CPPFunc.h"


namespace zeek::detail {

std::unordered_map<std::string, FuncPtr> compiled_funcs;

void CPPFunc::Describe(ODesc* d) const
	{
	d->AddSP("compiled function");
	d->Add(name);
	}

} // zeek::detail
