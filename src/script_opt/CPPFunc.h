// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Func.h"

namespace zeek {

namespace detail {

extern std::unordered_map<std::string, FuncPtr> compiled_funcs;

class CPPFunc : public Func {
public:
	CPPFunc(const char* _name, bool _is_pure)
		{
		name = _name;
		is_pure = _is_pure;
		ASSERT(compiled_funcs.find(name) == compiled_funcs.end());
		compiled_funcs[name] = {NewRef{}, this};
		}

	bool IsPure() const override	{ return is_pure; }
	// ValPtr Invoke(zeek::Args* args, Frame* parent) const override;

	void Describe(ODesc* d) const override;

protected:
	std::string name;
	bool is_pure;
};

} // namespace detail

} // namespace zeek
