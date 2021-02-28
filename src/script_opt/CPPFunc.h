// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Func.h"

namespace zeek {

namespace detail {

class CPPFunc : public Func {
public:
	CPPFunc(const char* _name, bool _is_pure)
		{
		name = _name;
		is_pure = _is_pure;
		}

	bool IsPure() const override	{ return is_pure; }
	// ValPtr Invoke(zeek::Args* args, Frame* parent) const override;

	void Describe(ODesc* d) const override;

protected:
	std::string name;
	bool is_pure;
};

class CPPStmt : public Stmt {
public:
	CPPStmt(const char* _name) : Stmt(STMT_CPP), name(_name)	{ }

	const std::string& Name()	{ return name; }

protected:
	StmtPtr Duplicate() override	{ ASSERT(0); return ThisPtr(); }

	TraversalCode Traverse(TraversalCallback* cb) const override
		{ return TC_CONTINUE; }

	std::string name;
};

extern std::unordered_map<unsigned long long, IntrusivePtr<CPPStmt>> compiled_bodies;

} // namespace detail

} // namespace zeek
