// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Stmt.h"

namespace zeek {

namespace detail {

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

extern std::unordered_map<unsigned long long, CPPStmt*> compiled_bodies;

} // namespace detail

} // namespace zeek
