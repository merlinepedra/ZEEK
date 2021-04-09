// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Func.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek {

namespace detail {

class CPPFunc : public Func {
public:
	bool IsPure() const override	{ return is_pure; }
	// ValPtr Invoke(zeek::Args* args, Frame* parent) const override;

	void Describe(ODesc* d) const override;

protected:
	// Constructor used when deriving subclasses.
	CPPFunc(const char* _name, bool _is_pure)
		{
		name = _name;
		is_pure = _is_pure;
		}

	std::string name;
	bool is_pure;
};

class CPPStmt : public Stmt {
public:
	CPPStmt(const char* _name) : Stmt(STMT_CPP), name(_name)	{ }

	const std::string& Name()	{ return name; }

	// The following only get defined by lambda bodies.
	virtual void SetLambdaCaptures(Frame* f)	{ }
	virtual std::vector<ValPtr> SerializeLambdaCaptures() const
		{ return std::vector<ValPtr>{}; }

	virtual IntrusivePtr<CPPStmt> Clone()	
		{
		return {NewRef{}, this};
		}

protected:
	StmtPtr Duplicate() override	{ ASSERT(0); return ThisPtr(); }

	TraversalCode Traverse(TraversalCallback* cb) const override
		{ return TC_CONTINUE; }

	std::string name;
};

using CPPStmtPtr = IntrusivePtr<CPPStmt>;

class CPPLambdaFunc : public ScriptFunc {
public:
	CPPLambdaFunc(std::string name, FuncTypePtr ft, CPPStmtPtr l_body);

	bool CopySemantics() const override	{ return true; }

protected:
	broker::expected<broker::data> SerializeClosure() const override;
	void SetCaptures(Frame* f) override;

	FuncPtr DoClone() override;

	CPPStmtPtr l_body;
};


struct CompiledScript {
	CPPStmtPtr body; 
	int priority;
	std::vector<std::string> events;
};

extern std::unordered_map<hash_type, CompiledScript> compiled_scripts;

struct CompiledItemPair { int index; int scope; };
using VarMapper = std::unordered_map<hash_type, CompiledItemPair>;

extern VarMapper compiled_items;

} // namespace detail

} // namespace zeek
