// See the file "COPYING" in the main distribution directory for copyright.

// Class for traversing a function body's AST to build up a profile
// of its various elements.

#pragma once

#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"

namespace zeek::detail {

class ProfileFunc : public TraversalCallback {
public:
	// If the argument is true, then we compute a hash over the function's
	// AST to (pseudo-)uniquely identify it.
	ProfileFunc(bool _compute_hash = false, bool _analyze_attrs = false)
		{
		compute_hash = _compute_hash;
		analyze_attrs = _analyze_attrs;
		}

	const std::unordered_set<const ID*>& Globals() const
		{ return globals; }
	const std::unordered_set<const ID*>& AllGlobals() const
		{ return all_globals; }
	const std::unordered_set<const ID*>& Locals() const
		{ return locals; }
	const std::unordered_set<const ID*>& Params() const
		{ return params; }
	int NumParams() const	{ return num_params; }
	const std::unordered_set<const ID*>& Assignees() const
		{ return assignees; }
	const std::unordered_set<const ID*>& Inits() const
		{ return inits; }
	const std::unordered_set<const ConstExpr*>& Constants() const
		{ return constants; }
	const std::unordered_set<ScriptFunc*>& ScriptCalls() const
		{ return script_calls; }
	const std::unordered_set<Func*>& BiFCalls() const
		{ return BiF_calls; }
	const std::unordered_set<ScriptFunc*>& WhenCalls() const
		{ return when_calls; }
	const std::unordered_set<const char*>& Events() const
		{ return events; }
	const std::unordered_set<const SwitchStmt*>& ExprSwitches() const
		{ return expr_switches; }
	const std::unordered_set<const SwitchStmt*>& TypeSwitches() const
		{ return type_switches; }
	bool DoesIndirectCalls()		{ return does_indirect_calls; }

	std::size_t HashVal()	{ return hash_val; }

	int NumStmts()		{ return num_stmts; }
	int NumWhenStmts()	{ return num_when_stmts; }
	int NumExprs()		{ return num_exprs; }
	int NumLambdas()	{ return num_lambdas; }

protected:
	TraversalCode PreFunction(const Func*) override;
	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;

	void TraverseRecord(const RecordType* r);

	// Globals seen in the function.
	//
	// Does *not* include globals solely seen as the function being
	// called in a call.
	std::unordered_set<const ID*> globals;

	// Same, but also includes globals only seen as called functions.
	std::unordered_set<const ID*> all_globals;

	// Locals seen in the function.
	std::unordered_set<const ID*> locals;

	// The function's parameters.  Only valid if a separate traversal
	// of the Func* itself was made.
	std::unordered_set<const ID*> params;

	// How many parameters the function has; only valid with separate
	// Func* traversal.
	int num_params = -1;

	// Identifiers (globals, locals, parameters) that are assigned to.
	// Does not include implicit assignments due to initializations,
	// which are instead captured in "inits".
	std::unordered_set<const ID*> assignees;

	// Same for locals seen in initializations, so we can find,
	// for example, unused aggregates.
	std::unordered_set<const ID*> inits;

	// Constants seen in the function.
	std::unordered_set<const ConstExpr*> constants;

	// Script functions that this script calls.
	std::unordered_set<ScriptFunc*> script_calls;

	// Same for BiF's.
	std::unordered_set<Func*> BiF_calls;

	// Script functions appearing in "when" clauses.
	std::unordered_set<ScriptFunc*> when_calls;

	// Names of generated events.
	std::unordered_set<const char*> events;

	std::unordered_set<const SwitchStmt*> expr_switches;
	std::unordered_set<const SwitchStmt*> type_switches;

	// True if the function makes a call through an expression rather
	// than simply a function's (global) name.
	bool does_indirect_calls = false;

	// Hash value.  Only valid if constructor requested it.
	std::size_t hash_val = 0;

	// How many statements / when statements / lambda expressions /
	// expressions appear in the function body.
	int num_stmts = 0;
	int num_when_stmts = 0;
	int num_lambdas = 0;
	int num_exprs = 0;

	// Whether we're separately processing a "when" condition to
	// mine out its script calls.
	bool in_when = false;

	// Whether to skip any locals we encounter - used to recurse into
	// initialization statements.
	bool skip_locals = false;

	// We only compute a hash over the function if requested, since
	// it's somewhat expensive.
	bool compute_hash;

	// Whether to profile attributes associated with records that might
	// be instantiated.  Controllable because in most contexts, we
	// don't want them included.
	bool analyze_attrs = false;

	// The following are for computing a consistent hash that isn't
	// too profligate in how much it needs to compute over.

	// Checks whether we've already noted this type, and, if not,
	// updates the hash with it.
	void CheckType(const TypePtr& t);

	void UpdateHash(int val)
		{
		auto h = std::hash<int>{}(val);
		MergeInHash(h);
		}

	void UpdateHash(const IntrusivePtr<Obj>& o);

	void MergeInHash(std::size_t h)
		{
		// Taken from Boost.  See for example
		// https://www.boost.org/doc/libs/1_35_0/doc/html/boost/hash_combine_id241013.html
		// or
		// https://stackoverflow.com/questions/4948780/magic-number-in-boosthash-combine
		hash_val ^= h + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
		}

	// Types that we've already processed.  Hashing types can be
	// quite expensive since some of the common Zeek record types
	// (e.g., notices) are huge, so useful to not do them more than
	// once.  We track two forms, one by name (if available) and one
	// by raw pointer (if not).  Doing so allows us to track named
	// sub-records but also records that have no names.
	std::unordered_set<std::string> seen_types;
	std::unordered_set<const Type*> seen_type_ptrs;
};


} // namespace zeek::detail
