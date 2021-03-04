// See the file "COPYING" in the main distribution directory for copyright.

// Class for traversing a function body's AST to build up a profile
// of its various elements.

#pragma once

#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"

namespace zeek::detail {

using hash_type = unsigned long long;

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
	const std::vector<const Stmt*>& Stmts() const
		{ return stmts; }
	const std::vector<const Expr*>& Exprs() const
		{ return exprs; }
	const std::vector<const LambdaExpr*>& Lambdas() const
		{ return lambdas; }
	const std::vector<const ConstExpr*>& Constants() const
		{ return constants; }
	const std::unordered_set<const Type*>& Types() const
		{ return types; }
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

	hash_type HashVal()	{ return hash_val; }

	int NumLambdas()	{ return lambdas.size(); }
	int NumWhenStmts()	{ return num_when_stmts; }

protected:
	TraversalCode PreFunction(const Func*) override;
	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;

	void TraverseType(const TypePtr& t);

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

	// Statements seen in the function.  Does not include indirect
	// statements, such as those in lambda bodies.
	std::vector<const Stmt*> stmts;

	// Expressions seen in the function.  Does not include indirect
	// expressions (such as those appearing in attributes of types.
	std::vector<const Expr*> exprs;

	// Lambdas seen in the function.  We don't profile lambda bodies,
	// but rather make them available for separate profiling if
	// appropriate.
	std::vector<const LambdaExpr*> lambdas;

	// Constants seen in the function.
	std::vector<const ConstExpr*> constants;

	// Types seen in the function.  A set rather than a vector because
	// the same type can be seen numerous times.
	std::unordered_set<const Type*> types;

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
	hash_type hash_val = 0;

	// How many when statements expressions appear in the function body.
	// We could track these like we do for vectors, but to date all
	// that's mattered is whether a given body contains any.
	int num_when_stmts = 0;

	// Whether we're separately processing a "when" condition to
	// mine out its script calls.
	bool in_when = false;

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

	void UpdateHash(const char* val)
		{
		auto h = std::hash<std::string>{}(std::string(val));
		MergeInHash(h);
		}

	void UpdateHash(const Obj* o);
	void UpdateHash(const IntrusivePtr<Obj>& o)	{ UpdateHash(o.get()); }

	void MergeInHash(hash_type h)
		{
		// Taken from Boost.  See for example
		// https://www.boost.org/doc/libs/1_35_0/doc/html/boost/hash_combine_id241013.html
		// or
		// https://stackoverflow.com/questions/4948780/magic-number-in-boosthash-combine
		hash_val ^= h + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
		}

	// Hashing types can be quite expensive, since some of the common
	// Zeek record types (e.g., notices) are huge, so it's useful to
	// not do them more than once.  We already take care of that by
	// not revisiting the same pointer, but there's also a significant
	// gain by not hashing due to seeing the same name even if associated
	// with a different pointer.
	std::unordered_set<std::string> seen_type_names;
};


} // namespace zeek::detail
