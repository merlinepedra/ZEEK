// See the file "COPYING" in the main distribution directory for copyright.

// Class for traversing a function body's AST to build up a profile
// of its various elements.

#pragma once

#include "zeek/Expr.h"
#include "zeek/Stmt.h"
#include "zeek/Traverse.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek::detail {

using hash_type = unsigned long long;

class ProfileFunc : public TraversalCallback {
public:
	ProfileFunc(const Func* func, const StmtPtr& body);
	ProfileFunc(const Expr* func);

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
	const std::unordered_set<const ID*>& Identifiers() const
		{ return ids; }
	const std::vector<const ID*>& OrderedIdentifiers() const
		{ return ordered_ids; }
	const std::unordered_set<const Type*>& Types() const
		{ return types; }
	const std::vector<const Type*>& OrderedTypes() const
		{ return ordered_types; }
	const std::unordered_set<ScriptFunc*>& ScriptCalls() const
		{ return script_calls; }
	const std::unordered_set<const ID*>& BiFGlobals() const
		{ return BiF_globals; }
	const std::unordered_set<ScriptFunc*>& WhenCalls() const
		{ return when_calls; }
	const std::unordered_set<std::string>& Events() const
		{ return events; }
	const std::unordered_set<const Attributes*>& ConstructorAttrs() const
		{ return constructor_attrs; }
	const std::unordered_set<const SwitchStmt*>& ExprSwitches() const
		{ return expr_switches; }
	const std::unordered_set<const SwitchStmt*>& TypeSwitches() const
		{ return type_switches; }
	bool DoesIndirectCalls()		{ return does_indirect_calls; }

	const std::vector<int>& AdditionalInts() const	{ return addl_ints; }

	void SetHashVal(hash_type hash)	{ hash_val = hash; }
	hash_type HashVal() const	{ return hash_val; }

	int NumLambdas() const		{ return lambdas.size(); }
	int NumWhenStmts() const	{ return num_when_stmts; }

protected:
	void Profile(const FuncType* ft, const StmtPtr& body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PreID(const ID*) override;

	void RecordType(const Type* t);
	void RecordType(const TypePtr& t)	{ RecordType(t.get()); }

	void RecordID(const ID* id);

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

	// If we're profiling a lambda function, this holds the captures.
	std::unordered_set<const ID*> captures;

	// Constants seen in the function.
	std::vector<const ConstExpr*> constants;

	// Identifiers seen in the function.
	std::unordered_set<const ID*> ids;

	// The same, but in a deterministic order.
	std::vector<const ID*> ordered_ids;

	// Types seen in the function.  A set rather than a vector because
	// the same type can be seen numerous times.
	std::unordered_set<const Type*> types;

	// The same, but in a deterministic order.
	std::vector<const Type*> ordered_types;

	// Script functions that this script calls.
	std::unordered_set<ScriptFunc*> script_calls;

	// Same for BiF's, though for them we record the corresponding global.
	std::unordered_set<const ID*> BiF_globals;

	// Script functions appearing in "when" clauses.
	std::unordered_set<ScriptFunc*> when_calls;

	// Names of generated events.
	std::unordered_set<std::string> events;

	// Attributes seen in set or table constructors.
	std::unordered_set<const Attributes*> constructor_attrs;

	std::unordered_set<const SwitchStmt*> expr_switches;
	std::unordered_set<const SwitchStmt*> type_switches;

	// True if the function makes a call through an expression rather
	// than simply a function's (global) name.
	bool does_indirect_calls = false;

	// Additional integers present in the body that should be factored
	// into its hash.
	std::vector<int> addl_ints;

	// Associated hash value.
	hash_type hash_val = 0;

	// How many when statements expressions appear in the function body.
	// We could track these like we do for vectors, but to date all
	// that's mattered is whether a given body contains any.
	int num_when_stmts = 0;

	// Whether we're separately processing a "when" condition to
	// mine out its script calls.
	bool in_when = false;
};

// Collectively profile an entire collection of functions.
class ProfileFuncs {
public:
	// Updates entries in "funcs" to include profiles.
	ProfileFuncs(std::vector<FuncInfo>& funcs);

	const std::unordered_set<const ID*>& Globals() const
		{ return globals; }
	const std::unordered_set<const ID*>& AllGlobals() const
		{ return all_globals; }
	const std::unordered_set<const ConstExpr*>& Constants() const
		{ return constants; }
	const std::unordered_set<const Type*>& MainTypes() const
		{ return main_types; }
	const std::vector<const Type*>& RepTypes() const
		{ return rep_types; }
	const std::unordered_set<ScriptFunc*>& ScriptCalls() const
		{ return script_calls; }
	const std::unordered_set<const ID*>& BiFGlobals() const
		{ return BiF_globals; }
	const std::unordered_set<std::string>& Events() const
		{ return events; }
	const std::unordered_set<const LambdaExpr*>& Lambdas() const
		{ return lambdas; }

	ProfileFunc* FuncProf(const ScriptFunc* f)
		{ return func_profs[f]; }

	// This is only externally germane for LambdaExpr's.
	ProfileFunc* ExprProf(const Expr* e)
		{ return expr_profs[e].get(); }

	const Type* TypeRep(const Type* orig)	{ ASSERT(type_to_rep.count(orig) > 0); return type_to_rep[orig]; }

	hash_type HashType(const TypePtr& t)	{ return HashType(t.get()); }
	hash_type HashType(const Type* t);

protected:
	void MergeInProfile(ProfileFunc* pf);

	void DrainPendingExprs();

	// Computes hashes for the given set of types.  Potentially recursive
	// upon discovering additional types.
	void ComputeTypeHashes(const std::unordered_set<const Type*>& type_set);

	void ComputeBodyHashes(std::vector<FuncInfo>& funcs);
	void ComputeProfileHash(ProfileFunc* pf);

	void TrackAttrs(const Attributes* Attrs);

	hash_type Hash(int val)		{ return std::hash<int>{}(val); }

	hash_type MergeHashes(hash_type h1, hash_type h2)
		{
		// Taken from Boost.  See for example
		// https://www.boost.org/doc/libs/1_35_0/doc/html/boost/hash_combine_id241013.html
		// or
		// https://stackoverflow.com/questions/4948780/magic-number-in-boosthash-combine
		return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
		}

	// Globals seen across the functions, other than those solely seen
	// as the function being called in a call.
	std::unordered_set<const ID*> globals;

	// Same, but also includes globals only seen as called functions.
	std::unordered_set<const ID*> all_globals;

	// Constants seen across the functions.
	std::unordered_set<const ConstExpr*> constants;

	// Types seen across the functions.  Does not include subtypes.
	std::unordered_set<const Type*> main_types;

	// "Representative" types seen across the functions.  Includes
	// subtypes.  These all have unique hashes, and are returned by
	// calls to TypeRep().
	std::vector<const Type*> rep_types;

	// Maps a type to its representative (which might be itself).
	std::unordered_map<const Type*, const Type*> type_to_rep;

	// Script functions that get called.
	std::unordered_set<ScriptFunc*> script_calls;

	// Same for BiF's.
	std::unordered_set<const ID*> BiF_globals;

	// Names of generated events.
	std::unordered_set<std::string> events;

	// And for lambda's.
	std::unordered_set<const LambdaExpr*> lambdas;

	// Maps script functions to associated profiles.  This isn't
	// actually well-defined in the case of event handlers and hooks,
	// which can have multiple bodies.  However, the need for this
	// is temporary (it's for skipping compilation of functions that
	// appear in "when" clauses), and in that context it suffices.
	std::unordered_map<const ScriptFunc*, ProfileFunc*> func_profs;

	// Maps expressions to their profiles.  This is only germane
	// externally for LambdaExpr's, but internally it abets memory
	// management.
	std::unordered_map<const Expr*, std::shared_ptr<ProfileFunc>> expr_profs;

	// Maps types to their hashes.
	std::unordered_map<const Type*, hash_type> type_hashes;

	// An inverse mapping, to a representative for each distinct hash.
	std::unordered_map<hash_type, const Type*> type_hash_reps;

	// For types with names, tracks the ones we've already hashed,
	// so we can avoid work for distinct pointers that refer to the
	// same underlying type.
	std::unordered_map<std::string, const Type*> seen_type_names;

	// Expressions that we've discovered that we need to further
	// profile.  These can arise for example due to lambdas or
	// record attributes.
	std::vector<const Expr*> pending_exprs;
};

// Helper functions.
inline hash_type hash_string(const char* val)
	{
	return std::hash<std::string>{}(std::string(val));
	}

extern hash_type hash_obj(const Obj* o);
inline hash_type hash_obj(const IntrusivePtr<Obj>& o)
	{ return hash_obj(o.get()); }


} // namespace zeek::detail
