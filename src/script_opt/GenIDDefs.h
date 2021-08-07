// See the file "COPYING" in the main distribution directory for copyright.

// Class for generating identifier definition information by traversing
// a function body's AST.

#pragma once

#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

class GenIDDefs : public TraversalCallback {
public:
	GenIDDefs(std::shared_ptr<ProfileFunc> _pf, const Func* f,
	            ScopePtr scope, StmtPtr body);

private:
	// Traverses the given function body, using the first two
	// arguments for context.
	void TraverseFunction(const Func* f, ScopePtr scope, StmtPtr body);

	TraversalCode PreStmt(const Stmt*) override;
	TraversalCode PostStmt(const Stmt*) override;
	TraversalCode PreExpr(const Expr*) override;
	TraversalCode PostExpr(const Expr*) override;

	// Analyzes the target of an assignment.  Returns true if the LHS
	// was an expression for which we can track it as a definition
	// (e.g., assignments to variables, but not to elements of
	// aggregates).
	bool CheckLHS(const ExprPtr& lhs)	{ return CheckLHS(lhs.get()); }
	bool CheckLHS(const Expr* lhs);

	// True if the given expression directly represents an aggregate.
	bool IsAggr(const Expr* e) const;

	// If -u is active, checks for whether the given identifier present
	// in the given expression is undefined at that point.
	void CheckVarUsage(const Expr* e, const ID* id);

	// Begin a new confluence block with the given statement.
	void StartConfluenceBlock(const Stmt* s);

	void ClearConfluenceBlock();

	// Finish up the current confluence block.  If no_orig_flow is
	// true, then there's no control flow from the origin (the statement
	// that starts the block).
	void EndConfluenceBlock(bool no_orig_flow = false);

	void BranchBackTo(const Stmt* s = nullptr);
	void BranchBeyond(const Stmt* s);

	const Stmt* FindLoop();
	const Stmt* FindBranchBeyondTarget();

	void ReturnAt(const Stmt* s);

	// Tracks that the given identifier is defined at the current
	// statement in the current confluence block.  "is_init" specifies
	// whether this is an initialization-upon-function-entry, which
	// holds for parameters and globals.
	void TrackID(const IDPtr& id, bool is_init = false)
		{ TrackID(id.get(), is_init); }
	void TrackID(const ID* id, bool is_init = false);

	// Profile for the function.  Currently, all we actually need from
	// this is the list of globals.
	std::shared_ptr<ProfileFunc> pf;

	// Whether the Func is an event/hook/function.  We currently only
	// need to know whether it's a hook, so we correctly interpret an
	// outer "break" in that context.
	FunctionFlavor func_flavor;

	const Stmt* curr_stmt = nullptr;
	int stmt_num;

	std::vector<const Stmt*> confluence_blocks;
	std::vector<std::unordered_set<const ID*>> modified_IDs;
};

} // zeek::detail
