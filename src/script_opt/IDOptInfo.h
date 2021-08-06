// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with identifiers to aid script
// optimization.

#pragma once

#include <set>

#include "zeek/IntrusivePtr.h"

namespace zeek::detail {

class Expr;
class Stmt;

using ExprPtr = IntrusivePtr<Expr>;

#define NO_DEF -1

class IDDefRegion {
public:
	IDDefRegion(const Stmt* s, bool maybe, bool definitely, int single_def);
	IDDefRegion(int stmt_num, int level,
	            bool maybe, bool definitely, int single_def);

	void Init(bool maybe, bool definitely, int single_def)
		{
		maybe_defined = maybe;
		definitely_defined = definitely;
		single_definition = definitely ? single_def : NO_DEF;
		}

	// Number of the statement for which this region applies *after*
	// its execution.
	int start_stmt;
	int block_level;

	// Number of the statement that this region applies to, *after*
	// its execution.
	int end_stmt = NO_DEF;	// means the region hasn't ended yet

	// Identifier might be defined in this region.
	bool maybe_defined;

	// Identifier is definitely defined in this region.
	bool definitely_defined;

	// Statement number of unique definition, or NO_DEF if none.
	// Only meaningful if definitely_defined is true (but the
	// converse doesn't hold, as the identifier can be definitely
	// defined, but via > 1 statement).
	int single_definition;
};

class IDOptInfo {
public:
	void AddInitExpr(ExprPtr init_expr);
	const std::vector<ExprPtr>& GetInitExprs() const
		{ return init_exprs; }

	// Called when the identifier is defined via execution of the
	// given statement.
	void DefinedAt(const Stmt* s);

	// Called upon encountering a "return" statement.
	void ReturnAt(const Stmt* s);

	// Called when the current region contains a backwards branch,
	// possibly across multiple block levels.
	void BranchBackTo(const Stmt* to);

	// Called when the current region contains a forwards branch,
	// possibly across multiple block levels, to the statement that
	// comes right after "block".
	void BranchBeyond(const Stmt* block);

	// Start tracking block that begins with the body of s (not s itself).
	void StartConfluenceBlock(const Stmt* s);

	// Finish tracking confluence; s is the last point of execution
	// prior to leaving a block.
	void ConfluenceBlockEndsAt(const Stmt* s);

	// All of these regarding the identifer's state just prior to
	// executing the given statement.
	bool IsPossiblyDefinedAt(const Stmt* s);
	bool IsDefinitelyDefinedAt(const Stmt* s);
	bool IsUniquelyDefinedAt(const Stmt* s);

private:
	// End the active region after execution of the given statement.
	void EndRegionAt(int stmt_num, int level);

	// Find the region that applies *prior* to executing the
	// given statement.
	IDDefRegion& FindRegion(int stmt_num)
		{ return usage_regions[FindRegionIndex(stmt_num)]; }
	int FindRegionIndex(int stmt_num);

	IDDefRegion& ActiveRegion()
		{ return usage_regions[ActiveRegionIndex()]; }
	int ActiveRegionIndex();

	// Expressions used to initialize the identifier, for use by
	// the scripts-to-C++ compiler.  We need to track all of them
	// because it's possible that a global value gets created using
	// one of the earlier instances rather than the last one.
	std::vector<ExprPtr> init_exprs;

	std::vector<IDDefRegion> usage_regions;

	// A type for collecting the indices of usage_regions that will
	// all have confluence together at one point.
	using ConfluenceSet = std::set<IDDefRegion*>;

	// Maps loops/switches to their associated confluence sets.
	std::map<const Stmt*, ConfluenceSet> pending_confluences;

	// A stack of confluence statements, so we can always find
	// the innermost when ending a confluence block.
	std::vector<const Stmt*> confluence_stmts;
};

} // namespace zeek::detail
