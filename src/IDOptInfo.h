// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with identifiers to aid script
// optimization.

#pragma once

#include "zeek/IntrusivePtr.h"

namespace zeek::detail {

class Expr;
class ConstExpr;

using ExprPtr = IntrusivePtr<Expr>;

class IDOptInfo {
public:
	void AddInitExpr(ExprPtr init_expr);
	const std::vector<ExprPtr>& GetInitExprs() const
		{ return init_exprs; }

	int NumAssignments() const	{ return num_assignments; }
	void SetNumAssignments(int n)	{ num_assignments = n; }

	const ConstExpr* Const() const  { return const_expr; }

	bool ShouldTrackRDs() const	{ return track_RDs; }
	void SetShouldTrackRDs()	{ track_RDs = true; }

private:
	// Expressions used to initialize the identifier, for use by
	// the scripts-to-C++ compiler.  We need to track all of them
	// because it's possible that a global value gets created using
	// one of the earlier instances rather than the last one.
	std::vector<ExprPtr> init_exprs;

	// The following all relate to streamline the computation of
	// reaching-definitions and associated AST optimization.

	// Number of assignments made to the identifier.  For globals,
	// this is in the context of the function body currently being
	// analyzed (i.e., it's a local notion, not aggregated across all
	// scripts.
	int num_assignments = 0;

	// Associated constant expression, if any.
	const ConstExpr* const_expr = nullptr;

	// True if the optimizer has decided to track reaching-definitions
	// for this identifier.
	bool track_RDs = false;
};

} // namespace zeek::detail
