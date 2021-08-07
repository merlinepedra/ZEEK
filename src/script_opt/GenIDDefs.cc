// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Expr.h"
#include "zeek/Scope.h"
#include "zeek/Reporter.h"
#include "zeek/Desc.h"
#include "zeek/script_opt/GenIDDefs.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/StmtOptInfo.h"


namespace zeek::detail {


GenIDDefs::GenIDDefs(std::shared_ptr<ProfileFunc> _pf, const Func* f,
	             ScopePtr scope, StmtPtr body)
: pf(std::move(_pf))
	{
	TraverseFunction(f, scope, body);
	}

void GenIDDefs::TraverseFunction(const Func* f, ScopePtr scope, StmtPtr body)
	{
	func_flavor = f->Flavor();

	const auto& args = scope->OrderedVars();
	int nparam = f->GetType()->Params()->NumFields();

	for ( const auto& a : args )
		{
		if ( --nparam < 0 )
			break;

		TrackID(a, true);
		}

	for ( const auto& g : pf->Globals() )
		TrackID(g, true);

	stmt_num = 0;	// 0 = "before the first statement"

	body->Traverse(this);
	}

TraversalCode GenIDDefs::PreStmt(const Stmt* s)
	{
	curr_stmt = s;

	auto si = s->GetOptInfo();
	si->stmt_num = ++stmt_num;
	si->block_level = confluence_blocks.size();

	switch ( s->Tag() ) {
	case STMT_CATCH_RETURN:
		{
		auto cr = s->AsCatchReturnStmt();
		auto block = cr->Block();

		StartConfluenceBlock(s);
		block->Traverse(this);
		EndConfluenceBlock();

		TrackID(cr->RetVar()->Id());

		return TC_ABORTSTMT;
		}

	case STMT_IF:
		{
		auto i = s->AsIfStmt();
		auto cond = i->StmtExpr();
        
		cond->Traverse(this);

		StartConfluenceBlock(s);

		i->TrueBranch()->Traverse(this);
		if ( ! i->TrueBranch()->NoFlowAfter(false) )
			BranchBeyond(s);

		// This needs to reset identifiers, too.
		ClearConfluenceBlock();

		i->FalseBranch()->Traverse(this);
		if ( ! i->FalseBranch()->NoFlowAfter(false) )
			BranchBeyond(s);

		EndConfluenceBlock();

		return TC_ABORTSTMT;
		}

	case STMT_SWITCH:
		{
		auto sw = s->AsSwitchStmt();
		auto e = sw->StmtExpr();

		StartConfluenceBlock(sw);

		for ( const auto& c : *sw->Cases() )
			{
			auto body = c->Body();

			StartConfluenceBlock(body);

			auto exprs = c->ExprCases();
			if ( exprs )
				exprs->Traverse(this);

			auto type_ids = c->TypeCases();
			if ( type_ids )
				{
				for ( const auto& id : *type_ids )
					if ( id->Name() )
						TrackID(id);
				}

			body->Traverse(this);

			if ( ! body->NoFlowAfter(false) )
				BranchBeyond(s);

			EndConfluenceBlock();
			}

		EndConfluenceBlock(sw->HasDefault());

		return TC_ABORTSTMT;
		}

	case STMT_FOR:
		{
		auto f = s->AsForStmt();

		auto ids = f->LoopVars();
		auto e = f->LoopExpr();
		auto body = f->LoopBody();
		auto val_var = f->ValueVar();

		e->Traverse(this);

		for ( const auto& id : *ids )
			TrackID(id);

		if ( val_var )
			TrackID(val_var);

		StartConfluenceBlock(s);
		body->Traverse(this);

		if ( ! body->NoFlowAfter(false) )
			BranchBackTo();

		EndConfluenceBlock();

		return TC_ABORTSTMT;
		}

	case STMT_WHILE:
		{
		auto w = s->AsWhileStmt();

		StartConfluenceBlock(s);

		auto cond_stmt = w->CondPredStmt();
		if ( cond_stmt )
			cond_stmt->Traverse(this);

		w->Condition()->Traverse(this);

		auto body = w->Body();
		body->Traverse(this);

		if ( ! body->NoFlowAfter(false) )
			BranchBackTo();

		EndConfluenceBlock();

		return TC_ABORTSTMT;
		}

	case STMT_WHEN:
		{
		// ### punt on these for now, need to reflect on bindings.
		return TC_ABORTSTMT;
		}

	default:
		return TC_CONTINUE;
	}
	}

TraversalCode GenIDDefs::PostStmt(const Stmt* s)
	{
	switch ( s->Tag() ) {
	case STMT_INIT:
		{
		auto init = s->AsInitStmt();
		auto& inits = init->Inits();

		for ( const auto& id : inits )
			{
			auto id_t = id->GetType();

			// Only aggregates get initialized.
			if ( zeek::IsAggr(id->GetType()->Tag()) )
				TrackID(id);
			}

		break;
		}

	case STMT_RETURN:
		ReturnAt(s);
		break;

	case STMT_NEXT:
		BranchBackTo(FindLoop());
		break;

	case STMT_BREAK:
		{
		auto target = FindBranchBeyondTarget();

		if ( target )
			BranchBeyond(target);

		else
			{
			ASSERT(func_flavor == FUNC_FLAVOR_HOOK);
			ReturnAt(s);
			}

		break;
		}

	case STMT_FALLTHROUGH:
		// No need to do anything, the work all occurs
		// with NoFlowAfter.
		break;

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode GenIDDefs::PreExpr(const Expr* e)
	{
	switch ( e->Tag() ) {
	case EXPR_NAME:
		CheckVarUsage(e, e->AsNameExpr()->Id());
		break;

	case EXPR_ASSIGN:
	case EXPR_INDEX_ASSIGN:
	case EXPR_FIELD_ASSIGN:
	case EXPR_FIELD_LHS_ASSIGN:
		{
		auto a = e->AsAssignExpr();
		auto lhs = a->Op1();
		auto rhs = a->Op2();

		if ( lhs->Tag() == EXPR_LIST &&
		     rhs->GetType()->Tag() != TYPE_ANY )
			{
			// This combination occurs only for assignments used
			// to initialize table entries.  Treat it as references
			// to both the lhs and the rhs, not as an assignment.
			return TC_CONTINUE;
			}

		rhs->Traverse(this);

		// Index assignments have a third operand.  For those,
		// Op2() isn't actually "RHS" but rather the index into
		// the aggregate, but we still want to traverse it
		// in the same manner as a true RHS (i.e., treating it
		// as access to values, not assignments), so the above
		// call was okay.
		auto addl = a->GetOp3();

		if ( addl )
			addl->Traverse(this);

		if ( CheckLHS(lhs) )
			return TC_ABORTSTMT;

		// Too hard to figure out what's going on with the assignment.
		// Just analyze it in terms of values it accesses.
		break;
		}

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();
		auto args_l = c->Args();

		// If one of the arguments is an aggregate, then
		// it's actually passed by reference, and we shouldn't
		// ding it for not being initialized.  In addition,
		// we should treat this as a definition of the
		// aggregate, because while it can't be actually
		// reassigned, all of its dynamic properties can change
		// due to the call.  (In the future, we could consider
		// analyzing the call to see whether this is in fact
		// the case.)
		//
		// We handle all of this by just doing the traversal
		// ourselves.

		f->Traverse(this);

		for ( const auto& expr : args_l->Exprs() )
			{
			if ( IsAggr(expr) )
				// Not only do we skip analyzing it, but
				// we consider it initialized post-return.
				(void) CheckLHS(expr->GetOp1());
			else
				expr->Traverse(this);
			}

		// Mark any non-const globals as possibly modified by
		// the call.  In the future, we could aim to comprehensively
		// understand which globals could possibly be altered, but
		// for now we just assume they all could.
		for ( const auto& g : pf->Globals() )
			if ( ! g->IsConst() )
				TrackID(g);

		return TC_ABORTSTMT;
		}

	case EXPR_COND:
		// Special hack.  We don't bother traversing the operands
		// of conditionals.  This is because we use them heavily
		// to deconstruct logical expressions for which the
		// actual operand access is safe (guaranteed not to
		// access a value that hasn't been undefined), but the
		// flow analysis has trouble determining that.  In principle
		// we could do a bit better here and only traverse operands
		// that aren't temporaries, but that's a bit of a pain
		// to discern.
		e->GetOp1()->Traverse(this);

		return TC_ABORTSTMT;

	case EXPR_LAMBDA:
		{
		auto l = static_cast<const LambdaExpr*>(e);
		const auto& ids = l->OuterIDs();

		for ( auto& id : ids )
			CheckVarUsage(e, id);

		// Don't descend into the lambda body - we'll analyze and
		// optimize it separately, as its own function.
		return TC_ABORTSTMT;
		}

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode GenIDDefs::PostExpr(const Expr* e)
	{
	// Attend to expressions that reflect assignments after
	// execution, but for which the assignment target was
	// also an accessed value (so if we analyzed them
	// in PreExpr then we'd have had to do manual traversals
	// of their operands).

	auto t = e->Tag();
	if ( t == EXPR_INCR || t == EXPR_DECR || t == EXPR_ADD_TO ||
	     t == EXPR_APPEND_TO )
		(void) CheckLHS(e->GetOp1());

	return TC_CONTINUE;
	}

bool GenIDDefs::CheckLHS(const Expr* lhs)
	{
	if ( lhs->Tag() == EXPR_REF )
		lhs = lhs->GetOp1().get();

	switch ( lhs->Tag() ) {
	case EXPR_NAME:
		{
		auto n = lhs->AsNameExpr();
		TrackID(n->Id());
		return true;
		}

	case EXPR_LIST:
		{ // look for [a, b, c] = any_val
		auto l = lhs->AsListExpr();
		for ( const auto& expr : l->Exprs() )
			{
			if ( expr->Tag() != EXPR_NAME )
				// This will happen for table initializers,
				// for example.
				return false;

			auto n = expr->AsNameExpr();
			TrackID(n->Id());
			}

		return true;
		}

	case EXPR_FIELD:
		{
		auto f = lhs->AsFieldExpr();
		auto r = f->Op();

		if ( r->Tag() != EXPR_NAME )
			// This is a more complicated expression that we're
			// not able to concretely track.
			return false;

		TrackID(r->AsNameExpr()->Id());

		return true;
		}

	case EXPR_INDEX:
		{
		// Treat as an  initialization of the aggregate.
		auto i_e = lhs->AsIndexExpr();
		return CheckLHS(i_e->Op1());
		}

	default:
		reporter->InternalError("bad tag in RD_Decorate::CheckLHS");
	}
	}

bool GenIDDefs::IsAggr(const Expr* e) const
	{
	if ( e->Tag() != EXPR_NAME )
		return false;

	auto n = e->AsNameExpr();
	auto id = n->Id();
	auto tag = id->GetType()->Tag();

	return zeek::IsAggr(tag);
	}

void GenIDDefs::CheckVarUsage(const Expr* e, const ID* id)
	{
	if ( analysis_options.usage_issues == 0 )
		return;

	auto oi = id->GetOptInfo();

	if ( ! oi->IsDefinitelyDefinedAt(curr_stmt) &&
	     ! id->GetAttr(ATTR_IS_ASSIGNED) )
		{
		if ( ! oi->IsPossiblyDefinedAt(curr_stmt) )
			e->Warn("used without definition");
		else
			e->Warn("possibly used without definition");
		}
	}

void GenIDDefs::StartConfluenceBlock(const Stmt* s)
	{
	confluence_blocks.push_back(s);

	std::unordered_set<const ID*> empty_IDs;
	modified_IDs.push_back(empty_IDs);
	}

void GenIDDefs::ClearConfluenceBlock()
	{
	modified_IDs.back().clear();
	}

void GenIDDefs::EndConfluenceBlock(bool no_orig_flow)
	{
	auto s = confluence_blocks.back();
	auto ids = modified_IDs.back();

	for ( auto id : ids )
		id->GetOptInfo()->ConfluenceBlockEndsAt(s, no_orig_flow);

	confluence_blocks.pop_back();
	modified_IDs.pop_back();
	}

void GenIDDefs::BranchBackTo(const Stmt* s)
	{
	if ( ! s )
		s = confluence_blocks.back();

	auto ids = modified_IDs.back();

	for ( auto id : ids )
		id->GetOptInfo()->BranchBackTo(s);
	}

void GenIDDefs::BranchBeyond(const Stmt* s)
	{
	auto ids = modified_IDs.back();

	for ( auto id : ids )
		id->GetOptInfo()->BranchBeyond(s);
	}

const Stmt* GenIDDefs::FindLoop()
	{
	int i = confluence_blocks.size() - 1;
	while ( i >= 0 )
		{
		auto t = confluence_blocks[i]->Tag();
		if ( t == STMT_WHILE || t == STMT_FOR )
			break;

		--i;
		}

	ASSERT(i >= 0);

	return confluence_blocks[i];
	}

const Stmt* GenIDDefs::FindBranchBeyondTarget()
	{
	int i = confluence_blocks.size() - 1;
	while ( i >= 0 )
		{
		auto t = confluence_blocks[i]->Tag();
		if ( t == STMT_WHILE || t == STMT_FOR || t == STMT_SWITCH )
			break;

		--i;
		}

	ASSERT(i >= 0);

	return confluence_blocks[i];
	}

void GenIDDefs::ReturnAt(const Stmt* s)
	{
	auto ids = modified_IDs.back();

	for ( auto id : ids )
		id->GetOptInfo()->ReturnAt(s);
	}

void GenIDDefs::TrackID(const ID* id, bool is_init)
	{
	auto oi = id->GetOptInfo();

	if ( is_init && id->IsGlobal() )
		oi->Clear();

	const Stmt* conf_stmt;
	if ( confluence_blocks.size() > 0 )
		conf_stmt = confluence_blocks.back();
	else
		conf_stmt = nullptr;

	oi->DefinedAt(curr_stmt, conf_stmt);

	modified_IDs.back().insert(id);
	}

} // zeek::detail
