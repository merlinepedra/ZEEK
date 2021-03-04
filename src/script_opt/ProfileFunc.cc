// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/Desc.h"
#include "zeek/Stmt.h"
#include "zeek/Func.h"


namespace zeek::detail {


TraversalCode ProfileFunc::PreFunction(const Func* f)
	{
	TraverseType(f->GetType());

	// We do *not* continue into the body.  This is because for
	// functions with multiple bodies, we don't want to conflate
	// the properties of those bodies.  Instead, our caller needs
	// to explicitly pick the body of interest.
	return TC_ABORTSTMT;
	}

TraversalCode ProfileFunc::PreStmt(const Stmt* s)
	{
	++num_stmts;

	auto tag = s->Tag();

	if ( compute_hash )
		UpdateHash(int(tag));

	switch ( tag ) {
	case STMT_INIT:
		{
		for ( const auto& id : s->AsInitStmt()->Inits() )
			{
			inits.insert(id.get());

			if ( analyze_attrs )
				TraverseType(id->GetType());
			}

		skip_locals = true;
		}
		break;

	case STMT_WHEN:
		++num_when_stmts;

		in_when = true;
		s->AsWhenStmt()->Cond()->Traverse(this);
		in_when = false;

		// It doesn't do any harm for us to re-traverse the
		// conditional, so we don't bother hand-traversing the
		// rest of the when but just let the usual processing do it.
		break;

	case STMT_FOR:
		{
		auto sf = s->AsForStmt();
		auto loop_vars = sf->LoopVars();
		auto value_var = sf->ValueVar();

		for ( auto id : *loop_vars )
			locals.insert(id);

		if ( value_var )
			locals.insert(value_var.get());
		}
		break;

	case STMT_SWITCH:
		{
		// If this is a type-case switch statement, then find the
		// identifiers created so we can add them to our list of
		// locals.  Ideally this wouldn't be necessary since *surely*
		// if one bothers to define such an identifier then it'll be
		// subsequently used, and we'll pick up the local that way ...
		// but if for some reason it's not, then we would have an
		// incomplete list of locals that need to be tracked.

		auto sw = s->AsSwitchStmt();
		bool is_type_switch = false;

		for ( auto& c : *sw->Cases() )
			{
			auto idl = c->TypeCases();
			if ( idl ) 
				{
				for ( auto id : *idl )
					locals.insert(id);

				is_type_switch = true;
				}
			}

		if ( is_type_switch )
			type_switches.insert(sw);
		else
			expr_switches.insert(sw);
		}
		break;

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PostStmt(const Stmt* s)
	{
	if ( s->Tag() == STMT_INIT )
		skip_locals = false;

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PreExpr(const Expr* e)
	{
	++num_exprs;

	TraverseType(e->GetType());

	if ( compute_hash )
		UpdateHash(int(e->Tag()));

	switch ( e->Tag() ) {
	case EXPR_CONST:
		constants.insert(e->AsConstExpr());

		if ( compute_hash )
			UpdateHash(e->AsConstExpr()->ValuePtr());
		break;

	case EXPR_NAME:
		{
		auto n = e->AsNameExpr();
		auto id = n->Id();

		if ( id->IsGlobal() )
			{
			globals.insert(id);
			all_globals.insert(id);
			}

		else if ( in_lambda == 0 )
			{
			if ( id->Offset() < num_params )
				params.insert(id);

			if ( ! skip_locals )
				locals.insert(id);
			}

		if ( compute_hash )
			UpdateHash(id);

		break;
		}

	case EXPR_FIELD:
		if ( compute_hash )
			UpdateHash(e->AsFieldExpr()->Field());
		break;

	case EXPR_ASSIGN:
		{
		if ( e->GetOp1()->Tag() == EXPR_REF )
			{
			auto lhs = e->GetOp1()->GetOp1();
			if ( lhs->Tag() == EXPR_NAME )
				assignees.insert(lhs->AsNameExpr()->Id());
			}
		break;
		}

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();

		if ( f->Tag() != EXPR_NAME )
			{
			does_indirect_calls = true;
			return TC_CONTINUE;
			}

		auto n = f->AsNameExpr();
		auto func = n->Id();

		if ( compute_hash )
			UpdateHash(func);

		if ( ! func->IsGlobal() )
			{
			does_indirect_calls = true;
			return TC_CONTINUE;
			}

		all_globals.insert(func);

		auto func_v = func->GetVal();
		if ( func_v )
			{
			auto func_vf = func_v->AsFunc();

			if ( func_vf->GetKind() == Func::SCRIPT_FUNC )
				{
				auto bf = static_cast<ScriptFunc*>(func_vf);
				script_calls.insert(bf);

				if ( in_when )
					when_calls.insert(bf);
				}
			else
				BiF_calls.insert(func_vf);
			}
		else
			{
			// We could complain, but for now we don't because
			// if we're invoked prior to full Zeek initialization,
			// the value might indeed not there.
			// printf("no function value for global %s\n", func->Name());
			}

		// Recurse into the arguments.
		auto args = c->Args();
		args->Traverse(this);

		// Do the following explicitly, since we won't be recursing
		// into the LHS global.

		// Note that the type of the expression and the type of the
		// function can actually be *different* due to the NameExpr
		// being constructed based on a forward reference and then
		// the global getting a different (constructed) type when
		// the function is actually declared.  Geez.  So hedge our
		// bets.
		TraverseType(n->GetType());
		TraverseType(func->GetType());

		return TC_ABORTSTMT;
		}

	case EXPR_EVENT:
		events.insert(e->AsEventExpr()->Name());
		break;

	case EXPR_LAMBDA:
		++num_lambdas;
		++in_lambda;
		break;

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PostExpr(const Expr* e)
	{
	if ( e->Tag() == EXPR_LAMBDA )
		--in_lambda;

	return TC_CONTINUE;
	}

void ProfileFunc::TraverseType(const TypePtr& t)
	{
	if ( ! t || types.count(t.get()) > 0 )
		return;

	if ( compute_hash )
		CheckType(t);

	types.insert(t.get());

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ENUM:
	case TYPE_ERROR:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_OPAQUE:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_SUBNET:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_UNION:
	case TYPE_VOID:
		break;

	case TYPE_RECORD:
		{
		auto fields = t->AsRecordType()->Types();
		for ( const auto& f : *fields )
			{
			TraverseType(f->type);

			if ( f->attrs )
				{
				auto attrs = f->attrs->GetAttrs();

				for ( const auto& a : attrs )
					if ( a->GetExpr() )
						a->GetExpr()->Traverse(this);
				}
			}
		}
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();
		TraverseType(tbl->GetIndices());
		TraverseType(tbl->Yield());
		}
		break;

	case TYPE_FUNC:
		{
		auto ft = t->AsFuncType();
		TraverseType(ft->Params());
		TraverseType(ft->Yield());
		}
		break;

	case TYPE_LIST:
		{
		for ( const auto& tl : t->AsTypeList()->GetTypes() )
			TraverseType(tl);
		}
		break;

	case TYPE_VECTOR:
		TraverseType(t->AsVectorType()->Yield());
		break;

	case TYPE_FILE:
		TraverseType(t->AsFileType()->Yield());
		break;

	case TYPE_TYPE:
		TraverseType(t->AsTypeType()->GetType());
		break;
	}
	}

void ProfileFunc::CheckType(const TypePtr& t)
	{
	auto& tn = t->GetName();
	if ( tn.size() > 0 && seen_type_names.count(tn) > 0 )
		// No need to hash this in again, as we've already done so.
		return;

	seen_type_names.insert(tn);

	UpdateHash(t);
	}

void ProfileFunc::UpdateHash(const Obj* o)
	{
	ODesc d;
	o->Describe(&d);
	std::string desc(d.Description());
	auto h = std::hash<std::string>{}(desc);
	MergeInHash(h);
	}


} // namespace zeek::detail
