// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/CPPCompile.h"
#include "zeek/Desc.h"
#include "zeek/Stmt.h"
#include "zeek/Func.h"


namespace zeek::detail {


ProfileFunc::ProfileFunc(const Func* func, const StmtPtr& body)
	{
	Profile(func->GetType().get(), body);
	}

ProfileFunc::ProfileFunc(const Expr* e)
	{
	if ( e->Tag() == EXPR_LAMBDA )
		{
		auto func = e->AsLambdaExpr();
		Profile(func->GetType()->AsFuncType(), func->Ingredients().body);
		}

	else
		e->Traverse(this);
	}

void ProfileFunc::Profile(const FuncType* ft, const StmtPtr& body)
	{
	num_params = ft->Params()->NumFields();
	RecordType(ft);
	body->Traverse(this);
	}

TraversalCode ProfileFunc::PreStmt(const Stmt* s)
	{
	stmts.push_back(s);

	auto tag = s->Tag();

	switch ( tag ) {
	case STMT_INIT:
		for ( const auto& id : s->AsInitStmt()->Inits() )
			{
			inits.insert(id.get());
			RecordType(id->GetType());
			}

		// Don't traverse further into the statement, since we
		// don't want to view the identifiers as locals unless
		// they're also used elsewhere.
		return TC_ABORTSTMT;

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

TraversalCode ProfileFunc::PreExpr(const Expr* e)
	{
	exprs.push_back(e);

	RecordType(e->GetType());

	switch ( e->Tag() ) {
	case EXPR_CONST:
		constants.push_back(e->AsConstExpr());
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

		else
			{
			if ( id->Offset() < num_params )
				params.insert(id);

			locals.insert(id);
			}

		// This can differ from the type of the encompassing
		// expression.
		RecordType(id->GetType());

		break;
		}

	case EXPR_FIELD:
		addl_ints.push_back(e->AsFieldExpr()->Field());
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
				BiF_globals.insert(func);
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
		RecordType(n->GetType());
		RecordType(func->GetType());

		RecordID(func);

		return TC_ABORTSTMT;
		}

	case EXPR_EVENT:
		events.insert(e->AsEventExpr()->Name());
		break;

	case EXPR_LAMBDA:
		{
		auto l = e->AsLambdaExpr();
		lambdas.push_back(l);
		for ( const auto& i : l->OuterIDs() )
			{
			locals.insert(i);
			RecordID(i);
			}

		// Avoid recursing into the body.
		return TC_ABORTSTMT;
		}

	default:
		break;
	}

	return TC_CONTINUE;
	}

TraversalCode ProfileFunc::PreID(const ID* id)
	{
	RecordID(id);
	return TC_ABORTSTMT;
	}

void ProfileFunc::RecordType(const Type* t)
	{
	if ( ! t )
		return;

	if ( types.count(t) > 0 )
		return;

	types.insert(t);
	ordered_types.push_back(t);
	}

void ProfileFunc::RecordID(const ID* id)
	{
	if ( ! id )
		return;

	if ( ids.count(id) > 0 )
		return;

	ids.insert(id);
	ordered_ids.push_back(id);
	}


ProfileFuncs::ProfileFuncs(std::vector<FuncInfo>& funcs)
	{
	std::vector<const LambdaExpr*> lambda_exprs;

	for ( auto& f : funcs )
		{
		if ( f.Skip() )
			continue;

		auto pf = std::make_unique<ProfileFunc>(f.Func(), f.Body());

		if ( is_CPP_compilable(pf.get()) )
			MergeInProfile(pf.get());
		else
			f.SetSkip();

		f.SetProfile(std::move(pf));
		func_profs[f.Func()] = f.Profile();
		}

	ComputeTypeHashes(main_types);
	DrainPendingExprs();
	ComputeBodyHashes(funcs);
	}

void ProfileFuncs::MergeInProfile(ProfileFunc* pf)
	{
	all_globals.insert(pf->AllGlobals().begin(), pf->AllGlobals().end());
	globals.insert(pf->Globals().begin(), pf->Globals().end());
	constants.insert(pf->Constants().begin(), pf->Constants().end());
	main_types.insert(pf->Types().begin(), pf->Types().end());
	script_calls.insert(pf->ScriptCalls().begin(), pf->ScriptCalls().end());
	BiF_globals.insert(pf->BiFGlobals().begin(), pf->BiFGlobals().end());
	events.insert(pf->Events().begin(), pf->Events().end());

	for ( auto& i : pf->Lambdas() )
		{
		lambdas.insert(i);
		pending_exprs.push_back(i);
		}
	}

void ProfileFuncs::DrainPendingExprs()
	{
	while ( pending_exprs.size() > 0 )
		{
		// Copy the pending expressions so we can loop over them
		// while accruing additions.
		auto pe = pending_exprs;
		pending_exprs.clear();

		for ( auto e : pe )
			{
			auto pf = std::make_shared<ProfileFunc>(e);

			expr_profs[e] = pf;
			MergeInProfile(pf.get());

			ComputeTypeHashes(pf->Types());
			}
		}
	}

void ProfileFuncs::ComputeTypeHashes(const std::unordered_set<const Type*>& type_set)
	{
	for ( auto t : type_set )
		(void) HashType(t);
	}

void ProfileFuncs::ComputeBodyHashes(std::vector<FuncInfo>& funcs)
	{
	for ( auto& f : funcs )
		if ( ! f.Skip() )
			ComputeProfileHash(f.Profile());

	for ( auto& l : lambdas )
		ComputeProfileHash(ExprProf(l));
	}

void ProfileFuncs::ComputeProfileHash(ProfileFunc* pf)
	{
	hash_type h = 0;

	for ( auto i : pf->Stmts() )
		h = MergeHashes(h, Hash(i->Tag()));

	for ( auto i : pf->Exprs() )
		h = MergeHashes(h, Hash(i->Tag()));

	for ( auto i : pf->OrderedIdentifiers() )
		h = MergeHashes(h, hash_string(i->Name()));

	for ( auto i : pf->Constants() )
		h = MergeHashes(h, hash_obj(i->Value()));

	for ( auto i : pf->OrderedTypes() )
		h = MergeHashes(h, HashType(i));

	for ( auto i : pf->Lambdas() )
		h = MergeHashes(h, hash_obj(i));

	for ( auto i : pf->AdditionalInts() )
		h = MergeHashes(h, Hash(i));

	pf->SetHashVal(h);
	}

hash_type ProfileFuncs::HashType(const Type* t)
	{
	if ( ! t )
		return 0;

	if ( type_hashes.count(t) > 0 )
		return type_hashes[t];

	auto& tn = t->GetName();
	if ( tn.size() > 0 && seen_type_names.count(tn) > 0 )
		{
		auto seen_t = seen_type_names[tn];
		auto h = type_hashes[seen_t];

		type_hashes[t] = h;
		type_to_rep[t] = type_to_rep[seen_t];

		return h;
		}

	auto h = Hash(t->Tag());

	// Enter an initial value for this type's hash.  We'll update it
	// at the end, but having it here first will prevent recursive
	// records from leading to infinite recursion as we traverse them.
	// It's okay that the initial value is degenerate, as if we access
	// it during the traversal that will only happen due to a recursive
	// type, in which case the other elements of that type will serve
	// to differentiate its hash.
	type_hashes[t] = h;

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
		h = MergeHashes(h, hash_obj(t));
		break;

	case TYPE_RECORD:
		{
		auto fields = t->AsRecordType()->Types();
		h = MergeHashes(h, Hash(fields->size()));

		for ( const auto& f : *fields )
			{
			h = MergeHashes(h, HashType(f->type));

			// We don't hash the field name, as in some contexts
			// those are ignored.

			if ( f->attrs )
				{
				h = MergeHashes(h, hash_obj(f->attrs));

				auto attrs = f->attrs->GetAttrs();

				for ( const auto& a : attrs )
					{
					const Expr* e = a->GetExpr().get();

					if ( e )
						{
						pending_exprs.push_back(e);
						if ( e->Tag() == EXPR_LAMBDA )
							lambdas.insert(e->AsLambdaExpr());
						}
					}
				}
			}
		}
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();
		h = MergeHashes(h, HashType(tbl->GetIndices()));
		h = MergeHashes(h, HashType(tbl->Yield()));
		}
		break;

	case TYPE_FUNC:
		{
		auto ft = t->AsFuncType();
		h = MergeHashes(h, HashType(ft->Params()));
		h = MergeHashes(h, HashType(ft->Yield()));
		}
		break;

	case TYPE_LIST:
		{
		auto& tl = t->AsTypeList()->GetTypes();

		h = MergeHashes(h, Hash(tl.size()));

		for ( const auto& tl_i : tl )
			h = MergeHashes(h, HashType(tl_i));
		}
		break;

	case TYPE_VECTOR:
		h = MergeHashes(h, HashType(t->AsVectorType()->Yield()));
		break;

	case TYPE_FILE:
		h = MergeHashes(h, HashType(t->AsFileType()->Yield()));
		break;

	case TYPE_TYPE:
		h = MergeHashes(h, HashType(t->AsTypeType()->GetType()));
		break;
	}

	type_hashes[t] = h;

	if ( type_hash_reps.count(h) == 0 )
		{
		type_hash_reps[h] = t;
		type_to_rep[t] = t;
		rep_types.push_back(t);
		}
	else
		type_to_rep[t] = type_hash_reps[h];

	if ( tn.size() > 0 )
		seen_type_names[tn] = t;

	return h;
	}


hash_type hash_obj(const Obj* o)
	{
	ODesc d;
	o->Describe(&d);
	std::string desc(d.Description());
	auto h = std::hash<std::string>{}(desc);
	return h;
	}

} // namespace zeek::detail
