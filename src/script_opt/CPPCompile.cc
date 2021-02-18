// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPPCompile.h"
#include "zeek/script_opt/ProfileFunc.h"


namespace zeek::detail {

void CPPCompile::CompileTo(FILE* f)
	{
	write_file = f;

	GenProlog();

	for ( const auto& func : funcs )
		if ( IsCompilable(func) )
			compilable_funcs.insert(func.Func()->Name());

	for ( const auto& func : funcs )
		DeclareGlobals(func);

	for ( const auto& func : funcs )
		DeclareGlobals(func);

	for ( const auto& func : funcs )
		DeclareFunc(func);

	NL();

	for ( const auto& func : funcs )
		CompileFunc(func);

	GenEpilog();
	}

void CPPCompile::GenProlog()
	{
	Emit("#include \"zeek/script_opt/CPPProlog.h\"");
	NL();
	}

void CPPCompile::GenEpilog()
	{
	NL();

	for ( const auto& e : init_exprs.Keys() )
		GenInitExpr(e);

	for ( const auto& a : attributes.Keys() )
		GenAttrs(a);

	// Generate the guts of compound types.
	for ( const auto& t : types.Keys() )
		ExpandTypeVar(t);

	NL();
	Emit("void init__CPP()");

	StartBlock();

	Emit("types__CPP = new TypePtr[%s];", Fmt(types.Size()));

	NL();
	for ( const auto& i : pre_inits )
		Emit(i);

	NL();

	std::unordered_set<const Obj*> to_do;
	for ( const auto& oi : obj_inits )
		to_do.insert(oi.first);

	// Check for consistency.
	for ( const auto& od : obj_deps )
		{
		const auto& o = od.first;

		if ( to_do.count(o) == 0 )
			{
			fprintf(stderr, "object not in to_do: %s\n",
				obj_desc(o).c_str());
			exit(1);
			}

		for ( const auto& d : od.second )
			{
			if ( to_do.count(d) == 0 )
				{
				fprintf(stderr, "dep object for %s not in to_do: %s\n",
					obj_desc(o).c_str(), obj_desc(d).c_str());
				exit(1);
				}
			}
		}

	while ( to_do.size() > 0 )
		{
		std::unordered_set<const Obj*> done;

		for ( const auto& o : to_do )
			{
			const auto& od = obj_deps.find(o);

			bool has_pending_dep = false;

			if ( od != obj_deps.end() )
				{
				for ( const auto& d : od->second )
					if ( to_do.count(d) > 0 )
						{
						has_pending_dep = true;
						break;
						}
				}

			if ( has_pending_dep )
				continue;

			for ( const auto& i : obj_inits.find(o)->second )
				Emit("%s", i);

			done.insert(o);
			}

		ASSERT(done.size() > 0);

		for ( const auto& o : done )
			{
			ASSERT(to_do.count(o) > 0);
			to_do.erase(o);
			}

		NL();
		}

	// ... and then instantiate the functions themselves.
	NL();
	for ( const auto& f : compiled_funcs )
		Emit("%s_func = new %s();", f, f);

	EndBlock(true);

	Emit("} // zeek::detail");
	Emit("} // zeek");
	}

bool CPPCompile::IsCompilable(const FuncInfo& func)
	{
	if ( func.Func()->Flavor() != FUNC_FLAVOR_FUNCTION )
		return false;

	const auto& pf = func.Profile();

	if ( pf->NumWhenStmts() > 0 )
		return false;

	if ( pf->TypeSwitches().size() > 0 )
		return false;

	for ( const auto& sw : pf->ExprSwitches() )
		{
		auto it = sw->StmtExpr()->GetType()->InternalType();
		if ( it != TYPE_INTERNAL_INT && it != TYPE_INTERNAL_UNSIGNED )
			return false;
		}

	return true;
	}

void CPPCompile::DeclareGlobals(const FuncInfo& func)
	{
	if ( ! IsCompilable(func) )
		return;

	for ( const auto& b : func.Profile()->BiFCalls() )
		AddBiF(b);

	for ( const auto& g : func.Profile()->AllGlobals() )
		{
		auto gn = std::string(g->Name());
		if ( globals.count(gn) > 0 )
			// Already processed.
			continue;

		if ( compilable_funcs.count(gn) > 0 )
			{
			AddGlobal(g->Name(), "zf");
			const auto& ggn = globals[gn];

			Emit("FuncValPtr %s;", ggn);
			AddInit(g, ggn,
				std::string("make_intrusive<FuncVal>(") +
				ggn + "_func)");
			}

		else
			{
			AddGlobal(gn.c_str(), "gl");
			Emit("IDPtr %s;", globals[gn]);
			AddInit(g, globals[gn],
				std::string("lookup_global__CPP(\"") +
				gn + "\")");

			if ( bifs.count(gn) == 0 )
				global_vars.emplace(g);
			}
		}

	for ( const auto& e : func.Profile()->Events() )
		{
		AddGlobal(e, "ev");
		const auto& ev = globals[std::string(e)];

		if ( declared_events.count(ev) == 0 )
			{
			Emit("EventHandlerPtr %s;", ev);
			AddInit(nullptr, ev,
				std::string("register_event__CPP(\"") + e + "\")");
			declared_events.insert(ev);
			}
		}

	for ( const auto& c : func.Profile()->Constants() )
		AddConstant(c);
	}

void CPPCompile::AddBiF(const Func* b)
	{
	auto n = b->Name();

	if ( globals.count(n) > 0 )
		return;

	AddGlobal(n, "bif");
	bifs.insert(n);

	std::string ns(n);
	Emit("Func* %s;", globals[ns]);

	AddInit(b, globals[ns], std::string("lookup_bif__CPP(\"") + ns + "\")");
	}

void CPPCompile::AddGlobal(const std::string& g, const char* suffix)
	{
	if ( globals.count(g) == 0 )
		globals.emplace(g, GlobalName(g, suffix));
	}

void CPPCompile::AddConstant(const ConstExpr* c)
	{
	if ( IsNativeType(c->GetType()) )
		// These we instantiate directly.
		return;

	if ( const_exprs.count(c) > 0 )
		// Already did this one.
		return;

	auto v = c->Value();
	ODesc d;
	d.SetQuotes(true);
	v->Describe(&d);

	std::string c_desc(d.Description());

	if ( constants.count(c_desc) == 0 )
		{
		// Need a C++ global for this constant.
		auto const_name = std::string("CPP__const__") +
					Fmt(int(constants.size()));

		constants[c_desc] = const_name;
		auto tag = c->GetType()->Tag();

		switch ( tag ) {
		case TYPE_STRING:
			{
			Emit("StringValPtr %s;", const_name);
			auto def = std::string("make_intrusive<StringVal>(") +
					c_desc + ")";
			AddInit(c, const_name, def);
			}
			break;

		case TYPE_PATTERN:
			{
			Emit("PatternValPtr %s;", const_name);

			auto re = v->AsPatternVal()->Get();

			AddInit(c,
				std::string("{ auto re = new RE_Matcher(\"") +
				re->OrigText() + "\");");
			if ( re->IsCaseInsensitive() )
				AddInit(c, "re->MakeCaseInsensitive();");
			AddInit(c, "re->Compile();");
			AddInit(c, const_name, "make_intrusive<PatternVal>(re)");
			AddInit(c, "}");
			}
			break;

		case TYPE_ADDR:
		case TYPE_SUBNET:
			{
			auto prefix = (tag == TYPE_ADDR) ? "Addr" : "SubNet";

			Emit("%sValPtr %s;", prefix, const_name);

			ODesc d;
			v->Describe(&d);

			AddInit(c, const_name,
				std::string("make_intrusive<") + prefix +
				"Val>(\"" + d.Description() + "\")");
			}
			break;

		default:
			reporter->InternalError("bad constant type in CPPCompile::AddConstant");
		}
		}

	const_exprs[c] = constants[c_desc];
	}

void CPPCompile::DeclareFunc(const FuncInfo& func)
	{
	if ( ! IsCompilable(func) )
		return;

	NL();

	auto fname = Canonicalize(func.Func()->Name()) + "__zfc";
	DeclareSubclass(func, fname);

	body_names.emplace(func.Body().get(), fname);
	}

void CPPCompile::CompileFunc(const FuncInfo& func)
	{
	if ( ! IsCompilable(func) )
		return;

	NL();
	DefineBody(func, body_names[func.Body().get()]);
	}

void CPPCompile::DeclareSubclass(const FuncInfo& func, const std::string& fname)
	{
	auto is_pure = func.Func()->IsPure();

	Emit("class %s : public CPPFunc", fname);
	StartBlock();

	Emit("public:");
	Emit("%s() : CPPFunc(\"%s\", %s)", fname, func.Func()->Name(),
		is_pure ? "true" : "false");
	StartBlock();
	GenSubclassTypeAssignment(func.Func());
	EndBlock();

	const auto& ft = func.Func()->GetType();
	const auto& yt = ft->Yield();

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override");
	StartBlock();

	if ( IsNativeType(yt) )
		{
		auto args = BindArgs(func.Func()->GetType());
		GenInvokeBody(yt, args);
		}
	else
		Emit("return Call(%s);", BindArgs(func.Func()->GetType()));

	EndBlock();

	Emit("static %s Call(%s);", FullTypeName(yt),
		ParamDecl(ft, func.Profile()));

	EndBlock(true);

	Emit("%s* %s;", fname, fname + "_func");

	compiled_funcs.emplace(fname);
	}

void CPPCompile::GenSubclassTypeAssignment(Func* f)
	{
	Emit("type = cast_intrusive<FuncType>(%s);",
		GenTypeName(f->GetType()));
	}

void CPPCompile::GenInvokeBody(const TypePtr& t, const std::string& args)
	{
	auto call = std::string("Call(") + args + ")";

	if ( t->Tag() == TYPE_VOID )
		{
		Emit("%s;", call);
		Emit("return nullptr;");
		}
	else
		Emit("return %s;", NativeToGT(call, t, GEN_VAL_PTR));
	}

void CPPCompile::DefineBody(const FuncInfo& func, const std::string& fname)
	{
	locals.clear();
	params.clear();

	const auto& ft = func.Func()->GetType();
	ret_type = ft->Yield();

	for ( const auto& p : func.Profile()->Params() )
		params.emplace(p);

	Emit("%s %s::Call(%s)", FullTypeName(ret_type), fname,
		ParamDecl(ft, func.Profile()));

	StartBlock();

	// Emit("fprintf(stderr, \"executing %s\\n\");", func.Func()->Name());

	DeclareLocals(func);
	GenStmt(func.Body());

	EndBlock();
	}

void CPPCompile::DeclareLocals(const FuncInfo& func)
	{
	const auto& ls = func.Profile()->Locals();

	bool did_decl = false;

	for ( const auto& l : ls )
		{
		auto ln = LocalName(l);

		if ( params.count(l) == 0 )
			{
			Emit("%s %s;", FullTypeName(l->GetType()), ln);
			did_decl = true;
			}

		locals.emplace(l, ln);
		}

	if ( did_decl )
		NL();
	}

std::string CPPCompile::BindArgs(const FuncTypePtr& ft)
	{
	const auto& params = ft->Params();

	std::string res;

	int n = params->Types()->size();
	for ( auto i = 0; i < n; ++i )
		{
		auto arg_i = std::string("(*args)[") + Fmt(i) + "]";
		const auto& ft = params->GetFieldType(i);

		if ( IsNativeType(ft) )
			res += arg_i + NativeAccessor(ft);
		else
			res += GenericValPtrToGT(arg_i, ft, GEN_VAL_PTR);

		res += ", ";
		}

	return res + "parent";
	}

void CPPCompile::GenStmt(const Stmt* s)
	{
	switch ( s->Tag() ) {
	case STMT_INIT:
		{
		auto init = s->AsInitStmt();
		auto inits = s->AsInitStmt()->Inits();

		for ( const auto& aggr : inits )
			{
			const auto& t = aggr->GetType();

			if ( ! IsAggr(t->Tag()) )
				continue;

			auto type_name = IntrusiveVal(t);
			auto type_type = TypeType(t);
			auto type_ind = GenTypeName(t);

			Emit("%s = make_intrusive<%s>(cast_intrusive<%s>(%s));",
				IDName(aggr), type_name,
				type_type, type_ind);
			}
		}
		break;

	case STMT_LIST:
		{
		// These always occur in contexts surrounded by {}'s.
		auto sl = s->AsStmtList();
		const auto& stmts = sl->Stmts();

		for ( const auto& stmt : stmts )
			GenStmt(stmt);
		}
		break;

	case STMT_EXPR:
		{
		auto e = s->AsExprStmt()->StmtExpr();

		if ( e )
			Emit("%s;", GenExpr(e, GEN_DONT_CARE, true));
		}
		break;

	case STMT_IF:
		{
		auto i = s->AsIfStmt();
		auto cond = i->StmtExpr();

		Emit("if ( %s )", GenExpr(cond, GEN_NATIVE));
		StartBlock();
		GenStmt(i->TrueBranch());
		EndBlock();

		const auto& fb = i->FalseBranch();

		if ( fb->Tag() != STMT_NULL )
			{
			Emit("else");
			StartBlock();
			GenStmt(i->FalseBranch());
			EndBlock();
			}
		}
		break;


	case STMT_WHILE:
		{
		auto w = s->AsWhileStmt();
		Emit("while ( %s )",
			GenExpr(w->Condition(), GEN_NATIVE));
		StartBlock();
		GenStmt(w->Body());
		EndBlock();
		}
		break;

	case STMT_NULL:
		Emit(";");
		break;

	case STMT_RETURN:
		{
		auto e = s->AsReturnStmt()->StmtExpr();

		if ( ! e || e->GetType()->Tag() == TYPE_VOID )
			{
			Emit("return;");
			break;
			}

		auto gt = ret_type->Tag() == TYPE_ANY ?
				GEN_VAL_PTR : GEN_NATIVE;

		auto ret = GenExpr(e, gt);

		if ( e->GetType()->Tag() == TYPE_ANY )
			ret = GenericValPtrToGT(ret, ret_type, gt);

		Emit("return %s;", ret);
		}
		break;

	case STMT_ADD:
		{
		auto op = static_cast<const ExprStmt*>(s)->StmtExpr();
		auto aggr = GenExpr(op->GetOp1(), GEN_DONT_CARE);
		auto indices = op->GetOp2();

		Emit("%s->Assign(index_val__CPP({%s}), nullptr, true);",
			aggr, GenExpr(indices, GEN_VAL_PTR));
		}
		break;

	case STMT_DELETE:
		{
		auto op = static_cast<const ExprStmt*>(s)->StmtExpr();
		auto aggr = GenExpr(op->GetOp1(), GEN_DONT_CARE);

		if ( op->Tag() == EXPR_INDEX )
			{
			auto indices = op->GetOp2();

			Emit("%s->Remove(*(index_val__CPP({%s}).get()), true);",
				aggr, GenExpr(indices, GEN_VAL_PTR));
			}

		else
			{
			ASSERT(op->Tag() == EXPR_FIELD);
			auto field = Fmt(op->AsFieldExpr()->Field());
			Emit("%s->Assign(%s, nullptr);", aggr, field);
			}
		}
		break;

	case STMT_FOR:
		{
		auto f = s->AsForStmt();
		auto v = f->StmtExpr();
		auto value_var = f->ValueVar();
		auto loop_vars = f->LoopVars();

		Emit("{ // begin a new scope for the internal loop vars");

		auto t = v->GetType()->Tag();

		if ( t == TYPE_TABLE )
			{
			Emit("auto tv__CPP = %s;", GenExpr(v, GEN_DONT_CARE));
			Emit("const PDict<TableEntryVal>* loop_vals__CPP = tv__CPP->AsTable();");

			Emit("if ( loop_vals__CPP->Length() > 0 )");
			StartBlock();

			Emit("for ( const auto& lve__CPP : *loop_vals__CPP )");
			StartBlock();

			Emit("auto k__CPP = lve__CPP.GetHashKey();");
			Emit("auto* current_tev__CPP = lve__CPP.GetValue<TableEntryVal*>();");
			Emit("auto ind_lv__CPP = tv__CPP->RecreateIndex(*k__CPP);");

                        if ( value_var )
				Emit("%s = %s;",
					IDName(value_var),
					GenericValPtrToGT("current_tev__CPP->GetVal()",
						value_var->GetType(),
						GEN_NATIVE));

			for ( int i = 0; i < loop_vars->length(); ++i )
				{
				auto var = (*loop_vars)[i];
				const auto& v_t = var->GetType();
				auto acc = NativeAccessor(v_t);

				if ( IsNativeType(v_t) )
					Emit("%s = ind_lv__CPP->Idx(%s)%s;",
						IDName(var), Fmt(i), acc);
				else
					Emit("%s = {NewRef{}, ind_lv__CPP->Idx(%s)%s};",
						IDName(var), Fmt(i), acc);
				}

			GenStmt(f->LoopBody());
			EndBlock();
			EndBlock();
			}

		else if ( t == TYPE_VECTOR )
			{
			Emit("auto vv__CPP = %s;", GenExpr(v, GEN_DONT_CARE));

			Emit("for ( auto i__CPP = 0u; i__CPP < vv__CPP->Size(); ++i__CPP )");
			StartBlock();

			Emit("if ( ! vv__CPP->At(i__CPP) ) continue;");
			Emit("%s = i__CPP;", IDName((*loop_vars)[0]));

			GenStmt(f->LoopBody());
			EndBlock();
			}

		else if ( t == TYPE_STRING )
			{
			Emit("auto sval__CPP = %s;",
				GenExpr(v, GEN_DONT_CARE));

			Emit("for ( auto i__CPP = 0u; i__CPP < sval__CPP->Len(); ++i__CPP )");
			StartBlock();

			Emit("auto sv__CPP = make_intrusive<StringVal>(1, (const char*) sval__CPP->Bytes() + i__CPP);");
			Emit("%s = std::move(sv__CPP);", IDName((*loop_vars)[0]));

			GenStmt(f->LoopBody());
			EndBlock();
			}

		else
			reporter->InternalError("bad for statement in CPPCompile::GenStmt");

		Emit("} // end of for scope");
		}
		break;

	case STMT_NEXT:
		Emit("continue;");
		break;

	case STMT_BREAK:
		Emit("break;");
		break;

	case STMT_PRINT:
		{
		auto el = static_cast<const ExprListStmt*>(s)->ExprList();
		Emit("do_print_stmt({%s});", GenExpr(el, GEN_VAL_PTR));
		}
		break;

	case STMT_EVENT:
		{
		auto ev_s = static_cast<const EventStmt*>(s)->StmtExprPtr();
		auto ev_e = cast_intrusive<EventExpr>(ev_s);

		if ( ev_e->Args()->Exprs().length() > 0 )
			Emit("event_mgr.Enqueue(%s, %s);",
				globals[std::string(ev_e->Name())],
				GenExpr(ev_e->Args(), GEN_VAL_PTR));
		else
			Emit("event_mgr.Enqueue(%s, Args{});",
				globals[std::string(ev_e->Name())]);
		}
		break;

	case STMT_SWITCH:
		{
		auto sw = static_cast<const SwitchStmt*>(s);
		auto e = sw->StmtExpr();
		auto cases = sw->Cases();

		Emit("switch ( %s ) {", GenExpr(e, GEN_NATIVE));

		bool is_int = e->GetType()->InternalType() == TYPE_INTERNAL_INT;

		for ( const auto& c : *cases )
			{
			if ( c->ExprCases() )
				{
				const auto& c_e_s =
					c->ExprCases()->AsListExpr()->Exprs();

				for ( const auto& c_e : c_e_s )
					{
					auto c_v = c_e->Eval(nullptr);
					ASSERT(c_v);
					auto c_v_rep = Fmt(is_int ?
								c_v->AsInt() :
								c_v->AsCount());
					Emit("case %s:", c_v_rep);
					}
				}

			else
				Emit("default:");

			StartBlock();
			GenStmt(c->Body());
			EndBlock();
			}

		Emit("}");
		}
		break;

	case STMT_FALLTHROUGH:
		break;

	case STMT_WHEN:
		ASSERT(0);
		break;

	default:
		reporter->InternalError("bad statement type in CPPCompile::GenStmt");
	}
	}

std::string CPPCompile::GenExpr(const Expr* e, GenType gt, bool top_level)
	{
	const auto& t = e->GetType();

	std::string gen;

	switch ( e->Tag() ) {
	case EXPR_NAME:
		{
		auto n = e->AsNameExpr()->Id();

		if ( global_vars.count(n) > 0 )
			return GenericValPtrToGT(globals[n->Name()] + "->GetVal()",
							t, gt);

		return NativeToGT(IDNameStr(n), t, gt);
		}

	case EXPR_CONST:
		{
		auto c = e->AsConstExpr();

		if ( ! IsNativeType(t) )
			return NativeToGT(const_exprs[c], t, gt);

		auto v = c->Value();
		auto tag = t->Tag();

		// Check for types that don't render into what
		// C++ expects.

		if ( tag == TYPE_BOOL )
			gen = std::string(v->IsZero() ? "false" : "true");

		else if ( tag == TYPE_ENUM )
			gen = Fmt(v->AsEnum());

		else if ( tag == TYPE_PORT )
			gen = Fmt(v->AsCount());

		else if ( tag == TYPE_INTERVAL )
			gen = Fmt(v->AsDouble());

		else
			{
			ODesc d;
			d.SetQuotes(true);
			v->Describe(&d);
			gen = std::string(d.Description());
			}

		return NativeToGT(gen, t, gt);
		}

	case EXPR_CLONE:
		gen = GenExpr(e->GetOp1(), GEN_VAL_PTR) + "->Clone()";
		return GenericValPtrToGT(gen, t, gt);

	case EXPR_INCR:
	case EXPR_DECR:
		{
		// For compound operands (table indexing, record fields),
		// Zeek's interpreter will actually evaluate the operand
		// twice, so easiest is to just transform this node
		// into the expanded equivalent.
		auto op = e->GetOp1();
		auto one = make_intrusive<ConstExpr>(val_mgr->Int(1));

		ExprPtr rhs;
		if ( e->Tag() == EXPR_INCR )
			rhs = make_intrusive<AddExpr>(op, one);
		else
			rhs = make_intrusive<SubExpr>(op, one);

		auto assign = make_intrusive<AssignExpr>(op, rhs, false,
						nullptr, nullptr, false);

		gen = GenExpr(assign, GEN_DONT_CARE);

		if ( ! top_level )
			gen = "(" + gen + ", " + GenExpr(op, gt) + ")";

		return gen;
		}

	case EXPR_NOT:		return GenUnary(e, gt, "!");
	case EXPR_COMPLEMENT:	return GenUnary(e, gt, "~");
	case EXPR_POSITIVE:	return GenUnary(e, gt, "+");
	case EXPR_NEGATE:	return GenUnary(e, gt, "-");

	case EXPR_ADD:		return GenBinary(e, gt, "+");
	case EXPR_SUB:		return GenBinary(e, gt, "-");
	case EXPR_REMOVE_FROM:	return GenBinary(e, gt, "-=");
	case EXPR_TIMES:	return GenBinary(e, gt, "*");
	case EXPR_DIVIDE:	return GenBinary(e, gt, "/");
	case EXPR_MOD:		return GenBinary(e, gt, "%");
	case EXPR_AND:		return GenBinary(e, gt, "&");
	case EXPR_OR:		return GenBinary(e, gt, "|");
	case EXPR_XOR:		return GenBinary(e, gt, "^");
	case EXPR_AND_AND:	return GenBinary(e, gt, "&&");
	case EXPR_OR_OR:	return GenBinary(e, gt, "||");
	case EXPR_LT:		return GenBinary(e, gt, "<");
	case EXPR_LE:		return GenBinary(e, gt, "<=");
	case EXPR_GE:		return GenBinary(e, gt, ">=");
	case EXPR_GT:		return GenBinary(e, gt, ">");

	case EXPR_EQ:		return GenEQ(e, gt, "==");
	case EXPR_NE:		return GenEQ(e, gt, "!=");

	case EXPR_COND:
		{
		auto op1 = e->GetOp1();
		auto op2 = e->GetOp2();
		auto op3 = e->GetOp3();

		auto gen1 = GenExpr(op1, GEN_NATIVE);
		auto gen2 = GenExpr(op2, gt);
		auto gen3 = GenExpr(op3, gt);

		return std::string("(") + gen1 + ") ? (" +
			gen2 + ") : (" + gen3 + ")";
		}

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();
		auto args_l = c->Args();

		gen = GenExpr(f, GEN_DONT_CARE);

		if ( f->Tag() == EXPR_NAME )
			{
			auto func = f->AsNameExpr()->Id();
			auto func_name = IDNameStr(func);

			if ( compiled_funcs.count(func_name) > 0 )
				{
				if ( args_l->Exprs().length() > 0 )
					gen += "_func->Call(" +
						GenArgs(args_l) + ", f__CPP)";
				else
					gen += "_func->Call(f__CPP)";

				return NativeToGT(gen, t, gt);
				}

			// If the function is a global and isn't (known as)
			// a BiF, then it will have been declared as a ValPtr
			// and we need to convert it to a Func*.
			if ( globals.count(func->Name()) > 0 &&
			     bifs.count(func->Name()) == 0 )
				gen = gen + "->AsFunc()";
			}

		else
			// Indirect call.
			gen = std::string("(") + gen + ")->AsFunc()";

		auto args_list = std::string(", {") +
					GenExpr(args_l, GEN_VAL_PTR) + "}";
		auto invoker = std::string("invoke__CPP(") +
					gen + args_list + ", f__CPP)";

		if ( IsNativeType(t) && gt != GEN_VAL_PTR )
			return invoker + NativeAccessor(t);

		return GenericValPtrToGT(invoker, t, gt);
		}

	case EXPR_LIST:
		{
		const auto& exprs = e->AsListExpr()->Exprs();

		int n = exprs.size();

		for ( auto i = 0; i < n; ++i )
			{
			gen = gen + GenExpr(exprs[i], gt);
			if ( i < n - 1 )
				gen += ", ";
			}

		return gen;
		}

	case EXPR_IN:
		{
		auto op1 = e->GetOp1();
		auto op2 = e->GetOp2();

		auto t1 = op1->GetType();
		auto t2 = op2->GetType();

		if ( t1->Tag() == TYPE_PATTERN )
			gen = std::string("(") + GenExpr(op1, GEN_DONT_CARE) +
				")->MatchAnywhere(" +
				GenExpr(op2, GEN_DONT_CARE) + "->AsString())";

		else if ( t2->Tag() == TYPE_STRING )
			// CPP__str_in(s1, s2): return util::strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1
			gen = std::string("str_in__CPP(") +
				GenExpr(op1, GEN_DONT_CARE) + "->AsString(), " +
				GenExpr(op2, GEN_DONT_CARE) + "->AsString())";

		else if ( t1->Tag() == TYPE_ADDR && t2->Tag() == TYPE_SUBNET )
			gen = std::string("(") + GenExpr(op2, GEN_DONT_CARE) +
				")->Contains(" +
				GenExpr(op1, GEN_VAL_PTR) + ")";

		else if ( t2->Tag() == TYPE_VECTOR )
			// v1->AsListVal()->Idx(0)->CoerceToUnsigned()
			gen = GenExpr(op2, GEN_DONT_CARE) + "->At(" +
				GenExpr(op1, GEN_NATIVE) + ")";

		else
			gen = std::string("(") + GenExpr(op2, GEN_DONT_CARE) +
				"->Find(index_val__CPP({" +
				GenExpr(op1, GEN_VAL_PTR) + "})) ? true : false)";

		return NativeToGT(gen, t, gt);
		}

	case EXPR_FIELD:
		{
		auto f = e->AsFieldExpr()->Field();
		auto f_s = Fmt(f);

		gen = GenExpr(e->GetOp1(), GEN_DONT_CARE) +
			"->GetFieldOrDefault(" + f_s + ")";

		return GenericValPtrToGT(gen, t, gt);
		}

	case EXPR_HAS_FIELD:
		{
		auto f = e->AsHasFieldExpr()->Field();
		auto f_s = Fmt(f);

		// Need to use accessors for native types.
		gen = std::string("(") + GenExpr(e->GetOp1(), GEN_DONT_CARE) +
			"->GetField(" + f_s + ") != nullptr)";

		return NativeToGT(gen, t, gt);
		}

	case EXPR_INDEX:
		{
		auto aggr = e->GetOp1();
		const auto& aggr_t = aggr->GetType();

		if ( aggr_t->Tag() == TYPE_TABLE )
			gen = std::string("index_table__CPP(") +
				GenExpr(aggr, GEN_NATIVE) + ", {" +
				GenExpr(e->GetOp2(), GEN_VAL_PTR) + "})";

		else if ( aggr_t->Tag() == TYPE_VECTOR )
			gen =  GenExpr(aggr, GEN_DONT_CARE) + "->At(" +
				GenExpr(e->GetOp2(), GEN_NATIVE) + ")";

		else if ( aggr_t->Tag() == TYPE_STRING )
			gen = std::string("index_string__CPP(") +
				GenExpr(aggr, GEN_NATIVE) + ", {" +
				GenExpr(e->GetOp2(), GEN_VAL_PTR) + "})";

		return GenericValPtrToGT(gen, t, gt);
		}
		break;

	case EXPR_ASSIGN:
		{
		auto op1 = e->GetOp1()->AsRefExprPtr()->GetOp1();
		auto op2 = e->GetOp2();

		const auto& t1 = op1->GetType();
		const auto& t2 = op2->GetType();

		auto rhs_native = GenExpr(op2, GEN_NATIVE);
		auto rhs_val_ptr = GenExpr(op2, GEN_VAL_PTR);

		auto lhs_is_any = t1->Tag() == TYPE_ANY;
		auto rhs_is_any = t2->Tag() == TYPE_ANY;

		if ( lhs_is_any && ! rhs_is_any )
			rhs_native = rhs_val_ptr;

		if ( rhs_is_any && ! lhs_is_any && t1->Tag() != TYPE_LIST )
			rhs_native = rhs_val_ptr =
				GenericValPtrToGT(rhs_val_ptr, t1, GEN_NATIVE);

		return GenAssign(op1, op2, rhs_native, rhs_val_ptr);
		}

	case EXPR_ADD_TO:
		if ( t->Tag() == TYPE_VECTOR )
			{
			gen = std::string("vector_append__CPP(") +
				GenExpr(e->GetOp1(), GEN_VAL_PTR) +
				", " + GenExpr(e->GetOp2(), GEN_VAL_PTR) + ")";
			return GenericValPtrToGT(gen, t, gt);
			}

		if ( t->Tag() == TYPE_STRING )
			{
			auto op1 = e->GetOp1()->AsRefExprPtr()->GetOp1();
			auto rhs_native = GenBinaryString(e, GEN_NATIVE, "+=");
			auto rhs_val_ptr = GenBinaryString(e, GEN_VAL_PTR, "+=");

			return GenAssign(op1, nullptr, rhs_native, rhs_val_ptr);
			}

		return GenBinary(e, gt, "+=");

	case EXPR_REF:
		return GenExpr(e->GetOp1(), gt);

	case EXPR_SIZE:
		return GenericValPtrToGT(GenExpr(e->GetOp1(), GEN_DONT_CARE) +
						"->SizeVal()", t, gt);

	case EXPR_ARITH_COERCE:
		{
		auto it = t->InternalType();
		auto cast_name =
			it == TYPE_INTERNAL_DOUBLE ? "double" :
				(it == TYPE_INTERNAL_INT ?
					"bro_int_t" : "bro_uint_t");

		return NativeToGT(std::string(cast_name) + "(" +
					GenExpr(e->GetOp1(), GEN_NATIVE) + ")",
					t, gt);
		}

	case EXPR_RECORD_COERCE:
		{
		auto rc = static_cast<const RecordCoerceExpr*>(e);
		auto op1 = rc->GetOp1();
		const auto& from_type = op1->GetType();
		const auto& to_type = rc->GetType();

		if ( same_type(from_type, to_type) )
			// Elide coercion.
			return GenExpr(op1, gt);

		const auto& map = rc->Map();
		auto type_var = GenTypeName(to_type);

		return std::string("coerce_to_record(cast_intrusive<RecordType>(") +
				type_var + "), " +
				GenExpr(op1, GEN_VAL_PTR) + ".get(), " +
				GenIntVector(map) + ")";
		}

	case EXPR_TABLE_COERCE:
		{
		auto tc = static_cast<const TableCoerceExpr*>(e);
		auto op1 = tc->GetOp1();
		const auto& t = tc->GetType();

		return std::string("table_coerce__CPP(") +
			GenExpr(op1, GEN_VAL_PTR) + ", " + GenTypeName(t) + ")";
		}

	case EXPR_RECORD_CONSTRUCTOR:
		{
		auto rc = static_cast<const RecordConstructorExpr*>(e);
		auto t = rc->GetType<RecordType>();

		const auto& exprs = rc->Op()->AsListExpr()->Exprs();
		auto n = exprs.length();

		std::string vals;

		for ( auto i = 0; i < n; ++i )
			{
			const auto& e = exprs[i];

			ASSERT(e->Tag() == EXPR_FIELD_ASSIGN);

			vals += GenExpr(e->GetOp1(), GEN_VAL_PTR);

			if ( i < n - 1 )
				vals += ", ";
			}

		return std::string("record_constructor__CPP({") + vals + "}, " +
			"cast_intrusive<RecordType>(" + GenTypeName(t) + "))";
		}

	case EXPR_VECTOR_COERCE:
		{
		auto vc = static_cast<const VectorCoerceExpr*>(e);
		const auto& op = vc->GetOp1();
		const auto& t = vc->GetType<VectorType>();

		return std::string("vector_coerce__CPP(" +
			GenExpr(op, GEN_VAL_PTR) + ", " + GenTypeName(t) + ")");
		}

	case EXPR_SET_CONSTRUCTOR:
		{
		auto sc = static_cast<const SetConstructorExpr*>(e);
		auto t = sc->GetType<TableType>();
		auto attrs = sc->GetAttrs();

		std::string attrs_name = "nullptr";
		if ( attrs )
			{
			NoteInitDependency(e, attrs);
			RecordAttributes(attrs);
			attrs_name = AttrsName(attrs);
			}

		return std::string("set_constructor__CPP({") +
			GenExpr(sc->GetOp1(), GEN_VAL_PTR) + "}, " +
			"cast_intrusive<TableType>(" + GenTypeName(t) + "), " +
			attrs_name + ")";
		}

	case EXPR_TABLE_CONSTRUCTOR:
		{
		auto tc = static_cast<const TableConstructorExpr*>(e);
		auto t = tc->GetType<TableType>();
		auto attrs = tc->GetAttrs();

		std::string attrs_name = "nullptr";
		if ( attrs )
			{
			NoteInitDependency(e, attrs);
			RecordAttributes(attrs);
			attrs_name = AttrsName(attrs);
			}

		std::string indices;
		std::string vals;

		const auto& exprs = tc->GetOp1()->AsListExpr()->Exprs();
		auto n = exprs.length();

		for ( auto i = 0; i < n; ++i )
			{
			const auto& e = exprs[i];

			ASSERT(e->Tag() == EXPR_ASSIGN);

			auto index = e->GetOp1();
			auto v = e->GetOp2();

			if ( index->Tag() == EXPR_LIST )
				// Multiple indices.
				indices += "index_val__CPP({" +
					GenExpr(index, GEN_VAL_PTR) + "})";
			else
				indices += GenExpr(index, GEN_VAL_PTR);

			vals += GenExpr(v, GEN_VAL_PTR);

			if ( i < n - 1 )
				{
				indices += ", ";
				vals += ", ";
				}
			}

		return std::string("table_constructor__CPP({") +
			indices + "}, {" + vals + "}, " +
			"cast_intrusive<TableType>(" + GenTypeName(t) + "), " +
			attrs_name + ")";
		}

	case EXPR_VECTOR_CONSTRUCTOR:
		{
		auto vc = static_cast<const VectorConstructorExpr*>(e);
		auto t = vc->GetType<TableType>();

		return std::string("vector_constructor__CPP({") +
			GenExpr(vc->GetOp1(), GEN_VAL_PTR) + "}, " +
			"cast_intrusive<VectorType>(" + GenTypeName(t) + "))";
		}

	case EXPR_SCHEDULE:
		{
		auto s = static_cast<const ScheduleExpr*>(e);
		auto when = s->When();
		auto event = s->Event();
		std::string event_name(event->Handler()->Name());

		std::string when_s = GenExpr(when, GEN_NATIVE);
		if ( when->GetType()->Tag() == TYPE_INTERVAL )
			when_s += " + run_state::network_time";

		return std::string("schedule__CPP(") + when_s +
			", " + globals[event_name] + ", { " +
			GenExpr(event->Args(), GEN_VAL_PTR) + " })";
		}

	case EXPR_LAMBDA:
		{
		auto lb = static_cast<const LambdaExpr*>(e);
		const auto& in = lb->Ingredients();
		return std::string("nullptr /* ### */");
		}

	case EXPR_EVENT:
		// These should not wind up being directly generated,
		// but instead deconstructed in the context of either
		// a "schedule" expression or an "event" statement.
		ASSERT(0);

	case EXPR_CAST:
		gen = std::string("cast_value_to_type(") +
			GenExpr(e->GetOp1(), GEN_VAL_PTR) + ".get(), " +
			GenTypeName(t) + ".get())";
		return GenericValPtrToGT(gen, t, gt);

	case EXPR_FIELD_ASSIGN:
	case EXPR_IS:
	case EXPR_INDEX_SLICE_ASSIGN:
	case EXPR_INLINE:
		ASSERT(0);

	default:
		return std::string("EXPR");
	}
	}

std::string CPPCompile::GenArgs(const Expr* e)
	{
	if ( e->Tag() == EXPR_LIST )
		{
		const auto& exprs = e->AsListExpr()->Exprs();
		std::string gen;

		int n = exprs.size();

		for ( auto i = 0; i < n; ++i )
			{
			gen = gen + GenArgs(exprs[i]);
			if ( i < n - 1 )
				gen += ", ";
			}

		return gen;
		}

	return GenExpr(e, GEN_NATIVE);
	}

std::string CPPCompile::GenUnary(const Expr* e, GenType gt, const char* op)
	{
	return NativeToGT(std::string(op) + "(" +
				GenExpr(e->GetOp1(), GEN_NATIVE) + ")",
				e->GetType(), gt);
	}

std::string CPPCompile::GenBinary(const Expr* e, GenType gt, const char* op)
	{
	const auto& op1 = e->GetOp1();
	const auto& op2 = e->GetOp2();

	auto t = op1->GetType();

	if ( t->IsSet() )
		return GenBinarySet(e, gt, op);

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_STRING:
		return GenBinaryString(e, gt, op);

	case TYPE_INTERNAL_ADDR:
		return GenBinaryAddr(e, gt, op);

	case TYPE_INTERNAL_SUBNET:
		return GenBinarySubNet(e, gt, op);

	default:
		if ( t->Tag() == TYPE_PATTERN )
			return GenBinaryPattern(e, gt, op);
		break;
	}

	return NativeToGT(std::string("(") +
				GenExpr(e->GetOp1(), GEN_NATIVE) + ")" +
				op +
				"(" + GenExpr(e->GetOp2(), GEN_NATIVE) + ")",
				e->GetType(), gt);
	}

std::string CPPCompile::GenBinarySet(const Expr* e, GenType gt, const char* op)
	{
	auto v1 = GenExpr(e->GetOp1(), GEN_DONT_CARE) + "->AsTableVal()";
	auto v2 = GenExpr(e->GetOp2(), GEN_DONT_CARE) + "->AsTableVal()";

	std::string res;

	switch ( e->Tag() ) {
	case EXPR_AND:
		res = v1 + "->Intersection(*" + v2 + ")";
		break;

	case EXPR_OR:
                // auto rval = v1->Clone();
                // if ( ! tv2->AddTo(rval.get(), false, false) )
                //        reporter->InternalError("set union failed to type check)"
		res = v1 + "->Union(*" + v2 + ")";
		break;

	case EXPR_SUB:
		//                 if ( ! tv2->RemoveFrom(rval.get()) )
		res = v1 + "->TakeOut(*" + v2 + ")";
		break;

	case EXPR_EQ:
		res = v1 + "->EqualTo(*" + v2 + ")";
		break;

	case EXPR_NE:
		res = std::string("! ") + v1 + "->EqualTo(*" + v2 + ")";
		break;

	case EXPR_LE:
		res = v1 + "->IsSubsetOf(*" + v2 + ")";
		break;

	case EXPR_LT:
		res = std::string("(") + v1 + "->IsSubsetOf(*" + v2 + ") &&" +
			v1 + "->Size() < " + v2 + "->Size())";
		break;

	default:
		reporter->InternalError("bad type in CPPCompile::GenBinarySet");
	}

	return NativeToGT(res, e->GetType(), gt);
	}

std::string CPPCompile::GenBinaryString(const Expr* e, GenType gt,
					const char* op)
	{
	auto v1 = GenExpr(e->GetOp1(), GEN_DONT_CARE) + "->AsString()";
	auto v2 = GenExpr(e->GetOp2(), GEN_DONT_CARE) + "->AsString()";

	std::string res;

	if ( e->Tag() == EXPR_ADD || e->Tag() == EXPR_ADD_TO )
		res = std::string("str_concat__CPP(") + v1 + ", " + v2 + ")";
	else
		res = std::string("(Bstr_cmp(") + v1 + ", " + v2 + ") " + op + " 0)";

	return NativeToGT(res, e->GetType(), gt);
	}

std::string CPPCompile::GenBinaryPattern(const Expr* e, GenType gt,
						const char* op)
	{
	auto v1 = GenExpr(e->GetOp1(), GEN_DONT_CARE) + "->AsPattern()";
	auto v2 = GenExpr(e->GetOp2(), GEN_DONT_CARE) + "->AsPattern()";

	auto func = e->Tag() == EXPR_AND ?
			"RE_Matcher_conjunction" : "RE_Matcher_disjunction";

	return NativeToGT(std::string("make_intrusive<PatternVal>(") +
				func + "(" + v1 + ", " + v2 + "))",
				e->GetType(), gt);
	}

std::string CPPCompile::GenBinaryAddr(const Expr* e, GenType gt, const char* op)
	{
	auto v1 = GenExpr(e->GetOp1(), GEN_DONT_CARE) + "->AsAddr()";
	auto v2 = GenExpr(e->GetOp2(), GEN_DONT_CARE) + "->AsAddr()";

	return NativeToGT(v1 + op + v2, e->GetType(), gt);
	}

std::string CPPCompile::GenBinarySubNet(const Expr* e, GenType gt,
					const char* op)
	{
	auto v1 = GenExpr(e->GetOp1(), GEN_DONT_CARE) + "->AsSubNet()";
	auto v2 = GenExpr(e->GetOp2(), GEN_DONT_CARE) + "->AsSubNet()";

	return NativeToGT(v1 + op + v2, e->GetType(), gt);
	}

std::string CPPCompile::GenEQ(const Expr* e, GenType gt, const char* op)
	{
	auto op1 = e->GetOp1();
	auto op2 = e->GetOp2();
	auto tag = op1->GetType()->Tag();
	std::string negated(e->Tag() == EXPR_EQ ? "" : "! ");

	if ( tag == TYPE_PATTERN )
		return NativeToGT(negated + GenExpr(op1, GEN_DONT_CARE) +
					"->MatchExactly(" +
					GenExpr(op2, GEN_DONT_CARE) +
					"->AsString())",
					e->GetType(), gt);

	if ( tag == TYPE_FUNC )
		return NativeToGT(negated + "util::streq(" +
			GenExpr(op1, GEN_DONT_CARE) + "->AsFunc()->Name(), " +
			GenExpr(op2, GEN_DONT_CARE) + "->AsFunc()->Name())",
			e->GetType(), gt);

	return GenBinary(e, gt, op);
	}

std::string CPPCompile::GenAssign(const ExprPtr& lhs, const ExprPtr& rhs,
					const std::string& rhs_native,
					const std::string& rhs_val_ptr)
	{
	std::string gen;

	switch ( lhs->Tag() ) {
	case EXPR_NAME:
		{
		auto n = lhs->AsNameExpr()->Id();
		auto name = IDNameStr(n);

		if ( n->IsGlobal() )
			gen = globals[n->Name()] + "->SetVal(" +
				rhs_val_ptr + ")";
		else
			gen = name + " = " + rhs_native;
		}
		break;

	case EXPR_INDEX:
		gen = std::string("assign_to_index__CPP(") +
			GenExpr(lhs->GetOp1(), GEN_VAL_PTR) + ", " +
			"index_val__CPP({" +
			GenExpr(lhs->GetOp2(), GEN_VAL_PTR) + "}), " +
			rhs_val_ptr + ")";
		break;

	case EXPR_FIELD:
		gen = GenExpr(lhs->GetOp1(), GEN_DONT_CARE) +
			"->Assign(" +
			Fmt(lhs->AsFieldExpr()->Field()) + ", " +
			rhs_val_ptr + ")";
		break;

	case EXPR_LIST:
		{
		if ( rhs->Tag() != EXPR_NAME )
			reporter->InternalError("compound RHS expression in multi-assignment");

		gen = "(";

		const auto& vars = lhs->AsListExpr()->Exprs();

		auto n = vars.length();
		for ( auto i = 0; i < n; ++i )
			{
			const auto& var_i = vars[i];
			if ( var_i->Tag() != EXPR_NAME )
				reporter->InternalError("compound LHS expression in multi-assignment");
			const auto& t_i = var_i->GetType();
			auto var = var_i->AsNameExpr();

			auto rhs_i_base = GenExpr(rhs, GEN_DONT_CARE);
			rhs_i_base += "->AsListVal()->Idx(" + Fmt(i) + ")";
			auto rhs_i =
				GenericValPtrToGT(rhs_i_base, t_i, GEN_NATIVE);

			gen = gen + IDNameStr(var->Id()) + " = " + rhs_i;

			if ( i < n - 1 )
				gen += ", ";
			}

		gen += ")";
		}
		break;

	default:
		reporter->InternalError("bad assigment node in CPPCompile::GenExpr");
	}

	return gen;
	}

std::string CPPCompile::GenIntVector(const std::vector<int>& vec)
	{
	std::string res("{ ");

	for ( auto i = 0; i < vec.size(); ++i )
		{
		res += Fmt(vec[i]);

		if ( i < vec.size() - 1 )
			res += ", ";
		}

	return res + " }";
	}

std::string CPPCompile::NativeToGT(const std::string& expr, const TypePtr& t,
					GenType gt)
	{
	if ( gt == GEN_DONT_CARE )
		return expr;

	if ( gt == GEN_NATIVE )
		return expr;

	if ( ! IsNativeType(t) )
		return expr;

	// Need to convert to a ValPtr.
	switch ( t->Tag() ) {
	case TYPE_VOID:
		return expr;

	case TYPE_BOOL:
		return std::string("val_mgr->Bool(") + expr + ")";

	case TYPE_INT:
		return std::string("val_mgr->Int(") + expr + ")";

	case TYPE_COUNT:
		return std::string("val_mgr->Count(") + expr + ")";

	case TYPE_PORT:
		return std::string("val_mgr->Port(") + expr + ")";

	case TYPE_ENUM:
		return std::string("make_enum__CPP(") + GenTypeName(t) + ", " +
					expr + ")";

	default:
		return std::string("make_intrusive<") + IntrusiveVal(t) +
			">(" + expr + ")";
	}
	}

std::string CPPCompile::GenericValPtrToGT(const std::string& expr,
						const TypePtr& t, GenType gt)
	{
	if ( gt != GEN_VAL_PTR && IsNativeType(t) )
		return expr + NativeAccessor(t);
	else
		return std::string("cast_intrusive<") +
				IntrusiveVal(t) + ">(" + expr + ")";
	}

void CPPCompile::GenInitExpr(const ExprPtr& e)
	{
	NL();

	const auto& t = e->GetType();

	// First, create a CPPFunc that we can compile to compute e.
	auto name = std::string("wrapper_") + InitExprName(e);
	Emit("class %s : public CPPFunc", name);
	StartBlock();

	Emit("public:");
	Emit("%s() : CPPFunc(\"%s\", false)", name, name);

	StartBlock();
	Emit("type = make_intrusive<FuncType>(make_intrusive<RecordType>(new type_decl_list()), %s, FUNC_FLAVOR_FUNCTION);", GenTypeName(t));

	NoteInitDependency(e, t);
	EndBlock();

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override");
	StartBlock();

	if ( IsNativeType(t) )
		GenInvokeBody(t, "parent");
	else
		Emit("return Call(parent);");

	EndBlock();

	Emit("static %s Call(Frame* f__CPP)", FullTypeName(t));
	StartBlock();

	Emit("return %s;", GenExpr(e, GEN_NATIVE));
	EndBlock();

	EndBlock(true);

	auto init_expr_name = InitExprName(e);

	Emit("CallExprPtr %s;", init_expr_name);

	NoteInitDependency(e, t);
	AddInit(e, init_expr_name, std::string("make_intrusive<CallExpr>(make_intrusive<ConstExpr>(make_intrusive<FuncVal>(make_intrusive<") +
		name + ">())), make_intrusive<ListExpr>(), false)");
	}

std::string CPPCompile::InitExprName(const ExprPtr& e)
	{
	return init_exprs.KeyName(e);
	}

void CPPCompile::GenAttrs(const AttributesPtr& attrs)
	{
	NL();

	Emit("AttributesPtr %s", AttrsName(attrs));

	StartBlock();

	const auto& avec = attrs->GetAttrs();
	Emit("auto attrs = std::vector<AttrPtr>();");

	for ( auto i = 0; i < avec.size(); ++i )
		{
		const auto& attr = avec[i];
		const auto& e = attr->GetExpr();

		if ( e )
			{
			Emit("attrs.emplace_back(make_intrusive<Attr>(%s, %s));",
				AttrName(attr),
				InitExprName(e));
			NoteInitDependency(attrs, e);
			AddInit(attrs);
			}
		else
			Emit("attrs.emplace_back(make_intrusive<Attr>(%s));",
				AttrName(attr));
		}

	Emit("return make_intrusive<Attributes>(attrs, nullptr, true, false);");

	EndBlock();
	}

std::string CPPCompile::AttrsName(const AttributesPtr& a)
	{
	return attributes.KeyName(a) + "()";
	}

const char* CPPCompile::AttrName(const AttrPtr& attr)
	{
	switch ( attr->Tag() ) {
	case ATTR_OPTIONAL:	return "ATTR_OPTIONAL";
	case ATTR_DEFAULT:	return "ATTR_DEFAULT";
	case ATTR_REDEF:	return "ATTR_REDEF";
	case ATTR_ADD_FUNC:	return "ATTR_ADD_FUNC";
	case ATTR_DEL_FUNC:	return "ATTR_DEL_FUNC";
	case ATTR_EXPIRE_FUNC:	return "ATTR_EXPIRE_FUNC";
	case ATTR_EXPIRE_READ:	return "ATTR_EXPIRE_READ";
	case ATTR_EXPIRE_WRITE:	return "ATTR_EXPIRE_WRITE";
	case ATTR_EXPIRE_CREATE:	return "ATTR_EXPIRE_CREATE";
	case ATTR_RAW_OUTPUT:	return "ATTR_RAW_OUTPUT";
	case ATTR_PRIORITY:	return "ATTR_PRIORITY";
	case ATTR_GROUP:	return "ATTR_GROUP";
	case ATTR_LOG:	return "ATTR_LOG";
	case ATTR_ERROR_HANDLER:	return "ATTR_ERROR_HANDLER";
	case ATTR_TYPE_COLUMN:	return "ATTR_TYPE_COLUMN";
	case ATTR_TRACKED:	return "ATTR_TRACKED";
	case ATTR_ON_CHANGE:	return "ATTR_ON_CHANGE";
	case ATTR_BROKER_STORE:	return "ATTR_BROKER_STORE";
	case ATTR_BROKER_STORE_ALLOW_COMPLEX:	return "ATTR_BROKER_STORE_ALLOW_COMPLEX";
	case ATTR_BACKEND:	return "ATTR_BACKEND";
	case ATTR_DEPRECATED:	return "ATTR_DEPRECATED";
	case ATTR_IS_ASSIGNED:	return "ATTR_IS_ASSIGNED";

	case NUM_ATTRS:	return "<busted";
	}
	}

void CPPCompile::GenPreInit(const TypePtr& t)
	{
	std::string pre_init;

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ERROR:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_VOID:
		pre_init = std::string("base_type(") + TypeTagName(t->Tag()) + ")";
		break;

	case TYPE_ENUM:
		pre_init = std::string("get_enum_type__CPP(\"") +
				t->GetName() + "\")";
		break;

	case TYPE_SUBNET:
		pre_init = std::string("make_intrusive<SubNetType>()");
		break;

	case TYPE_FILE:
		pre_init = std::string("make_intrusive<FileType>(") +
				GenTypeName(t->AsFileType()->Yield()) + ")";
		break;

	case TYPE_OPAQUE:
		pre_init = std::string("make_intrusive<OpaqueType>(\"") +
				t->AsOpaqueType()->Name() + "\")";
		break;

	case TYPE_RECORD:
		{
		std::string name;

		if ( t->GetName() != "" )
			name = std::string("\"") + t->GetName() +
					std::string("\"");
		else
			name = "nullptr";

		pre_init = std::string("get_record_type__CPP(") + name + ")";
		}
		break;

	case TYPE_LIST:
		pre_init = std::string("make_intrusive<TypeList>()");
		break;

	case TYPE_TYPE:
	case TYPE_VECTOR:
	case TYPE_TABLE:
	case TYPE_FUNC:
		// Nothing to do for these, pre-initialization-wise.
		return;

	default:
		reporter->InternalError("bad type in CPPCompile::GenType");
	}

	pre_inits.emplace_back(GenTypeName(t) + " = " + pre_init + ";");
	}

void CPPCompile::ExpandTypeVar(const TypePtr& t)
	{
	auto tn = GenTypeName(t);

	switch ( t->Tag() ) {
	case TYPE_LIST:
		{
		auto tl = t->AsTypeList()->GetTypes();
		auto t_name = tn + "->AsTypeList()";

		for ( auto i = 0; i < tl.size(); ++i )
			AddInit(t, t_name + "->Append(" +
				GenTypeName(tl[i]) + ");");
		}
		break;

	case TYPE_RECORD:
		{
		auto r = t->AsRecordType()->Types();
		auto t_name = tn + "->AsRecordType()";

		AddInit(t, std::string("if ( ") + t_name + "->NumFields() == 0 )");

		AddInit(t, "{");
		AddInit(t, "type_decl_list tl;");

		for ( auto i = 0; i < r->length(); ++i )
			{
			const auto& td = (*r)[i];
			auto type_accessor = GenTypeName(td->type);

			if ( td->attrs )
				AddInit(t, std::string("tl.append(new TypeDecl(\"") +
					td->id + "\", " + type_accessor +
					", " + AttrsName(td->attrs) +"));");
			else
				AddInit(t, std::string("tl.append(new TypeDecl(\"") +
					td->id + "\", " + type_accessor +"));");
			}

		AddInit(t, t_name + "->AddFieldsDirectly(tl);");
		AddInit(t, "}");
		}
		break;

	case TYPE_ENUM:
		{
		auto e_name = tn + "->AsEnumType()";
		auto et = t->AsEnumType();
		auto names = et->Names();

		AddInit(t, "{ auto et = " + e_name + ";");
		AddInit(t, "if ( et->Names().size() == 0 ) {");

		for ( const auto& name_pair : et->Names() )
			AddInit(t, std::string("\tet->AddNameInternal(\"") +
				name_pair.first + "\", " +
				Fmt(int(name_pair.second)) + ");");

		AddInit(t, "}}");
		}
		break;

	case TYPE_TYPE:
		AddInit(t, tn, std::string("make_intrusive<TypeType>(") +
				GenTypeName(t->AsTypeType()->GetType()) + ")");
		break;

	case TYPE_VECTOR:
		AddInit(t, tn, std::string("make_intrusive<VectorType>(") +
				GenTypeName(t->AsVectorType()->Yield()) + ")");
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();

		const auto& indices = tbl->GetIndices();
		const auto& yield = tbl->Yield();

		if ( tbl->IsSet() )
			AddInit(t, tn,
				std::string("make_intrusive<SetType>(cast_intrusive<TypeList>(") +
				GenTypeName(indices) +
				" ), nullptr)");
		else
			AddInit(t, tn,
				std::string("make_intrusive<TableType>(cast_intrusive<TypeList>(") +
				GenTypeName(indices) + "), " +
				GenTypeName(yield) + ")");
		}
		break;

	case TYPE_FUNC:
		{
		auto f = t->AsFuncType();

		auto args_type_accessor = GenTypeName(f->Params());
		auto params = f->Params();
		auto yt = f->Yield();

		std::string yield_type_accessor;

		if ( yt )
			yield_type_accessor += GenTypeName(yt);
		else
			yield_type_accessor += "nullptr";

		auto fl = f->Flavor();

		std::string fl_name;
		if ( fl == FUNC_FLAVOR_FUNCTION )
			fl_name = "FUNC_FLAVOR_FUNCTION";
		else if ( fl == FUNC_FLAVOR_EVENT )
			fl_name = "FUNC_FLAVOR_EVENT";
		else if ( fl == FUNC_FLAVOR_HOOK )
			fl_name = "FUNC_FLAVOR_HOOK";

		auto type_init = std::string("make_intrusive<FuncType>(cast_intrusive<RecordType>(") +
			args_type_accessor + "), " +
			yield_type_accessor + ", " + fl_name + ")";

		AddInit(t, tn, type_init);
		}
		break;

	default:
		break;
	}

	AddInit(t);
	}

std::string CPPCompile::GenTypeName(const TypePtr& t)
	{
	return std::string("types__CPP[") + Fmt(TypeIndex(t)) + "]";
	}

const char* CPPCompile::TypeTagName(TypeTag tag) const
	{
	switch ( tag ) {
	case TYPE_ADDR:		return "TYPE_ADDR";
	case TYPE_ANY:		return "TYPE_ANY";
	case TYPE_BOOL:		return "TYPE_BOOL";
	case TYPE_COUNT:	return "TYPE_COUNT";
	case TYPE_DOUBLE:	return "TYPE_DOUBLE";
	case TYPE_ENUM:		return "TYPE_ENUM";
	case TYPE_ERROR:	return "TYPE_ERROR";
	case TYPE_FILE:		return "TYPE_FILE";
	case TYPE_FUNC:		return "TYPE_FUNC";
	case TYPE_INT:		return "TYPE_INT";
	case TYPE_INTERVAL:	return "TYPE_INTERVAL";
	case TYPE_OPAQUE:	return "TYPE_OPAQUE";
	case TYPE_PATTERN:	return "TYPE_PATTERN";
	case TYPE_PORT:		return "TYPE_PORT";
	case TYPE_RECORD:	return "TYPE_RECORD";
	case TYPE_STRING:	return "TYPE_STRING";
	case TYPE_SUBNET:	return "TYPE_SUBNET";
	case TYPE_TABLE:	return "TYPE_TABLE";
	case TYPE_TIME:		return "TYPE_TIME";
	case TYPE_TIMER:	return "TYPE_TIMER";
	case TYPE_TYPE:		return "TYPE_TYPE";
	case TYPE_VECTOR:	return "TYPE_VECTOR";
	case TYPE_VOID:		return "TYPE_VOID";

	default:
		reporter->InternalError("bad type in CPPCompile::TypeTagName");
	}
	}

const std::string& CPPCompile::IDNameStr(const ID* id) const
	{
	if ( id->IsGlobal() )
		{
		auto g = std::string(id->Name());
		ASSERT(globals.count(g) > 0);
		return ((CPPCompile*)(this))->globals[g];
		}

	ASSERT(locals.count(id) > 0);

	return ((CPPCompile*)(this))->locals[id];
	}

std::string CPPCompile::ParamDecl(const FuncTypePtr& ft, const ProfileFunc* pf)
	{
	const auto& params = ft->Params();
	int n = params->NumFields();

	std::string decl;

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = params->GetFieldType(i);
		auto tn = FullTypeName(t);
		auto param_id = FindParam(i, pf);
		auto fn = param_id ?
				LocalName(param_id) :
				(std::string("unused_param__CPP_") + Fmt(i));

		if ( IsNativeType(t) )
			decl = decl + tn + " " + fn;
		else
			{
			if ( param_id && pf->Assignees().count(param_id) > 0 )
				decl = decl + tn + " " + fn;
			else
				decl = decl + "const " + tn + "& " + fn;
			}

		decl += ", ";
		}

	return decl + "Frame* f__CPP";
	}

const ID* CPPCompile::FindParam(int i, const ProfileFunc* pf)
	{
	const auto& params = pf->Params();

	for ( const auto& p : params )
		if ( p->Offset() == i )
			return p;

	return nullptr;
	}

bool CPPCompile::IsNativeType(const TypePtr& t) const
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ENUM:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_PORT:
	case TYPE_TIME:
	case TYPE_VOID:
		return true;

	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_FILE:
	case TYPE_FUNC:
	case TYPE_OPAQUE:
	case TYPE_PATTERN:
	case TYPE_RECORD:
	case TYPE_STRING:
	case TYPE_SUBNET:
	case TYPE_TABLE:
	case TYPE_TYPE:
	case TYPE_VECTOR:
		return false;

	default:
		reporter->InternalError("bad type in CPPCompile::IsNativeType");
	}
	}

const char* CPPCompile::TypeName(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:		return "bool";
	case TYPE_COUNT:	return "bro_uint_t";
	case TYPE_DOUBLE:	return "double";
	case TYPE_ENUM:		return "int";
	case TYPE_INT:		return "bro_int_t";
	case TYPE_INTERVAL:	return "double";
	case TYPE_PORT:		return "bro_uint_t";
	case TYPE_TIME:		return "double";
	case TYPE_VOID:		return "void";

	case TYPE_ADDR:		return "AddrVal";
	case TYPE_ANY:		return "Val";
	case TYPE_FILE:		return "FileVal";
	case TYPE_FUNC:		return "FuncVal";
	case TYPE_OPAQUE:	return "OpaqueVal";
	case TYPE_PATTERN:	return "PatternVal";
	case TYPE_RECORD:	return "RecordVal";
	case TYPE_STRING:	return "StringVal";
	case TYPE_SUBNET:	return "SubNetVal";
	case TYPE_TABLE:	return "TableVal";
	case TYPE_TYPE:		return "TypeVal";
	case TYPE_VECTOR:	return "VectorVal";

	default:
		reporter->InternalError("bad type in CPPCompile::TypeName");
	}
	}

const char* CPPCompile::FullTypeName(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ENUM:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_PORT:
	case TYPE_TIME:
	case TYPE_VOID:
		return TypeName(t);

	case TYPE_ADDR:		return "AddrValPtr";
	case TYPE_ANY:		return "ValPtr";
	case TYPE_FILE:		return "FileValPtr";
	case TYPE_FUNC:		return "FuncValPtr";
	case TYPE_OPAQUE:	return "OpaqueValPtr";
	case TYPE_PATTERN:	return "PatternValPtr";
	case TYPE_RECORD:	return "RecordValPtr";
	case TYPE_STRING:	return "StringValPtr";
	case TYPE_SUBNET:	return "SubNetValPtr";
	case TYPE_TABLE:	return "TableValPtr";
	case TYPE_TYPE:		return "TypeValPtr";
	case TYPE_VECTOR:	return "VectorValPtr";

	default:
		reporter->InternalError("bad type in CPPCompile::FullTypeName");
	}
	}

const char* CPPCompile::TypeType(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_RECORD:	return "RecordType";
	case TYPE_TABLE:	return "TableType";
	case TYPE_VECTOR:	return "VectorType";

	default:
		reporter->InternalError("bad type in CPPCompile::TypeType");
	}
	}

int CPPCompile::TypeIndex(const TypePtr& t)
	{
	auto tp = t.get();

	if ( types.HasKey(t) )
		// Do this check first, so we can recurse below when
		// adding a new type.
		return types.KeyIndex(tp);

	if ( processed_types.count(tp) == 0 )
		{
		ASSERT(! types.HasKey(t));

		// Add the type before going further, to avoid loops due to
		// types that reference each other.
		processed_types.insert(tp);

		// Recursively do its subtypes, so that they will be
		// available when we ultimately do this type.
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
		case TYPE_PATTERN:
		case TYPE_PORT:
		case TYPE_STRING:
		case TYPE_TIME:
		case TYPE_TIMER:
		case TYPE_VOID:
		case TYPE_OPAQUE:
		case TYPE_SUBNET:
		case TYPE_FILE:
			// Nothing to do.
			break;

		case TYPE_TYPE:
			{
			const auto& tt = t->AsTypeType()->GetType();
			NoteNonRecordInitDependency(t, tt);
			(void) TypeIndex(tt);
			}
			break;

		case TYPE_VECTOR:
			{
			const auto& yield = t->AsVectorType()->Yield();
			NoteNonRecordInitDependency(t, yield);
			(void) TypeIndex(yield);
			}
			break;

		case TYPE_LIST:
			{
			auto tl = t->AsTypeList()->GetTypes();
			for ( auto i = 0; i < tl.size(); ++i )
				{
				NoteNonRecordInitDependency(t, tl[i]);
				(void) TypeIndex(tl[i]);
				}
			}
			break;

		case TYPE_TABLE:
			{
			auto tbl = t->AsTableType();
			const auto& indices = tbl->GetIndices();
			const auto& yield = tbl->Yield();

			NoteNonRecordInitDependency(t, indices);
			if ( yield )
				NoteNonRecordInitDependency(t, yield);

			(void) TypeIndex(indices);

			if ( ! tbl->IsSet() )
				(void) TypeIndex(yield);
			}
			break;

		case TYPE_RECORD:
			{
			auto r = t->AsRecordType()->Types();

			for ( auto i = 0; i < r->length(); ++i )
				{
				const auto& r_i = (*r)[i];

				NoteNonRecordInitDependency(t, r_i->type);
				(void) TypeIndex(r_i->type);

				if ( r_i->attrs )
					{
					NoteInitDependency(t, r_i->attrs);
					RecordAttributes(r_i->attrs);
					}
				}
			}
			break;

		case TYPE_FUNC:
			{
			auto f = t->AsFuncType();

			NoteInitDependency(t, f->Params());
			(void) TypeIndex(f->Params());

			if ( f->Yield() )
				{
				NoteNonRecordInitDependency(t, f->Yield());
				(void) TypeIndex(f->Yield());
				}
			}
			break;

		default:
			reporter->InternalError("bad type in CPPCompile::TypeIndex");
		}

		types.AddKey(t);
		}

	if ( types.HasKey(t) )
		{
		// The following (indirectly) recurses, but the check at
		// the top of this method keeps the code from reaching
		// this point.
		GenPreInit(t);
		return types.KeyIndex(tp);
		}
	else
		// This can happen when two types refer to one another.
		// Presumably our caller is discarding what we return.
		return -1;
	}

void CPPCompile::RecordAttributes(const AttributesPtr& attrs)
	{
	if ( ! attrs || attributes.HasKey(attrs) )
		return;

	attributes.AddKey(attrs);

	AddInit(attrs);

	for ( const auto& a : attrs->GetAttrs() )
		{
		const auto& e = a->GetExpr();
		if ( e )
			{
			init_exprs.AddKey(e);
			AddInit(e);
			NoteInitDependency(attrs, e);
			}
		}
	}

std::string CPPCompile::LocalName(const ID* l) const
	{
	auto n = l->Name();
	auto without_module = strstr(n, "::");

	if ( without_module )
		return Canonicalize(without_module + 2);
	else
		return Canonicalize(n);
	}

std::string CPPCompile::Canonicalize(const char* name) const
	{
	std::string cname;

	for ( int i = 0; name[i]; ++i )
		{
		auto c = name[i];
		if ( c == ':' )
			c = '_';

		cname = cname + c;
		}

	return cname;
	}

const char* CPPCompile::NativeAccessor(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:		return "->AsBool()";
	case TYPE_COUNT:	return "->AsCount()";
	case TYPE_DOUBLE:	return "->AsDouble()";
	case TYPE_ENUM:		return "->AsEnum()";
	case TYPE_INT:		return "->AsInt()";
	case TYPE_INTERVAL:	return "->AsDouble()";
	case TYPE_PORT:		return "->AsCount()";
	case TYPE_TIME:		return "->AsDouble()";

	case TYPE_ADDR:		return "->AsAddrVal()";
	case TYPE_FILE:		return "->AsFileVal()";
	case TYPE_FUNC:		return "->AsFuncVal()";
	case TYPE_OPAQUE:	return "->AsOpaqueVal()";
	case TYPE_PATTERN:	return "->AsPatternVal()";
	case TYPE_RECORD:	return "->AsRecordVal()";
	case TYPE_STRING:	return "->AsStringVal()";
	case TYPE_SUBNET:	return "->AsSubNetVal()";
	case TYPE_TABLE:	return "->AsTableVal()";
	case TYPE_TYPE:		return "->AsTypeVal()";
	case TYPE_VECTOR:	return "->AsVectorVal()";

	case TYPE_ANY:		return ".get()";

	case TYPE_VOID:		return "";

	default:
		reporter->InternalError("bad type in CPPCompile::NativeAccessor");
	}
	}

const char* CPPCompile::IntrusiveVal(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:		return "BoolVal";
	case TYPE_COUNT:	return "CountVal";
	case TYPE_DOUBLE:	return "DoubleVal";
	case TYPE_ENUM:		return "EnumVal";
	case TYPE_INT:		return "IntVal";
	case TYPE_INTERVAL:	return "IntervalVal";
	case TYPE_PORT:		return "PortVal";
	case TYPE_TIME:		return "TimeVal";

	case TYPE_ADDR:		return "AddrVal";
	case TYPE_ANY:		return "Val";
	case TYPE_FILE:		return "FileVal";
	case TYPE_FUNC:		return "FuncVal";
	case TYPE_OPAQUE:	return "OpaqueVal";
	case TYPE_PATTERN:	return "PatternVal";
	case TYPE_RECORD:	return "RecordVal";
	case TYPE_STRING:	return "StringVal";
	case TYPE_SUBNET:	return "SubNetVal";
	case TYPE_TABLE:	return "TableVal";
	case TYPE_TYPE:		return "TypeVal";
	case TYPE_VECTOR:	return "VectorVal";

	default:
		reporter->InternalError("bad type in CPPCompile::IntrusiveVal");
	}
	}

void CPPCompile::AddInit(const Obj* o, const std::string& init)
	{
	obj_inits[o].emplace_back(init);
	}

void CPPCompile::AddInit(const Obj* o)
	{
	if ( obj_inits.count(o) == 0 )
		{
		std::vector<std::string> empty;
		obj_inits[o] = empty;
		}
	}

void CPPCompile::NoteInitDependency(const Obj* o1, const Obj* o2)
	{
	obj_deps[o1].emplace(o2);
	}

void CPPCompile::StartBlock()
	{
	++block_level;
	Emit("{");
	}

void CPPCompile::EndBlock(bool needs_semi)
	{
	Emit("}%s", needs_semi ? ";" : "");
	--block_level;
	}

void CPPCompile::Indent() const
	{
	for ( auto i = 0; i < block_level; ++i )
		fprintf(write_file, "%s", "\t");
	}

} // zeek::detail
