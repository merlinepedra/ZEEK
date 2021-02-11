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
		CreateGlobals(func);

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
	for ( auto i = 0; i < init_exprs.size(); ++i )
		GenInitExpr(init_exprs[i]);

	for ( auto i = 0; i < attributes.size(); ++i )
		GenAttrs(attributes[i]);

	for ( auto i = 0; i < types.size(); ++i )
		GenType(types[i]);

	Emit("TypePtr types__CPP[%s] =", Fmt(int(types.size())).c_str());
	StartBlock();
	for ( auto i = 0; i < types.size(); ++i )
		Emit("gen_type%s__CPP(),", Fmt(i).c_str());
	EndBlock(true);

	Emit("} // zeek::detail");
	Emit("} // zeek");
	}

void CPPCompile::CreateGlobals(const FuncInfo& func)
	{
	if ( ! IsCompilable(func) )
		return;

	for ( const auto& b : func.Profile()->BiFCalls() )
		AddBiF(b);

	for ( const auto& g : func.Profile()->Globals() )
		{
		auto gn = std::string(g->Name());
		if ( globals.count(gn) == 0 )
			{
			AddGlobal(gn.c_str(), "gl");
			Emit("ID* %s;", globals[gn].c_str());
			}

		global_vars.emplace(g);
		}

	for ( const auto& s : func.Profile()->ScriptCalls() )
		AddGlobal(s->Name(), "zf");

	for ( const auto& c : func.Profile()->Constants() )
		AddConstant(c);
	}

void CPPCompile::AddBiF(const Func* b)
	{
	auto n = b->Name();

	if ( globals.count(n) > 0 )
		return;

	AddGlobal(n, "bif");

	Emit("BuiltinFunc* %s;", globals[std::string(n)].c_str());
	}

void CPPCompile::AddGlobal(const char* g, const char* suffix)
	{
	std::string gs(g);

	if ( globals.count(gs) == 0 )
		globals.emplace(gs, GlobalName(g, suffix));
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
		constants[c_desc] =
			std::string("CPP__const__") + Fmt(int(constants.size()));

		switch ( c->GetType()->Tag() ) {
		case TYPE_STRING:
			Emit("const StringValPtr %s = make_intrusive<StringVal>(%s);",
				constants[c_desc].c_str(), c_desc.c_str());
			break;

		case TYPE_PATTERN:
			Emit("// ### Need to deal with case sensitivity, compiling");
			Emit("const PatternValPtr %s = make_intrusive<PatternVal>(new RE_Matcher(\"%s\"));",
				constants[c_desc].c_str(),
				v->AsPatternVal()->Get()->OrigText());
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

	auto fname = Canonicalize(func.Func()->Name()) + "__zf";
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

	Emit("class %s : public CPPFunc", fname.c_str());
	StartBlock();

	Emit("public:");
	Emit("%s() : CPPFunc(\"%s\", %s) { }", fname.c_str(), func.Func()->Name(),
		is_pure ? "true" : "false");

	const auto& ft = func.Func()->GetType();
	const auto& yt = ft->Yield();

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override");
	StartBlock();

	if ( IsNativeType(yt) )
		{
		auto args = BindArgs(func.Func()->GetType());
		GenInvokeBody(yt, args.c_str());
		}
	else
		Emit("return Call(%s);",
			BindArgs(func.Func()->GetType()).c_str());

	EndBlock();

	Emit("static %s Call(%s);", FullTypeName(yt), ParamDecl(ft).c_str());

	EndBlock(true);

	Emit("%s %s_func;", fname.c_str(), fname.c_str());

	compiled_funcs.emplace(fname);
	}

void CPPCompile::GenInvokeBody(const TypePtr& t, const char* args)
	{
	switch ( t->Tag() ) {
	case TYPE_VOID:
		Emit("Call(%s);", args);
		Emit("return nullptr;");
		break;

	case TYPE_BOOL:
		Emit("return val_mgr->Bool(Call(%s));", args);
		break;

	case TYPE_INT:
	case TYPE_ENUM:
		Emit("return val_mgr->Int(Call(%s));", args);
		break;

	case TYPE_COUNT:
		Emit("return val_mgr->Count(Call(%s));", args);
		break;

	case TYPE_PORT:
		Emit("return val_mgr->Port(Call(%s));", args);
		break;

	default:
		Emit("auto v__CPP = Call(%s);", args);
		Emit("return make_intrusive<%s>(v__CPP);", NativeVal(t));
	}
	}

void CPPCompile::DefineBody(const FuncInfo& func, const std::string& fname)
	{
	locals.clear();
	params.clear();

	const auto& ft = func.Func()->GetType();
	const auto& yt = ft->Yield();

	const auto& p = ft->Params();
	for ( auto i = 0; i < p->NumFields(); ++i )
		params.emplace(std::string(p->FieldName(i)));

	Emit("%s %s::Call(%s)", FullTypeName(yt), fname.c_str(),
		ParamDecl(ft).c_str());

	StartBlock();

	DeclareLocals(func);

	NL();
	GenStmt(func.Body());

	EndBlock();
	}

void CPPCompile::DeclareLocals(const FuncInfo& func)
	{
	const auto& ls = func.Profile()->Locals();

	for ( const auto& l : ls )
		{
		auto ln = LocalName(l);

		if ( params.count(ln) == 0 )
			Emit("%s %s;", FullTypeName(l->GetType()), ln.c_str());

		locals.emplace(l, ln);
		}
	}

std::string CPPCompile::BindArgs(const FuncTypePtr& ft)
	{
	const auto& params = ft->Params();

	std::string res;

	int n = params->Types()->size();
	for ( auto i = 0; i < n; ++i )
		{
		auto arg_i = std::string("(*args)[") + Fmt(i) + "]";

		res += arg_i + NativeAccessor(params->GetFieldType(i));

		if ( i < n - 1 )
			res += ", ";
		}

	return res;
	}

std::string CPPCompile::ValToNative(std::string v, const TypePtr& t)
	{
	if ( t->Tag() == TYPE_VOID )
		return v;

	std::string res;

	if ( IsNativeType(t) )
		return v + NativeAccessor(t);

	// return std::string("{AdoptRef{}, static_cast<") + TypeName(t) +
	//		"*>(" + v + ".release())}";
	return std::string("cast_intrusive<") + TypeName(t) +
			">(" + v + ")";
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

			auto type_name = TypeName(t);
			auto type_type = TypeType(t);
			auto type_ind = Fmt(TypeIndex(t)).c_str();

			Emit("%s = make_intrusive<%s>(cast_intrusive<%s>(types__CPP[%s]));",
				IDName(aggr), type_name, type_type, type_ind);
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
			Emit("%s;", GenExpr(e).c_str());
		}
		break;

	case STMT_IF:
		{
		auto i = s->AsIfStmt();
		auto cond = i->StmtExpr();

		Emit("if ( %s )", GenExpr(cond).c_str());
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
		Emit("while ( %s )", GenExpr(w->Condition()).c_str());
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

		auto ret = GenExpr(e);
		if ( ! IsNativeType(e->GetType()) && ! ExprIsValPtr(e) )
			ret = std::string("{NewRef{}, ") + ret + "}";

		Emit("return %s;", ret.c_str());
		}
		break;

	case STMT_ADD:
		{
		auto op = static_cast<const ExprStmt*>(s)->StmtExpr();
		auto aggr = GenExpr(op->GetOp1());
		auto indices = op->GetOp2();

		Emit("%s->Assign(index_val__CPP({%s}), nullptr, true);",
			aggr.c_str(), GenValExpr(indices).c_str());
		}
		break;

	case STMT_DELETE:
		{
		auto op = static_cast<const ExprStmt*>(s)->StmtExpr();
		auto aggr = GenExpr(op->GetOp1());

		if ( op->Tag() == EXPR_INDEX )
			{
			auto indices = op->GetOp2();

			Emit("%s->Remove(*(index_val__CPP({%s}).get()), true);",
				aggr.c_str(), GenValExpr(indices).c_str());
			}

		else
			{
			ASSERT(op->Tag() == EXPR_FIELD);
			auto field = Fmt(op->AsFieldExpr()->Field()).c_str();
			Emit("%s->Assign(%s, nullptr);", aggr.c_str(), field);
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
			Emit("TableVal* tv__CPP = %s;", GenExpr(v).c_str());
			Emit("const PDict<TableEntryVal>* loop_vals__CPP = tv__CPP->AsTable();");

			Emit("if ( loop_vals__CPP->Length() > 0 )");
			StartBlock();

			Emit("for ( const auto& lve__CPP : *loop_vals__CPP )");
			StartBlock();

			Emit("auto k__CPP = lve__CPP.GetHashKey();");
			Emit("auto* current_tev__CPP = lve__CPP.GetValue<TableEntryVal*>();");
			Emit("auto ind_lv__CPP = tv__CPP->RecreateIndex(*k__CPP);");

                        if ( value_var )
				Emit("%s = current_tev__CPP->GetVal();",
					IDName(value_var));

			for ( int i = 0; i < loop_vars->length(); ++i )
				{
				auto var = (*loop_vars)[i];
				const auto& v_t = var->GetType();
				auto acc = NativeAccessor(v_t);

				if ( IsNativeType(v_t) )
					Emit("%s = ind_lv__CPP->Idx(%s)%s;",
						IDName(var), Fmt(i).c_str(),
						acc);
				else
					Emit("%s = {NewRef{}, ind_lv__CPP->Idx(%s)%s};",
						IDName(var), Fmt(i).c_str(),
						acc);
				}

			GenStmt(f->LoopBody());
			EndBlock();
			EndBlock();
			}

		else if ( t == TYPE_VECTOR )
			{
			Emit("VectorVal* vv__CPP = %s;", GenExpr(v).c_str());

			Emit("for ( auto i__CPP = 0u; i__CPP < vv__CPP->Size(); ++i__CPP )");
			StartBlock();

			Emit("if ( ! vv__CPP->At(i__CPP) ) continue;");
			Emit("%s = i__CPP;", IDName((*loop_vars)[0]));

			GenStmt(f->LoopBody());
			EndBlock();
			}

		else if ( t == TYPE_STRING )
			{
			Emit("StringVal* sval__CPP = %s;", GenExpr(v).c_str());

			Emit("for ( auto i__CPP = 0u; i__CPP < sval__CPP->Len(); ++i )");
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

	case STMT_PRINT:
	case STMT_EVENT:
	case STMT_WHEN:
	case STMT_SWITCH:
	case STMT_NEXT:
	case STMT_BREAK:
	case STMT_FALLTHROUGH:
		ASSERT(0);
		break;

	default:
		reporter->InternalError("bad statement type in CPPCompile::GenStmt");
	}
	}

std::string CPPCompile::GenExpr(const Expr* e)
	{
	std::string gen;

	switch ( e->Tag() ) {
	case EXPR_NAME:
		{
		auto n = e->AsNameExpr()->Id();
		auto name = IDNameStr(n);

		if ( global_vars.count(n) > 0 )
			name = name + "->GetVal()" +
				NativeAccessor(n->GetType());

		return name;
		}

	case EXPR_CONST:
		{
		auto c = e->AsConstExpr();

		if ( IsNativeType(c->GetType()) )
			{
			auto v = c->Value();
			const auto& t = c->GetType()->Tag();

			// Check for types that don't render into what
			// C++ expects.

			if ( t == TYPE_BOOL )
				return std::string(v->IsZero() ? "false" : "true");

			if ( t == TYPE_ENUM )
				return Fmt(v->AsEnum());

			if ( t == TYPE_PORT )
				return Fmt(v->AsCount());

			if ( t == TYPE_INTERVAL )
				return Fmt(v->AsDouble());

			ODesc d;
			d.SetQuotes(true);
			v->Describe(&d);
			return std::string(d.Description());
			}

		ASSERT(const_exprs.count(c) > 0);
		return const_exprs[c];
		}

	case EXPR_CLONE:
		return std::string("copy(") +
			GenExpr(static_cast<const CloneExpr*>(e)) + ")";

	case EXPR_INCR:		return GenUnary(e, "++");
	case EXPR_DECR:		return GenUnary(e, "--");
	case EXPR_NOT:		return GenUnary(e, "!");
	case EXPR_COMPLEMENT:	return GenUnary(e, "~");
	case EXPR_POSITIVE:	return GenUnary(e, "+");
	case EXPR_NEGATE:	return GenUnary(e, "-");

	case EXPR_ADD:		return GenBinary(e, "+");
	case EXPR_SUB:		return GenBinary(e, "-");
	case EXPR_ADD_TO:	return GenBinary(e, "+=");
	case EXPR_REMOVE_FROM:	return GenBinary(e, "-=");
	case EXPR_TIMES:	return GenBinary(e, "*");
	case EXPR_DIVIDE:	return GenBinary(e, "/");
	case EXPR_MOD:		return GenBinary(e, "%");
	case EXPR_AND:		return GenBinary(e, "&");
	case EXPR_OR:		return GenBinary(e, "|");
	case EXPR_XOR:		return GenBinary(e, "^");
	case EXPR_AND_AND:	return GenBinary(e, "&&");
	case EXPR_OR_OR:	return GenBinary(e, "||");
	case EXPR_LT:		return GenBinary(e, "<");
	case EXPR_LE:		return GenBinary(e, "<=");
	case EXPR_GE:		return GenBinary(e, ">=");
	case EXPR_GT:		return GenBinary(e, ">");

	case EXPR_EQ:		return GenEQ(e, "==");
	case EXPR_NE:		return GenEQ(e, "!=");

	case EXPR_COND:
		{
		auto op1 = e->GetOp1();
		auto op2 = e->GetOp2();
		auto op3 = e->GetOp3();

		auto gen1 = GenExpr(op1);
		auto gen2 = GenExpr(op2);
		auto gen3 = GenExpr(op3);

		if ( ! IsNativeType(e->GetType()) )
			{
			if ( ExprIsValPtr(op2.get()) )
				gen2 = gen2 + ".get()";

			if ( ExprIsValPtr(op3.get()) )
				gen3 = gen3 + ".get()";
			}

		return std::string("(") + gen1 + ") ? (" +
			gen2 + ") : (" + gen3 + ")";
		}

	case EXPR_CALL:
		{
		auto c = e->AsCallExpr();
		auto f = c->Func();
		auto args_l = c->Args();

		gen = GenExpr(f);

		if ( f->Tag() == EXPR_NAME )
			{
			auto func = f->AsNameExpr()->Id();
			auto func_name = IDNameStr(func);

			if ( compiled_funcs.count(func_name) > 0 )
				return gen + "_func.Call(" + GenArgs(args_l) + ")";
			}

		else
			// Indirect call.
			gen = std::string("(") + gen + ")->AsFunc()";

		gen = std::string("invoke__CPP(") + gen +
			", {" + GenValExpr(args_l) + "})";

		return gen + NativeAccessor(f->GetType()->Yield());
		}

	case EXPR_LIST:
		{
		const auto& exprs = e->AsListExpr()->Exprs();

		int n = exprs.size();

		for ( auto i = 0; i < n; ++i )
			{
			gen = gen + GenExpr(exprs[i]);
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
			return std::string("(") + GenExpr(op1) +
				")->MatchAnywhere(" + GenExpr(op2) + "->AsString())";

		if ( t2->Tag() == TYPE_STRING )
			// CPP__str_in(s1, s2): return util::strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1
			return std::string("CPP__str_in(") + GenExpr(op1) +
				", " + GenExpr(op2) + ")";

		if ( t1->Tag() == TYPE_ADDR && t2->Tag() == TYPE_SUBNET )
			return std::string("(") + GenExpr(op2) + ")" +
				"->Contains(" + GenValExpr(op1) + ")";

		if ( t2->Tag() == TYPE_VECTOR )
			// v1->AsListVal()->Idx(0)->CoerceToUnsigned()
			return GenExpr(op2) + "->At(" + GenExpr(op1) + ")";

		return std::string("(") + GenExpr(op2) +
			"->Find(index_val__CPP({" + GenValExpr(op1) +
			"})) ? true : false)";
		}

	case EXPR_FIELD:
		{
		auto f = e->AsFieldExpr()->Field();
		auto f_s = Fmt(f).c_str();

		// Need to use accessors for native types.
		return GenExpr(e->GetOp1()) +
			"->GetFieldOrDefault(" + f_s + ")" +
			NativeAccessor(e->GetType());
		}

	case EXPR_HAS_FIELD:
		{
		auto f = e->AsHasFieldExpr()->Field();
		auto f_s = Fmt(f).c_str();

		// Need to use accessors for native types.
		return std::string("(") + GenExpr(e->GetOp1()) +
			"->GetField(" + f_s + ") != nullptr)";
		}

	case EXPR_INDEX:
		{
		auto aggr = e->GetOp1();
		const auto& aggr_t = aggr->GetType();

		auto yield = NativeAccessor(e->GetType());

		if ( aggr_t->Tag() == TYPE_TABLE )
			return std::string("index_table__CPP(") +
				GenExpr(aggr) + ", {" +
				GenValExpr(e->GetOp2()) + "})" + yield;

		if ( aggr_t->Tag() == TYPE_VECTOR )
			return GenExpr(aggr) + "->At(" + GenExpr(e->GetOp2()) +
				")" + yield;

		return std::string("INDEXBOTCH");
		}
		break;

	case EXPR_ASSIGN:
		{
		auto op1 = e->GetOp1()->AsRefExprPtr()->GetOp1();
		auto op2 = e->GetOp2();

		switch ( op1->Tag() ) {
		case EXPR_NAME:
			if ( IsNativeType(op1->GetType()) )
				return GenExpr(op1) + "=" + GenExpr(op2);
			else
				return GenExpr(op1) + "=" + GenValExpr(op2);

		case EXPR_INDEX:
			return std::string("assign_to_index__CPP(") +
				GenValExpr(op1->GetOp1()) + ", " +
				"index_val__CPP({" +
				GenValExpr(op1->GetOp2()) + "}), " +
				GenValExpr(op2) + ")";

		case EXPR_FIELD:
			return GenExpr(op1->GetOp1()) + "->Assign(" +
				Fmt(op1->AsFieldExpr()->Field()) + ", " +
				GenValExpr(op2) + ")";

		default:
			reporter->InternalError("bad assigment node in CPPCompile::GenExpr");
		}
		}
		break;

	case EXPR_REF:
		return GenExpr(e->GetOp1());

	case EXPR_SIZE:
		return GenExpr(e->GetOp1()) + "->SizeVal()" +
			NativeAccessor(e->GetType());

	case EXPR_ARITH_COERCE:
		{
		auto t = e->GetType()->InternalType();
		auto cast_name =
			t == TYPE_INTERNAL_DOUBLE ? "double" :
				(t == TYPE_INTERNAL_INT ?
					"bro_int_t" : "bro_uint_t");

		return std::string(cast_name) + "(" + GenExpr(e->GetOp1()) + ")";
		}

	case EXPR_RECORD_COERCE:
		return std::string("record_coerce()");

	case EXPR_TABLE_COERCE:
		return std::string("table_coerce()");

	case EXPR_RECORD_CONSTRUCTOR:
		return std::string("record_constructor()");

	case EXPR_SET_CONSTRUCTOR:
		return std::string("set_constructor()");

	case EXPR_TABLE_CONSTRUCTOR:
		return std::string("table_constructor()");

	case EXPR_VECTOR_CONSTRUCTOR:
		return std::string("vector_constructor()");

	case EXPR_SCHEDULE:
		return std::string("schedule()");

	case EXPR_FIELD_ASSIGN:
	case EXPR_LAMBDA:
	case EXPR_EVENT:
	case EXPR_VECTOR_COERCE:
	case EXPR_CAST:
	case EXPR_IS:
	case EXPR_INDEX_SLICE_ASSIGN:
	case EXPR_INLINE:
		ASSERT(0);

	default:
		return std::string("EXPR");
	}
	}

std::string CPPCompile::GenValExpr(const Expr* e)
	{
	if ( e->Tag() == EXPR_LIST )
		{
		const auto& exprs = e->AsListExpr()->Exprs();
		std::string gen;

		int n = exprs.size();

		for ( auto i = 0; i < n; ++i )
			{
			gen = gen + GenValExpr(exprs[i]);
			if ( i < n - 1 )
				gen += ", ";
			}

		return gen;
		}

	const auto& t = e->GetType();

	if ( IsNativeType(t) )
		return std::string("make_intrusive<") + NativeVal(t) +
				">(" + GenExpr(e) + ")";

	if ( ExprIsValPtr(e) )
		return GenExpr(e);

	return std::string("val_to_valptr__CPP<") + TypeName(t) + ">(" +
		GenExpr(e) + ")";
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

	const auto& t = e->GetType();

	auto res = GenExpr(e);

	if ( ExprIsValPtr(e) )
		res = res + ".get()";

	return res;
	}

bool CPPCompile::ExprIsValPtr(const Expr* e) const
	{
	if ( IsNativeType(e->GetType()) )
		return false;

	if ( e->Tag() == EXPR_CONST )
		return true;

	if ( e->Tag() == EXPR_NAME )
		{
		auto n = e->AsNameExpr()->Id();

		if ( global_vars.count(n) > 0 )
			return false;

		if ( params.count(LocalName(n)) > 0 )
			return false;

		return true;
		}

	if ( e->Tag() == EXPR_CALL )
		{
		auto f = e->AsCallExpr()->Func();

		if ( f->Tag() == EXPR_NAME )
			{
			auto func = f->AsNameExpr()->Id();
			auto func_name = IDNameStr(func);

			if ( compiled_funcs.count(func_name) > 0 )
				return true;
			}
		}

	return false;
	}

std::string CPPCompile::GenUnary(const Expr* e, const char* op)
	{
	return std::string(op) + "(" + GenExpr(e->GetOp1()) + ")";
	}

std::string CPPCompile::GenBinary(const Expr* e, const char* op)
	{
	const auto& op1 = e->GetOp1();
	const auto& op2 = e->GetOp2();

	auto t = op1->GetType();

	if ( t->IsSet() )
		return GenBinarySet(e, op);

	switch ( t->InternalType() ) {
	case TYPE_INTERNAL_STRING:
		return GenBinaryString(e, op);

	case TYPE_INTERNAL_ADDR:
		return GenBinaryAddr(e, op);

	case TYPE_INTERNAL_SUBNET:
		return GenBinarySubNet(e, op);

	default:
		if ( t->Tag() == TYPE_PATTERN )
			return GenBinaryPattern(e, op);
		break;
	}

	return std::string("(") + GenExpr(e->GetOp1()) + ")" +
		op + "(" + GenExpr(e->GetOp2()) + ")";
	}

std::string CPPCompile::GenBinarySet(const Expr* e, const char* op)
	{
	auto v1 = GenExpr(e->GetOp1()) + "->AsTableVal()";
	auto v2 = GenExpr(e->GetOp2()) + "->AsTableVal()";

	switch ( e->Tag() ) {
	case EXPR_AND:
		return v1 + "->Intersection(*" + v2 + ")";

	case EXPR_OR:
                // auto rval = v1->Clone();
                // if ( ! tv2->AddTo(rval.get(), false, false) )
                //        reporter->InternalError("set union failed to type check"
		return v1 + "->Union(*" + v2 + ")";

	case EXPR_SUB:
		//                 if ( ! tv2->RemoveFrom(rval.get()) )
		return v1 + "->TakeOut(*" + v2 + ")";

	case EXPR_EQ:
		return v1 + "->EqualTo(*" + v2 + ")";

	case EXPR_NE:
		return std::string("! ") + v1 + "->EqualTo(*" + v2 + ")";

	case EXPR_LE:
		return v1 + "->IsSubsetOf(*" + v2 + ")";

	case EXPR_LT:
		return std::string("(") + v1 + "->IsSubsetOf(*" + v2 + ") &&" +
			v1 + "->Size() < " + v2 + "->Size())";

	default:
		reporter->InternalError("bad type in CPPCompile::GenBinarySet");
	}
	}

std::string CPPCompile::GenBinaryString(const Expr* e, const char* op)
	{
	auto v1 = GenExpr(e->GetOp1()) + "->AsString()";
	auto v2 = GenExpr(e->GetOp2()) + "->AsString()";

	if ( e->Tag() == EXPR_ADD || e->Tag() == EXPR_ADD_TO )
		// make_intrusive<StringVal>(concatenate(strings))
		return std::string("str_concat__CPP(") + v1 + ", " + v2 + ")";

	return std::string("(Bstr_cmp(") + v1 + ", " + v2 + ") " + op + " 0)";
	}

std::string CPPCompile::GenBinaryPattern(const Expr* e, const char* op)
	{
	auto v1 = GenExpr(e->GetOp1()) + "->AsPattern()";
	auto v2 = GenExpr(e->GetOp2()) + "->AsPattern()";

	auto func = e->Tag() == EXPR_AND ?
			"RE_Matcher_conjunction" : "RE_Matcher_disjunction";

	return std::string("make_intrusive<PatternVal>(") +
		func + "(" + v1 + ", " + v2 + "))";
	}

std::string CPPCompile::GenBinaryAddr(const Expr* e, const char* op)
	{
	auto v1 = GenExpr(e->GetOp1()) + "->AsAddr()";
	auto v2 = GenExpr(e->GetOp2()) + "->AsAddr()";

	return v1 + op + v2;
	}

std::string CPPCompile::GenBinarySubNet(const Expr* e, const char* op)
	{
	auto v1 = GenExpr(e->GetOp1()) + "->AsSubNet()";
	auto v2 = GenExpr(e->GetOp2()) + "->AsSubNet()";

	return v1 + op + v2;
	}

std::string CPPCompile::GenEQ(const Expr* e, const char* op)
	{
	std::string negated(e->Tag() == EXPR_EQ ? "" : "! ");

	auto op1 = e->GetOp1();
	auto op2 = e->GetOp1();

	auto t = op1->GetType()->Tag();

	if ( t == TYPE_PATTERN )
		return negated + GenExpr(op1) + "->MatchExactly(" +
			GenExpr(op2) + "->AsString()";

	return GenBinary(e, op);
	}

void CPPCompile::GenInitExpr(const ExprPtr& e)
	{
	NL();

	// First, create a CPPFunc that we can compile to compute e.
	auto name = std::string("wrapper_") + InitExprName(e);
	Emit("class %s : public CPPFunc", name.c_str());
	StartBlock();

	Emit("public:");
	Emit("%s() : CPPFunc(\"%s\", false) { }", name.c_str(), name.c_str());

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override");
	StartBlock();

	const auto& t = e->GetType();

	if ( IsNativeType(t) )
		GenInvokeBody(t, "");
	else
		Emit("return Call();");

	EndBlock();

	Emit("%s Call() const", FullTypeName(t));
	StartBlock();

	auto ret = GenExpr(e);
	if ( ! IsNativeType(t) && ! ExprIsValPtr(e) )
		ret = std::string("{NewRef{}, ") + ret + "}";

	Emit("return %s;", ret.c_str());
	EndBlock();

	EndBlock(true);

	Emit("auto %s_func = make_intrusive<%s>();", name.c_str(), name.c_str());

	Emit("auto %s = make_intrusive<CallExpr>(make_intrusive<ConstExpr>(make_intrusive<FuncVal>(wrapper_%s_func)), make_intrusive<ListExpr>(), false);",
		InitExprName(e).c_str(),
		InitExprName(e).c_str());
	}

std::string CPPCompile::InitExprName(const ExprPtr& e)
	{
	ASSERT(init_expr_map.count(e.get()) > 0);
	return std::string("gen_init_expr") +
		Fmt(init_expr_map[e.get()]) + "__CPP";
	}

void CPPCompile::GenAttrs(const AttributesPtr& attrs)
	{
	NL();

	Emit("AttributesPtr %s", AttrsName(attrs).c_str());

	StartBlock();

	const auto& avec = attrs->GetAttrs();
	Emit("auto attrs = std::vector<AttrPtr>();");

	for ( auto i = 0; i < avec.size(); ++i )
		{
		const auto& attr = avec[i];

		if ( attr->GetExpr() )
			Emit("attrs.emplace_back(make_intrusive<Attr>(%s, %s));",
				AttrName(attr),
				InitExprName(attr->GetExpr()).c_str());
		else
			Emit("attrs.emplace_back(make_intrusive<Attr>(%s));",
				AttrName(attr));
		}

	Emit("return make_intrusive<Attributes>(attrs, nullptr, true, false);");

	EndBlock();
	}

std::string CPPCompile::AttrsName(const AttributesPtr& a)
	{
	ASSERT(attrs_map.count(a.get()) > 0);
	return std::string("gen_attrs") + Fmt(attrs_map[a.get()]) + "__CPP()";
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

void CPPCompile::GenType(const TypePtr& t)
	{
	NL();

	Emit("TypePtr %s", GeneratedTypeName(t).c_str());

	StartBlock();

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
		Emit("return base_type(%s);", TypeTagName(t->Tag()));
		break;

	case TYPE_SUBNET:   
		Emit("return make_intrusive<SubNetType>();");
		break;

	case TYPE_FILE:
		Emit("return make_intrusive<FileType>(%s);",
			TypeName(t->AsFileType()->Yield()));
		break;

	case TYPE_OPAQUE:
		Emit("return make_intrusive<OpaqueType>(%s);",
			t->AsOpaqueType()->Name().c_str());
		break;

	case TYPE_TYPE:
		Emit("return make_intrusive<TypeType>(%s);",
			TypeName(t->AsTypeType()->GetType()));
		break;

	case TYPE_VECTOR:
		Emit("return make_intrusive<VectorType>(%s);",
			TypeName(t->AsVectorType()->Yield()));
		break;

	case TYPE_LIST:
		{
		Emit("auto tl = make_intrusive<TypeList>();");

		auto tl = t->AsTypeList()->GetTypes();
		for ( auto i = 0; i < tl.size(); ++i )
			Emit("tl->Append(%s);", TypeName(tl[i]));

		Emit("return tl;");
		}
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();

		if ( tbl->IsSet() )
			Emit("return make_intrusive<SetType>(%s, nullptr);",
				TypeName(tbl->GetIndices()));
		else
			Emit("return make_intrusive<TableType>(%s, %s);",
				TypeName(tbl->GetIndices()),
				TypeName(tbl->Yield()));
		}
		break;

	case TYPE_RECORD:
		{
		auto r = t->AsRecordType()->Types();

		Emit("auto tl = new type_decl_list();");

		for ( auto i = 0; i < r->length(); ++i )
			{
			const auto& td = (*r)[i];

			auto type_accessor = std::string("types__CPP[") +
				Fmt(TypeIndex(td->type)).c_str() + "]";

			if ( td->attrs )
				Emit("tl->append(new TypeDecl(\"%s\", %s, %s));",
					td->id, type_accessor.c_str(),
					AttrsName(td->attrs).c_str());
			else
				Emit("tl->append(new TypeDecl(\"%s\", %s));",
					td->id, type_accessor.c_str());
			}

		Emit("return make_intrusive<RecordType>(tl);");
		}
		break;

	case TYPE_FUNC:
	default:
		reporter->InternalError("bad type in CPPCompile::GenType");
	}

	EndBlock();
	}

std::string CPPCompile::GeneratedTypeName(const TypePtr& t)
	{
	ASSERT(type_map.count(t.get()) > 0);
	return std::string("gen_type") + Fmt(type_map[t.get()]) + "__CPP()";
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

std::string CPPCompile::ParamDecl(const FuncTypePtr& ft)
	{
	const auto& params = ft->Params();
	int n = params->NumFields();

	std::string decl;

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = params->GetFieldType(i);
		auto tn = TypeName(t);
		auto fn = params->FieldName(i);

		if ( IsNativeType(t) )
			decl = decl + tn + " " + fn;
		else
			decl = decl + tn + "* " + fn;

		if ( i < n - 1 )
			decl += ", ";
		}

	return decl;
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

	if ( type_map.count(tp) == 0 )
		{
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
			(void) TypeIndex(t->AsTypeType()->GetType());
			break;

		case TYPE_VECTOR:
			(void) TypeIndex(t->AsVectorType()->Yield());
			break;

		case TYPE_LIST:
			{
			auto tl = t->AsTypeList()->GetTypes();
			for ( auto i = 0; i < tl.size(); ++i )
				(void) TypeIndex(tl[i]);
			}
			break;

		case TYPE_TABLE:
			{
			auto tbl = t->AsTableType();
			(void) TypeIndex(tbl->GetIndices());

			if ( ! tbl->IsSet() )
				(void) TypeIndex(tbl->Yield());
			}
			break;

		case TYPE_RECORD:
			{
			auto r = t->AsRecordType()->Types();

			for ( auto i = 0; i < r->length(); ++i )
				{
				const auto& r_i = (*r)[i];
				(void) TypeIndex(r_i->type);
				RecordAttributes(r_i->attrs);
				}
			}
			break;

		default:
			reporter->InternalError("bad type in CPPCompile::TypeIndex");
		}

		type_map[tp] = type_map.size();
		types.emplace_back(t);
		}

	return type_map[tp];
	}

void CPPCompile::RecordAttributes(const AttributesPtr& attrs)
	{
	if ( ! attrs || attrs_map.count(attrs.get()) > 0 )
		return;

	attrs_map[attrs.get()] = attrs_map.size();
	attributes.emplace_back(attrs);

	for ( const auto& a : attrs->GetAttrs() )
		{
		const auto& e = a->GetExpr();
		if ( e && init_expr_map.count(e.get()) == 0 )
			{
			init_expr_map[e.get()] = init_expr_map.size();
			init_exprs.emplace_back(e);
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

const char* CPPCompile::NativeVal(const TypePtr& t)
	{
	switch ( t->Tag() ) {
	case TYPE_BOOL:		return "BoolVal";
	case TYPE_COUNT:	return "CountVal";
	case TYPE_DOUBLE:	return "DoubleVal";
	case TYPE_ENUM:		return "IntVal";	// use internal repr.
	case TYPE_INT:		return "IntVal";
	case TYPE_INTERVAL:	return "DoubleVal";	// use internal repr.
	case TYPE_PORT:		return "PortVal";
	case TYPE_TIME:		return "TimeVal";

	default:
		reporter->InternalError("bad type in CPPCompile::NativeVal");
	}
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
