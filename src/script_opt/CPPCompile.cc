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
	for ( const auto& e : init_exprs.Keys() )
		GenInitExpr(e);

	for ( const auto& a : attributes.Keys() )
		GenAttrs(a);

	const auto& tk = types.Keys();
	for ( const auto& t : tk )
		GenTypeVar(t);

	Emit("TypePtr types__CPP[%s] =", Fmt(types.Size()).c_str());
	StartBlock();
	for ( auto i = 0; i < tk.size(); ++i )
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
		Emit("return make_intrusive<%s>(v__CPP);", IntrusiveVal(t));
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
		const auto& ft = params->GetFieldType(i);

		if ( IsNativeType(ft) )
			res += arg_i + NativeAccessor(ft);
		else
			res += GenericValPtrToGT(arg_i, ft, GEN_VAL_PTR);

		if ( i < n - 1 )
			res += ", ";
		}

	return res;
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
				type_type, type_ind.c_str());
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
			Emit("%s;", GenExpr(e, GEN_DONT_CARE).c_str());
		}
		break;

	case STMT_IF:
		{
		auto i = s->AsIfStmt();
		auto cond = i->StmtExpr();

		Emit("if ( %s )", GenExpr(cond, GEN_NATIVE).c_str());
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
			GenExpr(w->Condition(), GEN_NATIVE).c_str());
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

		Emit("return %s;", GenExpr(e, GEN_NATIVE).c_str());
		}
		break;

	case STMT_ADD:
		{
		auto op = static_cast<const ExprStmt*>(s)->StmtExpr();
		auto aggr = GenExpr(op->GetOp1(), GEN_DONT_CARE);
		auto indices = op->GetOp2();

		Emit("%s->Assign(index_val__CPP({%s}), nullptr, true);",
			aggr.c_str(), GenExpr(indices, GEN_VAL_PTR).c_str());
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
				aggr.c_str(), GenExpr(indices, GEN_VAL_PTR).c_str());
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
			Emit("auto tv__CPP = %s;",
				GenExpr(v, GEN_DONT_CARE).c_str());
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
			Emit("auto vv__CPP = %s;",
				GenExpr(v, GEN_DONT_CARE).c_str());

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
				GenExpr(v, GEN_DONT_CARE).c_str());

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

std::string CPPCompile::GenExpr(const Expr* e, GenType gt)
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
		else
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
		return std::string("copy(") +
			GenExpr(static_cast<const CloneExpr*>(e), GEN_VAL_PTR) + ")";

	case EXPR_INCR:		return GenUnary(e, gt, "++");
	case EXPR_DECR:		return GenUnary(e, gt, "--");
	case EXPR_NOT:		return GenUnary(e, gt, "!");
	case EXPR_COMPLEMENT:	return GenUnary(e, gt, "~");
	case EXPR_POSITIVE:	return GenUnary(e, gt, "+");
	case EXPR_NEGATE:	return GenUnary(e, gt, "-");

	case EXPR_ADD:		return GenBinary(e, gt, "+");
	case EXPR_SUB:		return GenBinary(e, gt, "-");
	case EXPR_ADD_TO:	return GenBinary(e, gt, "+=");
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
				gen += "_func.Call(" + GenArgs(args_l) + ")";
				return NativeToGT(gen, t, gt);
				}
			}

		else
			// Indirect call.
			gen = std::string("(") + gen + ")->AsFunc()";

		auto args_list = std::string(", {") +
					GenExpr(args_l, GEN_VAL_PTR) + "})";
		auto invoker = std::string("invoke__CPP(") + gen + args_list;

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
		auto f_s = Fmt(f).c_str();

		gen = GenExpr(e->GetOp1(), GEN_DONT_CARE) +
			"->GetFieldOrDefault(" + f_s + ")";

		return GenericValPtrToGT(gen, t, gt);
		}

	case EXPR_HAS_FIELD:
		{
		auto f = e->AsHasFieldExpr()->Field();
		auto f_s = Fmt(f).c_str();

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

		else
			gen = std::string("INDEXBOTCH");

		return GenericValPtrToGT(gen, t, gt);
		}
		break;

	case EXPR_ASSIGN:
		{
		auto op1 = e->GetOp1()->AsRefExprPtr()->GetOp1();
		auto op2 = e->GetOp2();

		switch ( op1->Tag() ) {
		case EXPR_NAME:
			{
			auto n = op1->AsNameExpr()->Id();
			auto name = IDNameStr(n);

			if ( n->IsGlobal() )
				gen = globals[name] + "->SetVal(" +
					GenExpr(op2, GEN_VAL_PTR) + ")";
			else
				gen = name + " = " + GenExpr(op2, GEN_NATIVE);
			}
			break;

		case EXPR_INDEX:
			gen = std::string("assign_to_index__CPP(") +
				GenExpr(op1->GetOp1(), GEN_VAL_PTR) + ", " +
				"index_val__CPP({" +
				GenExpr(op1->GetOp2(), GEN_VAL_PTR) + "}), " +
				GenExpr(op2, GEN_VAL_PTR) + ")";
			break;

		case EXPR_FIELD:
			gen = GenExpr(op1->GetOp1(), GEN_DONT_CARE) +
				"->Assign(" +
				Fmt(op1->AsFieldExpr()->Field()) + ", " +
				GenExpr(op2, GEN_VAL_PTR) + ")";
			break;

		default:
			reporter->InternalError("bad assigment node in CPPCompile::GenExpr");
		}

		return NativeToGT(gen, t, gt);
		}

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
				GenExpr(op1, GEN_VAL_PTR) +
				GenIntVector(map) + ")";
		}

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
                //        reporter->InternalError("set union failed to type check"
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
		// make_intrusive<StringVal>(concatenate(strings))
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

	if ( op1->GetType()->Tag() != TYPE_PATTERN )
		return GenBinary(e, gt, op);

	auto op2 = e->GetOp1();
	std::string negated(e->Tag() == EXPR_EQ ? "" : "! ");

	return NativeToGT(negated + GenExpr(op1, GEN_DONT_CARE) +
				"->MatchExactly(" +
				GenExpr(op2, GEN_DONT_CARE) +
				"->AsString())",
				e->GetType(), gt);
	}

std::string CPPCompile::GenIntVector(const std::vector<int>& vec)
	{
	std::string res("{ ");

	for ( auto i = 0; i < vec.size(); ++i )	
		{
		res += Fmt(i);

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
	case TYPE_ENUM:
		return std::string("val_mgr->Int(") + expr + ")";

	case TYPE_COUNT:
		return std::string("val_mgr->Count(") + expr + ")";

	case TYPE_PORT:
		return std::string("val_mgr->Port(") + expr + ")";

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

	Emit("return %s;", GenExpr(e, GEN_NATIVE).c_str());
	EndBlock();

	EndBlock(true);

	Emit("auto %s_func = make_intrusive<%s>();", name.c_str(), name.c_str());

	Emit("auto %s = make_intrusive<CallExpr>(make_intrusive<ConstExpr>(make_intrusive<FuncVal>(wrapper_%s_func)), make_intrusive<ListExpr>(), false);",
		InitExprName(e).c_str(),
		InitExprName(e).c_str());
	}

std::string CPPCompile::InitExprName(const ExprPtr& e)
	{
	return init_exprs.KeyName(e);
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

void CPPCompile::GenTypeVar(const TypePtr& t)
	{
	NL();

	Emit("TypePtr %s", types.KeyName(t.get()).c_str());

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
			GenTypeName(t->AsFileType()->Yield()).c_str());
		break;

	case TYPE_OPAQUE:
		Emit("return make_intrusive<OpaqueType>(%s);",
			t->AsOpaqueType()->Name().c_str());
		break;

	case TYPE_TYPE:
		Emit("return make_intrusive<TypeType>(%s);",
			GenTypeName(t->AsTypeType()->GetType()).c_str());
		break;

	case TYPE_VECTOR:
		Emit("return make_intrusive<VectorType>(%s);",
			GenTypeName(t->AsVectorType()->Yield()).c_str());
		break;

	case TYPE_LIST:
		{
		Emit("auto tl = make_intrusive<TypeList>();");

		auto tl = t->AsTypeList()->GetTypes();
		for ( auto i = 0; i < tl.size(); ++i )
			Emit("tl->Append(%s);", GenTypeName(tl[i]).c_str());

		Emit("return tl;");
		}
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();

		if ( tbl->IsSet() )
			Emit("return make_intrusive<SetType>(%s, nullptr);",
				GenTypeName(tbl->GetIndices()).c_str());
		else
			Emit("return make_intrusive<TableType>(%s, %s);",
				GenTypeName(tbl->GetIndices()).c_str(),
				GenTypeName(tbl->Yield()).c_str());
		}
		break;

	case TYPE_RECORD:
		{
		auto r = t->AsRecordType()->Types();

		Emit("auto tl = new type_decl_list();");

		for ( auto i = 0; i < r->length(); ++i )
			{
			const auto& td = (*r)[i];

			auto type_accessor = GenTypeName(td->type);

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
		{
		auto f = t->AsFuncType();

		auto args_type_accessor = GenTypeName(f->Params());
		auto params = f->Params();
		auto yt = f->Yield();

		std::string yield_type_accessor;

		if ( yt )
			yield_type_accessor += "nullptr";
		else
			yield_type_accessor += GenTypeName(yt);

		Emit("return make_intrusive<FuncType>(%s, %s, FUNC_FLAVOR_FUNCTION);",
			args_type_accessor.c_str(),
			yield_type_accessor.c_str());
		}
		break;

	default:
		reporter->InternalError("bad type in CPPCompile::GenType");
	}

	EndBlock();
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

std::string CPPCompile::ParamDecl(const FuncTypePtr& ft)
	{
	const auto& params = ft->Params();
	int n = params->NumFields();

	std::string decl;

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = params->GetFieldType(i);
		auto tn = FullTypeName(t);
		auto fn = params->FieldName(i);

		if ( IsNativeType(t) )
			decl = decl + tn + " " + fn;
		else
			decl = decl + "const " + tn + "& " + fn;

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

	if ( ! types.HasKey(tp) )
		{
		// Add the type before going further, to avoid loops due to
		// types that reference each other.
		types.AddKey(t);

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

		case TYPE_FUNC:
			{
			auto f = t->AsFuncType();
			(void) TypeIndex(f->Params());

			if ( f->Yield() )
				(void) TypeIndex(f->Yield());
			}
			break;

		default:
			reporter->InternalError("bad type in CPPCompile::TypeIndex");
		}
		}

	return types.KeyIndex(tp);
	}

void CPPCompile::RecordAttributes(const AttributesPtr& attrs)
	{
	if ( ! attrs || attributes.HasKey(attrs) )
		return;

	attributes.AddKey(attrs);

	for ( const auto& a : attrs->GetAttrs() )
		{
		const auto& e = a->GetExpr();
		if ( e )
			init_exprs.AddKey(e);
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
	case TYPE_ENUM:		return "IntVal";	// use internal repr.
	case TYPE_INT:		return "IntVal";
	case TYPE_INTERVAL:	return "DoubleVal";	// use internal repr.
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
