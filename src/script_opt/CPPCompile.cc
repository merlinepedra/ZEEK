// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zeek/RE.h"
#include "zeek/script_opt/CPPCompile.h"
#include "zeek/script_opt/ProfileFunc.h"


namespace zeek::detail {


CPPCompile::CPPCompile(std::vector<FuncInfo>& _funcs, ProfileFuncs& _pfs,
		const char* gen_name, CPPHashManager& _hm, bool _update)
: funcs(_funcs), pfs(_pfs), hm(_hm), update(_update)
	{
	auto mode = hm.IsAppend() ? "a" : "w";

	write_file = fopen(gen_name, mode);
	if ( ! write_file )
		{
		reporter->Error("can't open C++ target file %s", gen_name);
		exit(1);
		}

	if ( hm.IsAppend() )
		{
		struct stat st;
		if ( fstat(fileno(write_file), &st) != 0 )
			{
			char buf[256];
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Error("fstat failed on %s: %s", gen_name, buf);
			exit(1);
			}

		addl_tag = st.st_size + 1;
		}

	Compile();
	}

CPPCompile::~CPPCompile()
	{
	fclose(write_file);
	}

void CPPCompile::Compile()
	{
	char buf[8192];
	getcwd(buf, sizeof buf);
	working_dir = buf;

	if ( update && addl_tag > 0 )
		{
		for ( auto& g : pfs.AllGlobals() )
			{
			auto gn = std::string(g->Name());

			if ( hm.HasGlobal(gn) )
				{
				auto ht_orig = hm.GlobalTypeHash(gn);
				auto hv_orig = hm.GlobalValHash(gn);

				auto ht = pfs.HashType(g->GetType());
				hash_type hv = 0;
				if ( g->GetVal() )
					hv = hash_obj(g->GetVal());

				if ( ht != ht_orig || hv != hv_orig )
					{
					fprintf(stderr, "%s: hash clash for global %s (%llu/%llu vs. %llu/%llu)\n",
						working_dir.c_str(), gn.c_str(),
						ht, hv, ht_orig, hv_orig);
					fprintf(stderr, "val: %s\n", g->GetVal() ? obj_desc(g->GetVal().get()).c_str() : "<none>");
					exit(1);
					}
				}
			}

		bool collision = false;
		for ( auto& t : pfs.RepTypes() )
			{
			auto tag = t->Tag();

			if ( tag != TYPE_ENUM && tag != TYPE_RECORD )
				continue;

			const auto& tn = t->GetName();
			if ( tn.size() == 0 || ! hm.HasGlobal(tn) )
				continue;

			if ( tag == TYPE_ENUM && hm.HasEnumTypeGlobal(tn) )
				continue;

			if ( tag == TYPE_RECORD && hm.HasRecordTypeGlobal(tn) )
				continue;

			fprintf(stderr, "%s: type \"%s\" collides with compiled global\n",
				working_dir.c_str(), tn.c_str());
			collision = true;
			// exit(1);
			}

		if ( collision )
			exit(1);
		}

	GenProlog();

	for ( const auto& func : funcs )
		{
		if ( func.Func()->Flavor() == FUNC_FLAVOR_FUNCTION )
			{
			if ( IsCompilable(func) )
				compilable_funcs.insert(BodyName(func));

			auto h = func.Profile()->HashVal();
			if ( hm.HasHash(h) )
				hashed_funcs[func.Func()->Name()] =
					hm.FuncBodyName(h);
			}
		}

	for ( const auto& t : pfs.RepTypes() )
		{
		TypePtr tp{NewRef{}, (Type*)(t)};
		types.AddKey(tp, pfs.HashType(t));
		ASSERT(pfs.HashType(t) != 0);
		}

	for ( const auto& t : types.DistinctKeys() )
		if ( ! types.IsInherited(t) )
			Emit("TypePtr %s;", types.KeyName(t));

	NL();

	for ( const auto& c : pfs.Constants() )
		AddConstant(c);

	NL();

	auto& gl = pfs.Globals();
	auto& bifs = pfs.BiFGlobals();

	for ( auto& g : pfs.AllGlobals() )
		{
		auto gn = std::string(g->Name());
		bool is_bif = bifs.count(g) > 0;

		if ( gl.count(g) == 0 )
			{
			// Only used in the context of calls.  If it's
			// compilable, the we'll call it directly.
			if ( compilable_funcs.count(gn) > 0 )
				{
				AddGlobal(gn, "zf", true);
				continue;
				}

			if ( is_bif )
				{
				AddBiF(g, false);
				continue;
				}
			}

		if ( AddGlobal(gn, "gl", true) )
			{
			Emit("IDPtr %s;", globals[gn]);

			if ( pfs.Events().count(gn) > 0 )
				// This is an event that's also used as
				// a variable.
				Emit("EventHandlerPtr %s_ev;", globals[gn]);

			const auto& t = g->GetType();
			NoteInitDependency(g, TypeRep(t));

			AddInit(g, globals[gn],
				std::string("lookup_global__CPP(\"") + gn +
				"\", " + GenTypeName(t) + ")");

			if ( g->HasVal() )
				GenGlobalInit(g, globals[gn], g->GetVal());
			}

		if ( is_bif )
			AddBiF(g, true);

		global_vars.emplace(g);
		}

	for ( const auto& e : pfs.Events() )
		if ( AddGlobal(e, "gl", false) )
			Emit("EventHandlerPtr %s_ev;", globals[std::string(e)]);

	for ( const auto& t : pfs.RepTypes() )
		{
		ASSERT(types.HasKey(t));
		TypePtr tp{NewRef{}, (Type*)(t)};
		RegisterType(tp);
		}

	for ( const auto& func : funcs )
		DeclareFunc(func);

	for ( const auto& l : pfs.Lambdas() )
		DeclareLambda(l, pfs.ExprProf(l));

	NL();

	for ( const auto& func : funcs )
		CompileFunc(func);

	for ( const auto& l : pfs.Lambdas() )
		CompileLambda(l, pfs.ExprProf(l));

	for ( const auto& f : compiled_funcs )
		{
		auto h = body_hashes[f];

		std::string events;
		if ( body_events.count(f) > 0 )
			for ( auto e : body_events[f] )
				{
				if ( events.size() > 0 )
					events += ", ";
				events = events + "\"" + e + "\"";
				}

		events = std::string("{") + events + "}";

		if ( addl_tag > 0 )
			h = MergeHashes(h, hash_string(cf_locs[f].c_str()));

		auto init = std::string("register_body__CPP(make_intrusive<") +
				f + "_cl>(\"" + f + "\"), " + Fmt(h) +
				", " + events + ");";

		AddInit(names_to_bodies[f], init);

		if ( update )
			{
			fprintf(hm.HashFile(), "func\n%s%s\n",
				scope_prefix(addl_tag).c_str(), f.c_str());
			fprintf(hm.HashFile(), "%llu\n", h);
			}
		}

	GenFuncVarInits();

	GenEpilog();
	}

void CPPCompile::GenProlog()
	{
	if ( addl_tag == 0 )
		Emit("#include \"zeek/script_opt/CPPRuntime.h\"\n");

	Emit("namespace zeek::detail { //\n");
	Emit("namespace CPP_%s { // %s\n", Fmt(addl_tag), working_dir.c_str());

	// The following might-or-might-not wind up being populated/used.
	Emit("std::vector<int> field_mapping;");
	Emit("std::vector<int> enum_mapping;");
	NL();
	}

void CPPCompile::GenEpilog()
	{
	NL();

	for ( const auto& e : init_exprs.DistinctKeys() )
		{
		GenInitExpr(e);

		if ( update )
			init_exprs.LogIfNew(e, addl_tag, hm.HashFile());
		}

	for ( const auto& a : attributes.DistinctKeys() )
		{
		GenAttrs(a);

		if ( update )
			attributes.LogIfNew(a, addl_tag, hm.HashFile());
		}

	// Generate the guts of compound types.
	for ( const auto& t : types.DistinctKeys() )
		{
		ExpandTypeVar(t);

		if ( update )
			types.LogIfNew(t, addl_tag, hm.HashFile());
		}

	NL();
	Emit("void init__CPP()");

	StartBlock();

	// If any script/BiF functions are used for initializing globals,
	// the code generated from that will expect the presence of a
	// frame pointer, even if nil.
	Emit("Frame* f__CPP = nullptr;");

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

	// Populate mappings for dynamic offsets.
	Emit("int fm_offset;");
	for ( const auto& mapping : field_decls )
		{
		auto rt = mapping.first;
		auto td = mapping.second;
		auto fn = td->id;
		auto rt_name = GenTypeName(rt) + "->AsRecordType()";

		Emit("fm_offset = %s->FieldOffset(\"%s\");", rt_name, fn);
		Emit("if ( fm_offset < 0 )");
		StartBlock();
		Emit("// field does not exist, create it");
		Emit("fm_offset = %s->NumFields();", rt_name);
		Emit("type_decl_list tl;");
		Emit(GenTypeDecl(td));
		Emit("%s->AddFieldsDirectly(tl);", rt_name);
		EndBlock();
		Emit("field_mapping.push_back(fm_offset);");
		}

	Emit("int em_offset;");
	for ( const auto& mapping : enum_names )
		{
		auto et = mapping.first;
		const auto& e_name = mapping.second;
		auto et_name = GenTypeName(et) + "->AsEnumType()";

		Emit("em_offset = %s->Lookup(\"%s\");", et_name, e_name);
		Emit("if ( em_offset < 0 )");
		StartBlock();
		Emit("// enum does not exist, create it");
		Emit("em_offset = %s->Names().size();", et_name);
		Emit("if ( %s->Lookup(em_offset) )", et_name);
		Emit("\treporter->InternalError(\"enum inconsistency while initializing compiled scripts\");");
		Emit("%s->AddNameInternal(\"%s\", em_offset);", et_name, e_name);
		EndBlock();
		Emit("enum_mapping.push_back(em_offset);");
		}

	EndBlock(true);

	NL();
	Emit("int hook_in_init()");
	StartBlock();
	Emit("CPP_init_funcs.push_back(init__CPP);");
        Emit("return 0;");
	EndBlock();
	NL();
	Emit("static int dummy = hook_in_init();\n");

	Emit("} // %s\n", scope_prefix(addl_tag).c_str());

	for ( auto& g : pfs.AllGlobals() )
		{
		auto gn = g->Name();

		if ( update && ! hm.HasGlobal(gn) )
			{
			auto ht = pfs.HashType(g->GetType());

			hash_type hv = 0;
			if ( g->GetVal() )
				hv = hash_obj(g->GetVal());

			fprintf(hm.HashFile(), "global\n%s\n", gn);
			fprintf(hm.HashFile(), "%llu %llu\n", ht, hv);

			auto loc = g->GetLocationInfo();
			fprintf(hm.HashFile(), "%s %d\n",
				loc->filename, loc->first_line);

			if ( g->IsType() )
				{
				const auto& t = g->GetType();
				if ( t->Tag() == TYPE_RECORD )
					fprintf(hm.HashFile(), "record\n%s\n", gn);
				else if ( t->Tag() == TYPE_ENUM )
					fprintf(hm.HashFile(), "enum\n%s\n", gn);
				}
			}
		}

	if ( addl_tag > 0 )
		return;

	Emit("#include \"zeek/script_opt/CPP-gen-addl.h\"\n");
	Emit("} // zeek::detail");
	}

bool CPPCompile::IsCompilable(const FuncInfo& func)
	{
	if ( func.ShouldSkip() )
		return false;

	if ( hm.HasHash(func.Profile()->HashVal()) )
		return false;

	return is_CPP_compilable(func.Profile());
	}

void CPPCompile::AddBiF(const ID* b, bool is_var)
	{
	auto bn = b->Name();
	auto n = std::string(bn);
	if ( is_var )
		n = n + "_";	// make the name distinct

	if ( AddGlobal(n, "bif", true) )
		Emit("Func* %s;", globals[n]);

	AddInit(b, globals[n], std::string("lookup_bif__CPP(\"") + bn + "\")");
	}

bool CPPCompile::AddGlobal(const std::string& g, const char* suffix, bool track)
	{
	bool new_var = false;

	if ( globals.count(g) == 0 )
		{
		auto gn = GlobalName(g, suffix);

		if ( hm.HasGlobalVar(gn) )
			gn = scope_prefix(hm.GlobalVarScope(gn)) + gn;
		else
			{
			new_var = true;

			if ( track && update )
				fprintf(hm.HashFile(), "global-var\n%s\n%d\n",
					gn.c_str(), addl_tag);
			}

		globals.emplace(g, gn);
		}

	return new_var;
	}

void CPPCompile::AddConstant(const ConstExpr* c)
	{
	auto v = c->ValuePtr();

	if ( AddConstant(v) )
		{
		AddInit(c);
		NoteInitDependency(c, v.get());
		}
	}

bool CPPCompile::AddConstant(const ValPtr& vp)
	{
	auto v = vp.get();

	if ( IsNativeType(v->GetType()) )
		// These we instantiate directly.
		return false;

	if ( const_vals.count(v) > 0 )
		// Already did this one.
		return true;

	// Formulate a key that's unique per distinct constant.

	const auto& t = v->GetType();
	std::string c_desc;

	if ( t->Tag() == TYPE_STRING )
		{
		// We can't rely on these to render with consistent
		// escaping, sigh.  Just use the raw string.
		auto s = v->AsString();
		auto b = (const char*)(s->Bytes());
		c_desc = std::string(b, s->Len()) + "string";
		}
	else
		{
		ODesc d;
		v->Describe(&d);

		// Don't confuse constants of different types that happen to
		// render the same.
		t->Describe(&d);

		c_desc = d.Description();
		}

	if ( constants.count(c_desc) > 0 )
		{
		const_vals[v] = constants[c_desc];

		auto orig_v = constants_to_vals[c_desc];
		ASSERT(v != orig_v);
		AddInit(v);
		NoteInitDependency(v, orig_v);

		return true;
		}

	// Need a C++ global for this constant.
	auto const_name = std::string("CPP__const__") +
				Fmt(int(constants.size()));

	const_vals[v] = constants[c_desc] = const_name;
	constants_to_vals[c_desc] = v;

	auto tag = t->Tag();

	switch ( tag ) {
	case TYPE_STRING:
		{
		Emit("StringValPtr %s;", const_name);

		auto s = v->AsString();
		const char* b = (const char*)(s->Bytes());
		auto len = s->Len();

		AddInit(v, const_name, GenString(b, len));
		}
		return true;

	case TYPE_PATTERN:
		{
		Emit("PatternValPtr %s;", const_name);

		auto re = v->AsPatternVal()->Get();

		AddInit(v, std::string("{ auto re = new RE_Matcher(") +
			CPPEscape(re->OrigText()) + ");");
		if ( re->IsCaseInsensitive() )
			AddInit(v, "re->MakeCaseInsensitive();");
		AddInit(v, "re->Compile();");
		AddInit(v, const_name, "make_intrusive<PatternVal>(re)");
		AddInit(v, "}");
		}
		return true;

	case TYPE_ADDR:
	case TYPE_SUBNET:
		{
		auto prefix = (tag == TYPE_ADDR) ? "Addr" : "SubNet";

		Emit("%sValPtr %s;", prefix, const_name);

		ODesc d;
		v->Describe(&d);

		AddInit(v, const_name,
			std::string("make_intrusive<") + prefix +
			"Val>(\"" + d.Description() + "\")");
		}
		return true;

	case TYPE_LIST:
		{
		Emit("ListValPtr %s;", const_name);

		// No initialization dependency since we don't use the
		// underlying TypeList.

		AddInit(v, const_name,
			std::string("make_intrusive<ListVal>(TYPE_ANY)"));

		auto lv = cast_intrusive<ListVal>(vp);
		auto n = lv->Length();

		for ( auto i = 0; i < n; ++i )
			{
			const auto& l_i = lv->Idx(i);
			auto l_i_c = BuildConstant(v, l_i);
			AddInit(v, const_name + "->Append(" + l_i_c + ");");
			}
		}
		return true;

	case TYPE_VECTOR:
		{
		Emit("VectorValPtr %s;", const_name);

		NoteInitDependency(v, TypeRep(t));
		AddInit(v, const_name,
			std::string("make_intrusive<VectorVal>(") +
			"cast_intrusive<VectorType>(" + GenTypeName(t) + "))");

		auto vv = cast_intrusive<VectorVal>(vp);
		auto n = vv->Size();

		for ( auto i = 0; i < n; ++i )
			{
			const auto& v_i = vv->At(i);
			auto v_i_c = BuildConstant(v, v_i);
			AddInit(v, const_name + "->Append(" + v_i_c + ");");
			}
		}
		return true;

	case TYPE_RECORD:
		{
		Emit("RecordValPtr %s;", const_name);

		NoteInitDependency(v, TypeRep(t));
		AddInit(v, const_name,
			std::string("make_intrusive<RecordVal>(") +
			"cast_intrusive<RecordType>(" + GenTypeName(t) + "))");

		auto r = cast_intrusive<RecordVal>(vp);
		auto n = r->NumFields();

		for ( auto i = 0; i < n; ++i )
			{
			const auto& r_i = r->GetField(i);

			if ( r_i )
				{
				auto r_i_c = BuildConstant(v, r_i);
				AddInit(v, const_name + "->Assign(" + Fmt(i) +
					", " + r_i_c + ");");
				}
			}
		}
		return true;

	case TYPE_TABLE:
		{
		Emit("TableValPtr %s;", const_name);

		NoteInitDependency(v, TypeRep(t));
		AddInit(v, const_name,
			std::string("make_intrusive<TableVal>(") +
			"cast_intrusive<TableType>(" + GenTypeName(t) + "))");

		auto tv = cast_intrusive<TableVal>(vp);
		auto tv_map = tv->ToMap();

		for ( auto& tv_i : tv_map )
			{
			auto ind = BuildConstant(v, {AdoptRef{}, tv_i.first});
			auto val = BuildConstant(v, tv_i.second);
			AddInit(v, const_name + "->Assign(" + ind + ", " +
				val + ");");
			}
		}
		return true;

	case TYPE_FUNC:
		Emit("FuncValPtr %s;", const_name);

		// We can't generate the initialization now because it
		// depends on first having compiled the associated body,
		// so we know its hash.  So for now we just note it
		// to deal with later.
		func_vars[v->AsFuncVal()] = const_name;

		return true;

	default:
		reporter->InternalError("bad constant type in CPPCompile::AddConstant");
	}
	}

std::string CPPCompile::BuildConstant(const Obj* parent, const ValPtr& vp)
	{
	if ( ! vp )
		return "nullptr";

	if ( AddConstant(vp) )
		{
		auto v = vp.get();
		AddInit(parent);
		NoteInitDependency(parent, v);

		// Make sure the value pointer, which might be transient
		// in construction, sticks around so we can track its
		// value.
		cv_indices.push_back(vp);

		return const_vals[v];
		}
	else
		return NativeToGT(GenVal(vp), vp->GetType(), GEN_VAL_PTR);
	}

void CPPCompile::DeclareFunc(const FuncInfo& func)
	{
	if ( ! IsCompilable(func) )
		return;

	auto fname = Canonicalize(BodyName(func).c_str()) + "_zf";
	auto pf = func.Profile();
	auto f = func.Func();
	auto body = func.Body();

	DeclareSubclass(f->GetType(), pf, fname, body, nullptr, f->Flavor());
	}

void CPPCompile::DeclareLambda(const LambdaExpr* l, const ProfileFunc* pf)
	{
	ASSERT(is_CPP_compilable(pf));

	auto lname = Canonicalize(l->Name().c_str()) + "_lb";
	auto body = l->Ingredients().body;
	auto l_id = l->Ingredients().id;
	auto& ids = l->OuterIDs();

	for ( auto id : ids )
		lambda_names[id] = LocalName(id);

	DeclareSubclass(l_id->GetType<FuncType>(), pf, lname, body, l,
				FUNC_FLAVOR_FUNCTION);
	}

void CPPCompile::CompileFunc(const FuncInfo& func)
	{
	if ( ! IsCompilable(func) )
		return;

	auto fname = Canonicalize(BodyName(func).c_str()) + "_zf";
	auto pf = func.Profile();
	auto f = func.Func();
	auto body = func.Body();

	DefineBody(f->GetType(), pf, fname, body, nullptr, f->Flavor());
	}

void CPPCompile::CompileLambda(const LambdaExpr* l, const ProfileFunc* pf)
	{
	auto lname = Canonicalize(l->Name().c_str()) + "_lb";
	auto body = l->Ingredients().body;
	auto l_id = l->Ingredients().id;
	auto& ids = l->OuterIDs();

	DefineBody(l_id->GetType<FuncType>(), pf, lname, body, &ids,
			FUNC_FLAVOR_FUNCTION);
	}

void CPPCompile::DeclareSubclass(const FuncTypePtr& ft, const ProfileFunc* pf,
			const std::string& fname, const StmtPtr& body,
			const LambdaExpr* l, FunctionFlavor flavor)
	{
	const auto& yt = ft->Yield();
	in_hook = flavor == FUNC_FLAVOR_HOOK;
	const IDPList* lambda_ids = l ? &l->OuterIDs() : nullptr;

	auto yt_decl = in_hook ? "bool" : FullTypeName(yt);

	NL();
	Emit("static %s %s(%s);", yt_decl, fname, ParamDecl(ft, lambda_ids, pf));

	Emit("class %s_cl : public CPPStmt", fname);
	StartBlock();

	Emit("public:");

	std::string addl_args;
	std::string inits;

	if ( lambda_ids )
		{
		for ( auto& id : *lambda_ids )
			{
			auto name = lambda_names[id];
			auto tn = FullTypeName(id->GetType());
			addl_args = addl_args + ", " + tn + " _" + name;

			inits = inits + ", " + name + "(_" + name + ")";
			}
		}

	Emit("%s_cl(const char* name%s) : CPPStmt(name)%s { }",
		fname, addl_args.c_str(), inits.c_str());

	// An additional constructor just used to generate place-holder
	// instances, due to the mis-design that lambdas are identified
	// by their Func objects rather than their FuncVal objects.
	if ( lambda_ids && lambda_ids->length() > 0 )
		Emit("%s_cl(const char* name) : CPPStmt(name) { }", fname);

	Emit("ValPtr Exec(Frame* f, StmtFlowType& flow) override final");
	StartBlock();

	Emit("flow = FLOW_RETURN;");

	if ( in_hook )
		{
		Emit("if ( ! %s(%s) )", fname, BindArgs(ft, lambda_ids));
		StartBlock();
		Emit("flow = FLOW_BREAK;");
		EndBlock();
		Emit("return nullptr;");
		}

	else if ( IsNativeType(yt) )
		GenInvokeBody(fname, yt, BindArgs(ft, lambda_ids));

	else
		Emit("return %s(%s);", fname, BindArgs(ft, lambda_ids));

	EndBlock();

	if ( lambda_ids )
		{
		for ( auto& id : *lambda_ids )
			{
			auto name = lambda_names[id];
			auto tn = FullTypeName(id->GetType());
			Emit("%s %s;", tn, name.c_str());
			}

		auto literal_name = std::string("\"") + l->Name() + "\"";

		int nl = lambda_ids->length();

		auto instantiate = std::string("make_intrusive<") +
			fname + "_cl>(" + literal_name + ")";
		auto h = Fmt(pf->HashVal());
		auto has_captures = nl > 0 ? "true" : "false";
		auto l_init = std::string("register_lambda__CPP(") +
				instantiate + ", " + h +
				", \"" + l->Name() + "\", "
				+ GenTypeName(ft) + ", " + has_captures + ");";
		AddInit(l, l_init);
		NoteInitDependency(l, TypeRep(ft));

		// Make the lambda's body's initialization depend on the
		// lambda's initialization.  That way GenFuncVarInits()
		// can generate initializations with the assurance that
		// the associated body hashes will have been registered.
		AddInit(body.get());
		NoteInitDependency(body.get(), l);

		Emit("void SetLambdaCaptures(Frame* f) override");
		StartBlock();
		for ( int i = 0; i < nl; ++i )
			{
			auto l_i = (*lambda_ids)[i];
			const auto& t_i = l_i->GetType();
			auto cap_i = std::string("f->GetElement(") +
					Fmt(i) + ")";
			Emit("%s = %s;", lambda_names[l_i],
				GenericValPtrToGT(cap_i, t_i, GEN_NATIVE));
			}
		EndBlock();

		Emit("std::vector<ValPtr> SerializeLambdaCaptures() const override");
		StartBlock();
		Emit("std::vector<ValPtr> vals;");
		for ( int i = 0; i < nl; ++i )
			{
			auto l_i = (*lambda_ids)[i];
			const auto& t_i = l_i->GetType();
			Emit("vals.emplace_back(%s);",
				NativeToGT(lambda_names[l_i], t_i, GEN_VAL_PTR));
			}
		Emit("return vals;");
		EndBlock();

		Emit("CPPStmtPtr Clone() override");
		StartBlock();
		auto arg_clones = GenLambdaClone(l, true);
		Emit("return make_intrusive<%s_cl>(name.c_str()%s);", fname, arg_clones);
		EndBlock();
		}

	else
		{
		// We don't track lambda bodies as compiled because they
		// can't be instantiated directly without also supplying
		// the captures.  In principle we could make an exception
		// for lambdas that don't take any arguments, but that
		// seems potentially more confusing than beneficial.
		compiled_funcs.emplace(fname);

		auto loc_f = script_specific_filename(body);
		cf_locs[fname] = loc_f;

		Emit("// compiled body for: %s", loc_f);
		}

	EndBlock(true);

	body_hashes[fname] = pf->HashVal();
	body_names.emplace(body.get(), fname);
	names_to_bodies.emplace(std::move(fname), body.get());
	}

void CPPCompile::GenSubclassTypeAssignment(Func* f)
	{
	Emit("type = cast_intrusive<FuncType>(%s);", GenTypeName(f->GetType()));
	}

void CPPCompile::GenInvokeBody(const std::string& fname, const TypePtr& t,
				const std::string& args)
	{
	auto call = fname + "(" + args + ")";

	if ( ! t || t->Tag() == TYPE_VOID )
		{
		Emit("%s;", call);
		Emit("return nullptr;");
		}
	else
		Emit("return %s;", NativeToGT(call, t, GEN_VAL_PTR));
	}

void CPPCompile::DefineBody(const FuncTypePtr& ft, const ProfileFunc* pf,
			const std::string& fname, const StmtPtr& body,
			const IDPList* lambda_ids, FunctionFlavor flavor)
	{
	locals.clear();
	params.clear();

	body_name = fname;

	ret_type = ft->Yield();
	in_hook = flavor == FUNC_FLAVOR_HOOK;
	auto ret_type_str = in_hook ? "bool" : FullTypeName(ret_type);

	for ( const auto& p : pf->Params() )
		params.emplace(p);

	NL();

	Emit("%s %s(%s)", ret_type_str, fname, ParamDecl(ft, lambda_ids, pf));

	StartBlock();

	// Declare any parameters that originate from a type signature of
	// "any" but were concretized in this declaration.
	const auto& formals = ft->Params();
	int n = formals->NumFields();

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = formals->GetFieldType(i);
		if ( t->Tag() != TYPE_ANY )
			continue;

		auto param_id = FindParam(i, pf);
		if ( ! param_id )
			continue;

		const auto& pt = param_id->GetType();
		if ( pt->Tag() == TYPE_ANY )
			continue;

		auto any_i = std::string("any_param__CPP_") + Fmt(i);

		Emit("%s %s = %s;", FullTypeName(pt), LocalName(param_id),
			GenericValPtrToGT(any_i, pt, GEN_NATIVE));
		}

	// Make sure that any events referred to in this function have
	// been initialized.  We have to do this dynamically because it
	// depends on whether the final script using the compiled code
	// happens to load the associated event handler
	for ( const auto& e : pf->Events() )
		{
		auto ev_name = globals[e] + "_ev";

		// Create a scope so we don't have to individualize the
		// variables.
		Emit("{");
		Emit("static bool did_init = false;");
		Emit("if ( ! did_init )");
		StartBlock();

		// We do both a Lookup and a Register because only the latter
		// returns an EventHandlerPtr, sigh.
		Emit("if ( event_registry->Lookup(\"%s\") )", e);
		StartBlock();
		Emit("%s = event_registry->Register(\"%s\");", ev_name.c_str(), e);
		EndBlock();
		Emit("did_init = true;");
		EndBlock();
		Emit("}");
		}

	DeclareLocals(pf, lambda_ids);
	GenStmt(body);

	if ( in_hook )
		{
		Emit("return true;");
		in_hook = false;
		}

	// Seatbelts for running off the end of a function that's supposed
	// to return a non-native type.
	if ( ! IsNativeType(ret_type) )
		Emit("return nullptr;");

	EndBlock();
	}

void CPPCompile::DeclareLocals(const ProfileFunc* pf, const IDPList* lambda_ids)
	{
	std::unordered_set<const ID*> lambda_set;

	if ( lambda_ids )
		for ( auto li : *lambda_ids )
			lambda_set.insert(li);

	const auto& ls = pf->Locals();

	bool did_decl = false;

	for ( const auto& l : ls )
		{
		auto ln = LocalName(l);

		if ( lambda_set.count(l) > 0 )
			ln = lambda_names[l];

		else if ( params.count(l) == 0 )
			{
			Emit("%s %s;", FullTypeName(l->GetType()), ln);
			did_decl = true;
			}

		locals.emplace(l, ln);
		}

	if ( did_decl )
		NL();
	}

std::string CPPCompile::BodyName(const FuncInfo& func)
	{
	const auto& f = func.Func();
	const auto& bodies = f->GetBodies();

	std::string fname = f->Name();

	if ( bodies.size() > 1 )
		{
		const auto& body = func.Body();

		int i;
		for ( i = 0; i < bodies.size(); ++i )
			if ( bodies[i].stmts == body )
				break;

		if ( i >= bodies.size() )
			reporter->InternalError("can't find body in CPPCompile::BodyName");

		fname = fname + "__" + Fmt(i);
		}

	return fname;
	}

std::string CPPCompile::BindArgs(const FuncTypePtr& ft,
					const IDPList* lambda_ids)
	{
	const auto& params = ft->Params();

	std::string res;

	int n = params->Types()->size();
	for ( auto i = 0; i < n; ++i )
		{
		auto arg_i = std::string("f->GetElement(") + Fmt(i) + ")";
		const auto& ft = params->GetFieldType(i);

		if ( IsNativeType(ft) )
			res += arg_i + NativeAccessor(ft);
		else
			res += GenericValPtrToGT(arg_i, ft, GEN_VAL_PTR);

		res += ", ";
		}

	if ( lambda_ids )
		{
		for ( auto& id : *lambda_ids )
			res += lambda_names[id] + ", ";
		}

	return res + "f";
	}

void CPPCompile::BuildAttrs(const AttributesPtr& attrs,
				std::string& attr_tags, std::string& attr_vals)
	{
	if ( attrs )
		{
		for ( const auto& a : attrs->GetAttrs() )
			{
			if ( attr_tags.size() > 0 )
				{
				attr_tags += ", ";
				attr_vals += ", ";
				}

			attr_tags += Fmt(int(a->Tag()));

			const auto& e = a->GetExpr();

			if ( e )
				attr_vals += GenExpr(e, GEN_VAL_PTR, false);
			else
				attr_vals += "nullptr";
			}
		}

	attr_tags = std::string("{") + attr_tags + "}";
	attr_vals = std::string("{") + attr_vals + "}";
	}

std::string CPPCompile::GenArgs(const RecordTypePtr& params, const Expr* e)
	{
	ASSERT(e->Tag() == EXPR_LIST);

	const auto& exprs = e->AsListExpr()->Exprs();
	std::string gen;

	int n = exprs.size();

	for ( auto i = 0; i < n; ++i )
		{
		auto e_i = exprs[i];
		auto gt = GEN_NATIVE;

		const auto& param_t = params->GetFieldType(i);
		bool param_any = param_t->Tag() == TYPE_ANY;
		bool arg_any = e_i->GetType()->Tag() == TYPE_ANY;

		if ( param_any && ! arg_any )
			gt = GEN_VAL_PTR;

		auto expr_gen = GenExpr(e_i, gt);

		if ( ! param_any && arg_any )
			expr_gen = GenericValPtrToGT(expr_gen, param_t,
							GEN_NATIVE);

		gen = gen + expr_gen;
		if ( i < n - 1 )
			gen += ", ";
		}

	return gen;
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
	auto ename = InitExprName(e);

	// First, create a CPPFunc that we can compile to compute e.
	auto name = std::string("wrapper_") + ename;

	Emit("static %s %s(Frame* f__CPP);", FullTypeName(t), name);

	Emit("class %s_cl : public CPPFunc", name);
	StartBlock();

	Emit("public:");
	Emit("%s_cl() : CPPFunc(\"%s\", %s)", name, name, e->IsPure() ? "true" : "false");

	StartBlock();
	Emit("type = make_intrusive<FuncType>(make_intrusive<RecordType>(new type_decl_list()), %s, FUNC_FLAVOR_FUNCTION);", GenTypeName(t));

	NoteInitDependency(e, TypeRep(t));
	EndBlock();

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override final");
	StartBlock();

	if ( IsNativeType(t) )
		GenInvokeBody(name, t, "parent");
	else
		Emit("return %s(parent);", name);

	EndBlock();
	EndBlock(true);

	Emit("static %s %s(Frame* f__CPP)", FullTypeName(t), name);
	StartBlock();

	Emit("return %s;", GenExpr(e, GEN_NATIVE));
	EndBlock();

	Emit("CallExprPtr %s;", ename);

	NoteInitDependency(e, TypeRep(t));
	AddInit(e, ename, std::string("make_intrusive<CallExpr>(make_intrusive<ConstExpr>(make_intrusive<FuncVal>(make_intrusive<") +
		name + "_cl>())), make_intrusive<ListExpr>(), false)");
	}

bool CPPCompile::IsSimpleInitExpr(const ExprPtr& e) const
	{
	switch ( e->Tag() ) {
	case EXPR_CONST:
	case EXPR_NAME:
		return true;

	case EXPR_RECORD_COERCE:
		{ // look for coercion of empty record
		auto op = e->GetOp1();

		if ( op->Tag() != EXPR_RECORD_CONSTRUCTOR )
			return false;

		auto rc = static_cast<const RecordConstructorExpr*>(op.get());
		const auto& exprs = rc->Op()->AsListExpr()->Exprs();

		return exprs.length() == 0;
		}

	default:
		return false;
	}
	}

std::string CPPCompile::InitExprName(const ExprPtr& e)
	{
	return init_exprs.KeyName(e);
	}

void CPPCompile::GenGlobalInit(const ID* g, std::string& gl, const ValPtr& v)
	{
	if ( v->GetType()->Tag() == TYPE_FUNC )
		return;

	AddInit(g, std::string("if ( ! ") + gl + "->HasVal() )");
	AddInit(g, std::string("\t") + gl + "->SetVal(" + BuildConstant(g, v) + ");");
	}

void CPPCompile::GenFuncVarInits()
	{
	for ( const auto& fv_init : func_vars )
		{
		auto& fv = fv_init.first;
		auto f = fv->AsFunc();
		auto& const_name = fv_init.second;

		const auto& bodies = f->GetBodies();
		ASSERT(bodies.size() == 1);

		const auto body = bodies[0].stmts.get();
		ASSERT(body_names.count(body) > 0);

		auto& body_name = body_names[body];
		ASSERT(body_hashes.count(body_name) > 0);

		NoteInitDependency(fv, body);

		const auto& h = body_hashes[body_name];
		const auto& fn = f->Name();

		const auto& ft = f->GetType();
		auto ftr = TypeRep(ft);
		NoteInitDependency(fv, ftr);

		auto init = std::string("lookup_func__CPP(\"") + fn + "\", " +
				Fmt(h) + ", " + GenTypeName(ft) + ")";

		ValPtr fvp{NewRef{}, fv};
		AddInit(fvp, const_name, init);
		}
	}

void CPPCompile::GenAttrs(const AttributesPtr& attrs)
	{
	NL();

	Emit("AttributesPtr %s", AttrsName(attrs));

	StartBlock();

	const auto& avec = attrs->GetAttrs();
	Emit("auto attrs = std::vector<AttrPtr>();");

	AddInit(attrs);

	for ( auto i = 0; i < avec.size(); ++i )
		{
		const auto& attr = avec[i];
		const auto& e = attr->GetExpr();

		if ( ! e )
			{
			Emit("attrs.emplace_back(make_intrusive<Attr>(%s));",
				AttrName(attr));
			continue;
			}

		NoteInitDependency(attrs, e);
		AddInit(e);

		std::string e_arg;
		if ( IsSimpleInitExpr(e) )
			{
			switch ( e->Tag() ) {
			case EXPR_CONST:
				e_arg = std::string("make_intrusive<ConstExpr>(") +
					GenExpr(e, GEN_VAL_PTR) + ")";
				break;

			case EXPR_NAME:
				NoteInitDependency(e, e->AsNameExpr()->IdPtr());
				e_arg = std::string("make_intrusive<NameExpr>(") +
					globals[e->AsNameExpr()->Id()->Name()] +
					")";
				break;

			case EXPR_RECORD_COERCE:
				NoteInitDependency(e, TypeRep(e->GetType()));
				e_arg = std::string("make_intrusive<RecordCoerceExpr>(make_intrusive<RecordConstructorExpr>(make_intrusive<ListExpr>()), cast_intrusive<RecordType>(") +
					GenTypeName(e->GetType()) + "))";
				break;

			default:
				reporter->InternalError("bad expr tag in CPPCompile::GenAttrs");
			}
			}

		else
			e_arg = InitExprName(e);

		Emit("attrs.emplace_back(make_intrusive<Attr>(%s, %s));",
			AttrName(attr), e_arg);
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
			AddInit(t, GenTypeDecl(td));
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

std::string CPPCompile::GenTypeDecl(const TypeDecl* td)
	{
	auto type_accessor = GenTypeName(td->type);

	auto td_name = std::string("util::copy_string(\"") +
			td->id + "\")";

	if ( td->attrs )
		return std::string("tl.append(new TypeDecl(") +
			td_name + ", " + type_accessor +
			", " + AttrsName(td->attrs) +"));";

	return std::string("tl.append(new TypeDecl(") + td_name + ", "
				+ type_accessor +"));";
	}

std::string CPPCompile::GenTypeName(const Type* t)
	{
	return types.KeyName(TypeRep(t));
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

std::string CPPCompile::ParamDecl(const FuncTypePtr& ft,
			const IDPList* lambda_ids, const ProfileFunc* pf)
	{
	const auto& params = ft->Params();
	int n = params->NumFields();

	std::string decl;

	for ( auto i = 0; i < n; ++i )
		{
		const auto& t = params->GetFieldType(i);
		auto tn = FullTypeName(t);
		auto param_id = FindParam(i, pf);
		std::string fn;

		if ( param_id )
			{
			if ( t->Tag() == TYPE_ANY &&
			     param_id->GetType()->Tag() != TYPE_ANY )
				fn = std::string("any_param__CPP_") + Fmt(i);
			else
				fn = LocalName(param_id);
			}
		else
			fn = std::string("unused_param__CPP_") + Fmt(i);

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

	if ( lambda_ids )
		{
		for ( auto& id : *lambda_ids )
			{
			auto name = lambda_names[id];
			const auto& t = id->GetType();
			auto tn = FullTypeName(t);

			decl = decl + tn + "& " + name + ", ";
			}
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
	if ( ! t )
		return true;

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

	case TYPE_LIST:
		// These occur for initializing tables.
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
	if ( ! t )
		return "void";

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

void CPPCompile::RegisterType(const TypePtr& tp)
	{
	auto t = TypeRep(tp);

	if ( processed_types.count(t) > 0 )
		return;

	// Add the type before going further, to avoid loops due to types
	// that reference each other.
	processed_types.insert(t);

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
		RegisterType(tt);
		}
		break;

	case TYPE_VECTOR:
		{
		const auto& yield = t->AsVectorType()->Yield();
		NoteNonRecordInitDependency(t, yield);
		RegisterType(yield);
		}
		break;

	case TYPE_LIST:
		{
		auto tl = t->AsTypeList()->GetTypes();
		for ( auto i = 0; i < tl.size(); ++i )
			{
			NoteNonRecordInitDependency(t, tl[i]);
			RegisterType(tl[i]);
			}
		}
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();
		const auto& indices = tbl->GetIndices();
		const auto& yield = tbl->Yield();

		NoteNonRecordInitDependency(t, indices);
		RegisterType(indices);

		if ( yield )
			{
			NoteNonRecordInitDependency(t, yield);
			RegisterType(yield);
			}
		}
		break;

	case TYPE_RECORD:
		{
		auto r = t->AsRecordType()->Types();

		for ( auto i = 0; i < r->length(); ++i )
			{
			const auto& r_i = (*r)[i];

			NoteNonRecordInitDependency(t, r_i->type);
			RegisterType(r_i->type);

			if ( r_i->attrs )
				{
				NoteInitDependency(t, r_i->attrs);
				RegisterAttributes(r_i->attrs);
				}
			}
		}
		break;

	case TYPE_FUNC:
		{
		auto f = t->AsFuncType();

		NoteInitDependency(t, TypeRep(f->Params()));
		RegisterType(f->Params());

		if ( f->Yield() )
			{
			NoteNonRecordInitDependency(t, f->Yield());
			RegisterType(f->Yield());
			}
		}
		break;

	default:
		reporter->InternalError("bad type in CPPCompile::RegisterType");
	}

	AddInit(t);

	if ( ! types.IsInherited(t) )
		{
		auto t_rep = types.GetRep(t);
		if ( t_rep == t )
			GenPreInit(t);
		else
			NoteInitDependency(t, t_rep);
		}
	}

void CPPCompile::GenPreInit(const Type* t)
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

void CPPCompile::RegisterAttributes(const AttributesPtr& attrs)
	{
	if ( ! attrs || attributes.HasKey(attrs) )
		return;

	attributes.AddKey(attrs);
	AddInit(attrs);

	auto a_rep = attributes.GetRep(attrs);
	if ( a_rep != attrs.get() )
		{
		NoteInitDependency(attrs.get(), a_rep);
		return;
		}

	for ( const auto& a : attrs->GetAttrs() )
		{
		const auto& e = a->GetExpr();
		if ( e )
			{
			if ( IsSimpleInitExpr(e) )
				// Make sure any dependencies it has get noted.
				(void) GenExpr(e, GEN_VAL_PTR);
			else
				{
				init_exprs.AddKey(e);
				AddInit(e);
				NoteInitDependency(attrs, e);
				auto e_rep = init_exprs.GetRep(e);
				if ( e_rep != e.get() )
					NoteInitDependency(e.get(), e_rep);
				}
			}
		}
	}

void CPPCompile::RegisterEvent(std::string ev_name)
	{
	body_events[body_name].emplace_back(std::move(ev_name));
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

		// Strip <>'s - these get introduced for lambdas.
		if ( c == '<' || c == '>' )
			continue;

		if ( c == ':' )
			c = '_';

		cname = cname + c;
		}

	// Add a trailing '_' to avoid conflicts with C++ keywords.
	return cname + "_";
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

std::string CPPCompile::GenString(const char* b, int len) const
	{
	return std::string("make_intrusive<StringVal>(") + Fmt(len) +
			", " + CPPEscape(b, len) + ")";
	}

std::string CPPCompile::CPPEscape(const char* b, int len) const
	{
	std::string res = "\"";

	for ( int i = 0; i < len; ++i )
		{
		unsigned char c = b[i];

		switch ( c ) {
		case '\a':	res += "\\a"; break;
		case '\b':	res += "\\b"; break;
		case '\f':	res += "\\f"; break;
		case '\n':	res += "\\n"; break;
		case '\r':	res += "\\r"; break;
		case '\t':	res += "\\t"; break;
		case '\v':	res += "\\v"; break;

		case '\\':	res += "\\\\"; break;
		case '"':	res += "\\\""; break;

		default:
			if ( isprint(c) )
				res += c;
			else
				{
				char buf[8192];
				snprintf(buf, sizeof buf, "%03o", c);
				res += "\\";
				res += buf;
				}
			break;
		}
		}

	return res + "\"";
	}

void CPPCompile::Indent() const
	{
	for ( auto i = 0; i < block_level; ++i )
		fprintf(write_file, "%s", "\t");
	}

} // zeek::detail
