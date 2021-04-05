// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

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
