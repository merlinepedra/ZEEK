// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>

#include "zeek/RE.h"
#include "zeek/script_opt/CPPCompile.h"
#include "zeek/script_opt/ProfileFunc.h"


namespace zeek::detail {

// Helper functions.
std::string Fmt(int i)		{ return std::to_string(i); }
std::string Fmt(hash_type u)	{ return std::to_string(u) + "ULL"; }
std::string Fmt(double d)	{ return std::to_string(d); }

std::string ScopePrefix(const std::string& scope)
	{
	return std::string("zeek::detail::CPP_") + scope + "::";
	}

std::string ScopePrefix(int scope)
	{
	return ScopePrefix(std::to_string(scope));
	}


template<class T1, class T2>
void CPPTracker<T1, T2>::AddKey(T2 key, hash_type h)
	{
	if ( HasKey(key) )
		return;

	if ( h == 0 )
		h = Hash(key);

	if ( map2.count(h) == 0 )
		{
		int index;
		if ( mapper && mapper->count(h) > 0 )
			{
			const auto& pair = (*mapper)[h];
			index = pair.index;
			scope2[h] = Fmt(pair.scope);
			inherited.insert(h);
			}
		else
			{
			index = num_non_inherited++;
			keys2.push_back(key);
			}

		map2[h] = index;
		reps[h] = key.get();
		}

	ASSERT(h != 0);

	map[key.get()] = h;
	keys.push_back(key);
	}

template<class T1, class T2>
std::string CPPTracker<T1, T2>::KeyName(T1 key)
	{
	ASSERT(HasKey(key));

	auto hash = map[key];
	ASSERT(hash != 0);

	auto index = map2[hash];

	std::string scope;
	if ( IsInherited(hash) )
		scope = ScopePrefix(scope2[hash]);

	return scope + std::string(base_name) + "_" + Fmt(index) + "__CPP";
	}

template<class T1, class T2>
void CPPTracker<T1, T2>::LogIfNew(T2 key, int scope, FILE* log_file)
	{
	if ( IsInherited(key) )
		return;

	auto hash = map[key.get()];
	auto index = map2[hash];
	fprintf(log_file, "hash\n%llu %d %d\n", hash, index, scope);
	}

template<class T1, class T2>
hash_type CPPTracker<T1, T2>::Hash(T2 key) const
	{
	ODesc d;
	key->Describe(&d);
	std::string desc = d.Description();
	auto h = std::hash<std::string>{}(base_name + desc);
	return hash_type(h);
	}


CPPHashManager::CPPHashManager(const char* hash_name_base, bool _append)
	{
	append = _append;

	hash_name = std::string(hash_name_base) + ".dat";

	if ( append )
		{
		hf_r = fopen(hash_name.c_str(), "r");
		if ( ! hf_r )
			{
			reporter->Error("can't open auxiliary C++ hash file %s for reading",
				hash_name.c_str());
			exit(1);
			}

		lock_file(hash_name, hf_r);
		LoadHashes(hf_r);
		}

	auto mode = append ? "a" : "w";

	hf_w = fopen(hash_name.c_str(), mode);
	if ( ! hf_w )
		{
		reporter->Error("can't open auxiliary C++ hash file %s for writing",
				hash_name.c_str());
		exit(1);
		}
	}

CPPHashManager::~CPPHashManager()
	{
	fclose(hf_w);

	if ( hf_r )
		{
		unlock_file(hash_name, hf_r);
		fclose(hf_r);
		}
	}

void CPPHashManager::LoadHashes(FILE* f)
	{
	std::string key;

	while ( GetLine(f, key) )
		{
		std::string line;

		RequireLine(f, line);

		hash_type hash;

		if ( key == "func" )
			{
			auto func = line;

			RequireLine(f, line);

			if ( sscanf(line.c_str(), "%llu", &hash) != 1 || hash == 0 )
				BadLine(line);

			previously_compiled[hash] = func;
			}

		else if ( key == "global" )
			{
			auto gl = line;

			RequireLine(f, line);

			hash_type gl_t_h, gl_v_h;
			if ( sscanf(line.c_str(), "%llu %llu",
					&gl_t_h, &gl_v_h) != 2 )
				BadLine(line);

			gl_type_hashes[gl] = gl_t_h;
			gl_val_hashes[gl] = gl_v_h;

			// Eat the location info
			(void) RequireLine(f, line);
			}

		else if ( key == "global-var" )
			{
			auto gl = line;

			RequireLine(f, line);

			int scope;
			if ( sscanf(line.c_str(), "%d", &scope) != 1 )
				BadLine(line);

			gv_scopes[gl] = scope;
			}

		else if ( key == "hash" )
			{
			int index;
			int scope;

			if ( sscanf(line.c_str(), "%llu %d %d", &hash, &index,
				    &scope) != 3 || hash == 0 )
				BadLine(line);

			compiled_items[hash] = CompiledItemPair{index, scope};
			}

		else if ( key == "bif" )
			base_bifs.insert(line);

		else
			BadLine(line);
		}
	}

void CPPHashManager::RequireLine(FILE* f, std::string& line)
	{
	if ( ! GetLine(f, line) )
		{
		reporter->Error("missing final %s hash file entry", hash_name.c_str());
		exit(1);
		}
	}

bool CPPHashManager::GetLine(FILE* f, std::string& line)
	{
	char buf[8192];
	if ( ! fgets(buf, sizeof buf, f) )
		return false;

	int n = strlen(buf);
	if ( n > 0 && buf[n-1] == '\n' )
		buf[n-1] = '\0';

	line = buf;
	return true;
	}

void CPPHashManager::BadLine(std::string& line)
	{
	reporter->Error("bad %s hash file entry: %s",
			hash_name.c_str(), line.c_str());
	exit(1);
	}


CPPCompile::CPPCompile(std::vector<FuncInfo>& _funcs, ProfileFuncs& _pfs,
		const char* gen_name, CPPHashManager& _hm)
: funcs(_funcs), pfs(_pfs), hm(_hm)
	{
	auto mode = hm.Append() ? "a" : "w";

	write_file = fopen(gen_name, mode);
	if ( ! write_file )
		{
		reporter->Error("can't open C++ target file %s", gen_name);
		exit(1);
		}

	if ( hm.Append() )
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

	if ( addl_tag > 0 )
		{
		auto& bifs = pfs.BiFGlobals();

		for ( auto& g : pfs.AllGlobals() )
			{
			auto gn = std::string(g->Name());

			if ( bifs.count(g) && ! hm.HasBiF(gn) )
				{
				fprintf(stderr, "%s: code relies on non-base BiF %s\n",
					working_dir.c_str(), gn.c_str());
				exit(1);
				}

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
				AddGlobal(g->Name(), "zf");
				continue;
				}

			if ( is_bif )
				{
				AddBiF(g, false);
				continue;
				}
			}

		const auto& t = g->GetType();

		NoteInitDependency(g, TypeRep(t));

		if ( AddGlobal(g->Name(), "gl") )
			Emit("IDPtr %s;", globals[gn]);

		global_vars.emplace(g);

		AddInit(g, globals[gn],
			std::string("lookup_global__CPP(\"") + gn +
			"\", " + GenTypeName(t) + ")");

		if ( is_bif )
			AddBiF(g, true);
		}

	for ( const auto& c : pfs.Constants() )
		AddConstant(c);

	for ( const auto& t : pfs.RepTypes() )
		{
		ASSERT(types.HasKey(t));
		TypePtr tp{NewRef{}, (Type*)(t)};
		RegisterType(tp);
		}

	for ( const auto& e : pfs.Events() )
		{
		if ( AddGlobal(e, "gl") )
			{
			auto ev = globals[std::string(e)] + "_ev";
			Emit("EventHandlerPtr %s;", ev);
			}
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

	GenEpilog();
	}

void CPPCompile::GenProlog()
	{
	if ( addl_tag == 0 )
		Emit("#include \"zeek/script_opt/CPPProlog.h\"\n");

	Emit("namespace CPP_%s { // %s\n", Fmt(addl_tag), working_dir.c_str());
	}

void CPPCompile::GenEpilog()
	{
	NL();

	for ( const auto& e : init_exprs.DistinctKeys() )
		{
		GenInitExpr(e);
		init_exprs.LogIfNew(e, addl_tag, hm.HashFile());
		}

	for ( const auto& a : attributes.DistinctKeys() )
		{
		GenAttrs(a);
		attributes.LogIfNew(a, addl_tag, hm.HashFile());
		}

	// Generate the guts of compound types.
	for ( const auto& t : types.DistinctKeys() )
		{
		ExpandTypeVar(t);
		types.LogIfNew(t, addl_tag, hm.HashFile());
		}

	NL();
	Emit("void init__CPP()");

	StartBlock();

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

	// ... and then instantiate the bodies themselves.
	NL();
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

		Emit("register_body__CPP(make_intrusive<%s_cl>(\"%s\"), %s, %s);",
			f, f, Fmt(h), events);

		fprintf(hm.HashFile(), "func\n%s%s\n",
			ScopePrefix(addl_tag).c_str(), f.c_str());
		fprintf(hm.HashFile(), "%llu\n", h);
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

	Emit("} // %s\n", ScopePrefix(addl_tag).c_str());

	for ( auto& g : pfs.AllGlobals() )
		if ( ! hm.HasGlobal(g->Name()) )
			{
			auto ht = pfs.HashType(g->GetType());

			hash_type hv = 0;
			if ( g->GetVal() )
				{
				hv = hash_obj(g->GetVal());
				}

			fprintf(hm.HashFile(), "global\n%s\n", g->Name());
			fprintf(hm.HashFile(), "%llu %llu\n", ht, hv);

			auto loc = g->GetLocationInfo();
			fprintf(hm.HashFile(), "%s %d\n",
				loc->filename, loc->first_line);
			}

	if ( addl_tag > 0 )
		return;

	Emit("#include \"zeek/script_opt/CPP-gen-addl.h\"\n");
	Emit("} // zeek::detail");
	Emit("} // zeek");

	// For BiFs, what matters is the ones available, even if the
	// loaded scripts didn't happen to make reference to them.
	// Thus, we search the entire set of globals for them, rather
	// than relying on pfs.BiFGlobals().
	const auto& globals = global_scope()->Vars();
	for ( const auto& g : globals )
		{
		const auto& gv = g.second->GetVal();
		if ( ! gv || gv->GetType()->Tag() != TYPE_FUNC )
			continue;

		auto f = gv->AsFunc();
		if ( f->GetKind() == BuiltinFunc::BUILTIN_FUNC )
			fprintf(hm.HashFile(), "bif\n%s\n", f->Name());
		}
	}

bool CPPCompile::IsCompilable(const FuncInfo& func)
	{
	if ( func.Skip() )
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

	if ( AddGlobal(n, "bif") )
		Emit("Func* %s;", globals[n]);

	AddInit(b, globals[n], std::string("lookup_bif__CPP(\"") + bn + "\")");
	}

bool CPPCompile::AddGlobal(const std::string& g, const char* suffix)
	{
	bool new_var = false;

	if ( globals.count(g) == 0 )
		{
		auto gn = GlobalName(g, suffix);

		if ( hm.HasGlobalVar(gn) )
			gn = ScopePrefix(hm.GlobalVarScope(gn)) + gn;
		else
			{
			new_var = true;
			fprintf(hm.HashFile(), "global-var\n%s\n%d\n",
				gn.c_str(), addl_tag);
			}

		globals.emplace(g, gn);
		}

	return new_var;
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
	v->Describe(&d);
	std::string val_desc(d.Description());

	// Don't confuse constants of different types that happen to
	// render the same.
	v->GetType()->Describe(&d);

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
			auto def = std::string("make_intrusive<StringVal>(\"") +
					CPPEscape(val_desc) + "\")";
			AddInit(c, const_name, def);
			}
			break;

		case TYPE_PATTERN:
			{
			Emit("PatternValPtr %s;", const_name);

			auto re = v->AsPatternVal()->Get();

			AddInit(c,
				std::string("{ auto re = new RE_Matcher(\"") +
				CPPEscape(re->OrigText()) + "\");");
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
		{
		auto l_id_name = LocalName(id) + "_" + lname;
		lambda_names[id] = l_id_name;
		}

	DeclareSubclass(l_id->GetType<FuncType>(), pf, lname, body, &ids,
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
			const IDPList* lambda_ids, FunctionFlavor flavor)
	{
	const auto& yt = ft->Yield();
	in_hook = flavor == FUNC_FLAVOR_HOOK;

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

	Emit("ValPtr Exec(Frame* f, StmtFlowType& flow) const override final");
	StartBlock();

	Emit("flow = FLOW_RETURN;");

	if ( IsNativeType(yt) )
		{
		auto args = BindArgs(ft, lambda_ids);
		GenInvokeBody(fname, yt, args);
		}

	else
		{
		if ( in_hook )
			{
			Emit("if ( ! %s(%s) )", fname, BindArgs(ft, lambda_ids));
			StartBlock();
			Emit("flow = FLOW_BREAK;");
			EndBlock();
			}

		Emit("return %s(%s);", fname, BindArgs(ft, lambda_ids));
		}

	EndBlock();

	if ( lambda_ids )
		{
		for ( auto& id : *lambda_ids )
			{
			auto name = lambda_names[id];
			auto tn = FullTypeName(id->GetType());
			Emit("%s %s;", tn, name.c_str());
			}
		}

	else
		// We don't track lambda bodies as compiled because they
		// can't be instantiated directly without also supplying
		// the captures.  In principle we could make an exception
		// for lambdas that don't take any arguments, but that
		// seems potentially more confusing than beneficial.
		compiled_funcs.emplace(fname);

	EndBlock(true);

	body_hashes[fname] = pf->HashVal();
	body_names.emplace(body.get(), std::move(fname));
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

			if ( locals.count(aggr.get()) == 0 )
				{
				// fprintf(stderr, "aggregate %s unused\n", obj_desc(aggr.get()).c_str());
				continue;
				}

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
		++break_level;
		GenStmt(w->Body());
		--break_level;
		EndBlock();
		}
		break;

	case STMT_NULL:
		Emit(";");
		break;

	case STMT_RETURN:
		{
		auto e = s->AsReturnStmt()->StmtExpr();

		if ( ! ret_type || ! e || e->GetType()->Tag() == TYPE_VOID )
			{
			if ( in_hook )
				Emit("return true;");
			else
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

		++break_level;

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

		--break_level;

		Emit("} // end of for scope");
		}
		break;

	case STMT_NEXT:
		Emit("continue;");
		break;

	case STMT_BREAK:
		if ( break_level > 0 )
			Emit("break;");
		else
			Emit("return false;");
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

		auto ev_n = ev_e->Name();
		RegisterEvent(ev_n);

		if ( ev_e->Args()->Exprs().length() > 0 )
			Emit("event_mgr.Enqueue(%s_ev, %s);",
				globals[std::string(ev_n)],
				GenExpr(ev_e->Args(), GEN_VAL_PTR));
		else
			Emit("event_mgr.Enqueue(%s_ev, Args{});",
				globals[std::string(ev_n)]);
		}
		break;

	case STMT_SWITCH:
		GenSwitchStmt(static_cast<const SwitchStmt*>(s));
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

void CPPCompile::GenSwitchStmt(const SwitchStmt* sw)
	{
	auto e = sw->StmtExpr();
	auto cases = sw->Cases();

	auto e_it = e->GetType()->InternalType();
	bool is_int = e_it == TYPE_INTERNAL_INT;
	bool is_uint = e_it == TYPE_INTERNAL_UNSIGNED;
	bool organic = is_int || is_uint;

	std::string sw_val;

	if ( organic )
		sw_val = GenExpr(e, GEN_NATIVE);
	else
		sw_val = std::string("hash_obj(") + GenExpr(e, GEN_VAL_PTR) + ")";

	Emit("switch ( %s ) {", sw_val.c_str());

	++break_level;

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

				std::string c_v_rep;

				if ( is_int )
					c_v_rep = Fmt(int(c_v->AsInt()));
				else if ( is_uint )
					c_v_rep = Fmt(c_v->AsCount());
				else
					c_v_rep = Fmt(hash_obj(c_v));

				Emit("case %s:", c_v_rep);
				}
			}

		else
			Emit("default:");

		StartBlock();
		GenStmt(c->Body());
		EndBlock();
		}

	--break_level;

	Emit("}");
	}

std::string CPPCompile::GenExpr(const Expr* e, GenType gt, bool top_level)
	{
	const auto& t = e->GetType();

	std::string gen;

	switch ( e->Tag() ) {
	case EXPR_NAME:
		{
		auto n = e->AsNameExpr()->Id();
		bool is_global_var = global_vars.count(n) > 0;

		if ( t->Tag() == TYPE_FUNC && ! is_global_var )
			{
			auto func = n->Name();
			if ( globals.count(func) > 0 &&
			     pfs.BiFGlobals().count(n) == 0 )
				return GenericValPtrToGT(IDNameStr(n), t, gt);
			}

		if ( is_global_var )
			{
			if ( n->IsType() )
				gen = std::string("make_intrusive<TypeVal>(") +
							globals[n->Name()] +
							"->GetType(), true)";

			else
				gen = globals[n->Name()] + "->GetVal()";

			return GenericValPtrToGT(gen, t, gt);
			}

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
		auto one = e->GetType()->InternalType() == TYPE_INTERNAL_INT ?
				val_mgr->Int(1) : val_mgr->Count(1);
		auto one_e = make_intrusive<ConstExpr>(one);

		ExprPtr rhs;
		if ( e->Tag() == EXPR_INCR )
			rhs = make_intrusive<AddExpr>(op, one_e);
		else
			rhs = make_intrusive<SubExpr>(op, one_e);

		auto assign = make_intrusive<AssignExpr>(op, rhs, false,
						nullptr, nullptr, false);

		gen = GenExpr(assign, GEN_DONT_CARE, top_level);

		if ( ! top_level )
			gen = "(" + gen + ", " + GenExpr(op, gt) + ")";

		return gen;
		}

	case EXPR_NOT:		return GenUnary(e, gt, "!", "not");
	case EXPR_COMPLEMENT:	return GenUnary(e, gt, "~", "comp");
	case EXPR_POSITIVE:	return GenUnary(e, gt, "+", "pos");
	case EXPR_NEGATE:	return GenUnary(e, gt, "-", "neg");

	case EXPR_ADD:		return GenBinary(e, gt, "+", "add");
	case EXPR_SUB:		return GenBinary(e, gt, "-", "sub");
	case EXPR_REMOVE_FROM:	return GenBinary(e, gt, "-=");
	case EXPR_TIMES:	return GenBinary(e, gt, "*", "mul");
	case EXPR_DIVIDE:	return GenBinary(e, gt, "/", "div");
	case EXPR_MOD:		return GenBinary(e, gt, "%", "mod");
	case EXPR_AND:		return GenBinary(e, gt, "&", "and");
	case EXPR_OR:		return GenBinary(e, gt, "|", "or");
	case EXPR_XOR:		return GenBinary(e, gt, "^", "xor");
	case EXPR_AND_AND:	return GenBinary(e, gt, "&&", "andand");
	case EXPR_OR_OR:	return GenBinary(e, gt, "||", "oror");
	case EXPR_LT:		return GenBinary(e, gt, "<", "lt");
	case EXPR_LE:		return GenBinary(e, gt, "<=", "le");
	case EXPR_GE:		return GenBinary(e, gt, ">=","ge");
	case EXPR_GT:		return GenBinary(e, gt, ">", "gt");

	case EXPR_EQ:		return GenEQ(e, gt, "==", "eq");
	case EXPR_NE:		return GenEQ(e, gt, "!=", "ne");

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
			auto f_id = f->AsNameExpr()->Id();
			const auto& params =
				f_id->GetType()->AsFuncType()->Params();
			auto id_name = f_id->Name();
			auto fname = Canonicalize(id_name) + "_zf";

			bool is_compiled = compiled_funcs.count(fname) > 0;
			bool was_compiled = hashed_funcs.count(id_name) > 0;

			if ( is_compiled || was_compiled )
				{
				if ( was_compiled )
					fname = hashed_funcs[id_name];

				if ( args_l->Exprs().length() > 0 )
					gen = fname + "(" +
						GenArgs(params, args_l) +
						", f__CPP)";
				else
					gen = fname + "(f__CPP)";

				return NativeToGT(gen, t, gt);
				}

			// If the function isn't a BiF, then it will have
			// been declared as a ValPtr (or a FuncValPtr, if
			// a local), and we need to convert it to a Func*.
			//
			// If it is a BiF *that's also a global variable*,
			// then we need to look up the BiF version of the
			// global.
			if ( pfs.BiFGlobals().count(f_id) == 0 )
				gen += + "->AsFunc()";

			else if ( pfs.Globals().count(f_id) > 0 )
				// The BiF version has an extra "_", per
				// AddBiF(..., true).
				gen = globals[std::string(id_name) + "_"];
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
				GenExpr(op1, GEN_VAL_PTR) + "->Get())";

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
			{
			const auto& op2 = e->GetOp2();
			const auto& t2 = op2->GetType();
			ASSERT(t2->Tag() == TYPE_LIST);

			if ( t2->Tag() == TYPE_LIST &&
			     t2->AsTypeList()->GetTypes().size() == 2 )
				{
				auto& inds = op2->AsListExpr()->Exprs();
				auto first = inds[0];
				auto last = inds[1];
				gen = std::string("index_slice(") +
					GenExpr(aggr, GEN_VAL_PTR) +
					".get(), " +
					GenExpr(first, GEN_NATIVE) +
					", " +
					GenExpr(last, GEN_NATIVE) + ")";
				}
			else
				gen = GenExpr(aggr, GEN_DONT_CARE) + "->At(" +
					GenExpr(e->GetOp2(), GEN_NATIVE) + ")";
			}

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

		return GenAssign(op1, op2, rhs_native, rhs_val_ptr,
					gt, top_level);
		}

	case EXPR_ADD_TO:
		{
		if ( t->Tag() == TYPE_VECTOR )
			{
			gen = std::string("vector_append__CPP(") +
				GenExpr(e->GetOp1(), GEN_VAL_PTR) +
				", " + GenExpr(e->GetOp2(), GEN_VAL_PTR) + ")";
			return GenericValPtrToGT(gen, t, gt);
			}

		// Second GetOp1 is because for non-vectors, LHS will be
		// a RefExpr.
		auto lhs = e->GetOp1()->GetOp1();

		if ( t->Tag() == TYPE_STRING )
			{
			auto rhs_native = GenBinaryString(e, GEN_NATIVE, "+=");
			auto rhs_val_ptr = GenBinaryString(e, GEN_VAL_PTR, "+=");

			return GenAssign(lhs, nullptr, rhs_native, rhs_val_ptr,
						gt, top_level);
			}

		if ( lhs->Tag() != EXPR_NAME ||
		     lhs->AsNameExpr()->Id()->IsGlobal() )
			{
			// LHS is a compound, or a global (and thus doesn't
			// equate to a C++ variable); expand x += y to x = x + y
			auto rhs = make_intrusive<AddExpr>(lhs, e->GetOp2());
			auto assign = make_intrusive<AssignExpr>(lhs, rhs, false, nullptr, nullptr, false);
			return GenExpr(assign, gt, top_level);
			}

		return GenBinary(e, gt, "+=");
		}

	case EXPR_REF:
		return GenExpr(e->GetOp1(), gt);

	case EXPR_SIZE:
		{
		const auto& t1 = e->GetOp1()->GetType();
		auto it = t1->InternalType();

		gen = GenExpr(e->GetOp1(), GEN_NATIVE);

		if ( t1->Tag() == TYPE_BOOL )
			gen = std::string("((") + gen + ") ? 1 : 0)";

		else if ( it == TYPE_INTERNAL_UNSIGNED )
			// no-op
			;

		else if ( it == TYPE_INTERNAL_INT || it == TYPE_INTERNAL_DOUBLE )
			gen = std::string("abs__CPP(") + gen + ")";

		else
			return GenericValPtrToGT(gen + "->SizeVal()", t, gt);

		return NativeToGT(gen, t, gt);
		}

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

		std::string attr_tags;
		std::string attr_vals;
		BuildAttrs(attrs, attr_tags, attr_vals);

		return std::string("set_constructor__CPP({") +
			GenExpr(sc->GetOp1(), GEN_VAL_PTR) + "}, " +
			"cast_intrusive<TableType>(" + GenTypeName(t) + "), " +
			attr_tags + ", " + attr_vals + ")";
		}

	case EXPR_TABLE_CONSTRUCTOR:
		{
		auto tc = static_cast<const TableConstructorExpr*>(e);
		auto t = tc->GetType<TableType>();
		auto attrs = tc->GetAttrs();

		std::string attr_tags;
		std::string attr_vals;
		BuildAttrs(attrs, attr_tags, attr_vals);

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
			attr_tags + ", " + attr_vals + ")";
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

		RegisterEvent(event_name);

		std::string when_s = GenExpr(when, GEN_NATIVE);
		if ( when->GetType()->Tag() == TYPE_INTERVAL )
			when_s += " + run_state::network_time";

		return std::string("schedule__CPP(") + when_s +
			", " + globals[event_name] + "_ev, { " +
			GenExpr(event->Args(), GEN_VAL_PTR) + " })";
		}

	case EXPR_LAMBDA:
		{
		auto l = static_cast<const LambdaExpr*>(e);
		auto name = Canonicalize(l->Name().c_str()) + "_lb_cl";
		auto& ids = l->OuterIDs();
		const auto& in = l->Ingredients();

		std::string cl_args = "\"" + name + "\"";

		for ( const auto& id : ids )
			cl_args = cl_args + ", " + IDNameStr(id);

		auto body = std::string("make_intrusive<") + name + ">(" +
				cl_args + ")";
		auto func = std::string("make_intrusive<ScriptFunc>(") +
				"cast_intrusive<FuncType>(" +
				GenTypeName(t) + "), " + body + ")";
		return std::string("make_intrusive<FuncVal>(") + func + ")";
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

	case EXPR_IS:
		gen = std::string("can_cast_value_to_type(")
			+ GenExpr(e->GetOp1(), GEN_VAL_PTR) + ".get(), " +
			GenTypeName(t) + ".get())";
		return NativeToGT(gen, t, gt);

	case EXPR_FIELD_ASSIGN:
	case EXPR_INDEX_SLICE_ASSIGN:
	case EXPR_INLINE:
		// These are only generated for reduced ASTs, which
		// we shouldn't be compiling.
		ASSERT(0);

	default:
		return std::string("EXPR");
	}
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

std::string CPPCompile::GenUnary(const Expr* e, GenType gt,
					const char* op, const char* vec_op)
	{
	if ( e->GetType()->Tag() == TYPE_VECTOR )
		return GenVectorOp(GenExpr(e->GetOp1(), GEN_NATIVE), vec_op);

	return NativeToGT(std::string(op) + "(" +
				GenExpr(e->GetOp1(), GEN_NATIVE) + ")",
				e->GetType(), gt);
	}

std::string CPPCompile::GenBinary(const Expr* e, GenType gt,
					const char* op, const char* vec_op)
	{
	const auto& op1 = e->GetOp1();
	const auto& op2 = e->GetOp2();

	if ( e->GetType()->Tag() == TYPE_VECTOR )
		{
		auto gen1 = GenExpr(op1, GEN_NATIVE);
		auto gen2 = GenExpr(op2, GEN_NATIVE);
		return GenVectorOp(gen1, gen2, vec_op);
		}

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
		res = v1 + "->Union(" + v2 + ")";
		break;

	case EXPR_SUB:
		res = v1 + "->TakeOut(" + v2 + ")";
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

	if ( e->Tag() == EXPR_DIVIDE )
		{
		auto gen = std::string("addr_mask__CPP(") +
				v1 + ", " +
				GenExpr(e->GetOp2(), GEN_NATIVE) + ")";

		return NativeToGT(gen, e->GetType(), gt);
		}

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

std::string CPPCompile::GenEQ(const Expr* e, GenType gt,
					const char* op, const char* vec_op)
	{
	auto op1 = e->GetOp1();
	auto op2 = e->GetOp2();

	if ( e->GetType()->Tag() == TYPE_VECTOR )
		{
		auto gen1 = GenExpr(op1, GEN_NATIVE);
		auto gen2 = GenExpr(op2, GEN_NATIVE);
		return GenVectorOp(gen1, gen2, vec_op);
		}

	auto tag = op1->GetType()->Tag();
	std::string negated(e->Tag() == EXPR_EQ ? "" : "! ");

	if ( tag == TYPE_PATTERN )
		return NativeToGT(negated + GenExpr(op1, GEN_DONT_CARE) +
					"->MatchExactly(" +
					GenExpr(op2, GEN_DONT_CARE) +
					"->AsString())",
					e->GetType(), gt);

	if ( tag == TYPE_FUNC )
		{
		auto f1 = op1->Tag() == EXPR_NAME ?
				op1->AsNameExpr()->Id()->Name() : nullptr;
		auto f2 = op2->Tag() == EXPR_NAME ?
				op2->AsNameExpr()->Id()->Name() : nullptr;

		if ( f1 && f2 )
			{
			auto gen = util::streq(f1, f2) ? "true" : "false";
			return NativeToGT(negated + gen, e->GetType(), gt);
			}

		auto gen_f1 = GenExpr(op1, GEN_DONT_CARE);
		auto gen_f2 = GenExpr(op2, GEN_DONT_CARE);

		gen_f1 += "->AsFunc()->Name()";
		gen_f2 += "->AsFunc()->Name()";

		if ( f1 ) gen_f1 = std::string("\"") + f1 + "\"";
		if ( f2 ) gen_f2 = std::string("\"") + f2 + "\"";

		auto gen = "util::streq(" + gen_f1 + ", " + gen_f2 + ")";

		return NativeToGT(negated + gen, e->GetType(), gt);
		}

	return GenBinary(e, gt, op, vec_op);
	}

std::string CPPCompile::GenAssign(const ExprPtr& lhs, const ExprPtr& rhs,
					const std::string& rhs_native,
					const std::string& rhs_val_ptr,
					GenType gt, bool top_level)
	{
	std::string gen;

	switch ( lhs->Tag() ) {
	case EXPR_NAME:
		{
		auto n = lhs->AsNameExpr()->Id();
		auto name = IDNameStr(n);

		if ( n->IsGlobal() )
			{
			auto gn = globals[n->Name()];

			if ( top_level )
				gen = gn + "->SetVal(" + rhs_val_ptr + ")";
			else
				{
				gen = std::string("set_global__CPP(") +
					gn + ", " + rhs_val_ptr + ")";
				gen = GenericValPtrToGT(gen, n->GetType(), gt);
				}
			}
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
		{
		auto rec = GenExpr(lhs->GetOp1(), GEN_VAL_PTR);
		auto field = Fmt(lhs->AsFieldExpr()->Field());

		if ( top_level )
			gen = rec + "->Assign(" + field + ", " +
						rhs_val_ptr + ")";
		else
			{
			gen = std::string("assign_field__CPP(") +
				rec + ", " + field + ", " + rhs_val_ptr + ")";
			gen = GenericValPtrToGT(gen, rhs->GetType(), gt);
			}
		}
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

std::string CPPCompile::GenVectorOp(std::string op, const char* vec_op)
	{
	return std::string("vec_op_") + vec_op + "__CPP(" + op + ")";
	}

std::string CPPCompile::GenVectorOp(std::string op1, std::string op2,
					const char* vec_op)
	{
	return std::string("vec_op_") + vec_op + "__CPP(" + op1 +
		", " + op2 + ")";
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
	auto ename = InitExprName(e);

	// First, create a CPPFunc that we can compile to compute e.
	auto name = std::string("wrapper_") + ename;

	Emit("static %s %s(Frame* f__CPP);", FullTypeName(t), name);

	Emit("class %s_cl : public CPPFunc", name);
	StartBlock();

	Emit("public:");
	Emit("%s_cl() : CPPFunc(\"%s\", false)", name, name);

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
			auto type_accessor = GenTypeName(td->type);

			auto td_name = std::string("util::copy_string(\"") +
					td->id + "\")";

			if ( td->attrs )
				AddInit(t, std::string("tl.append(new TypeDecl(") +
					td_name + ", " + type_accessor +
					", " + AttrsName(td->attrs) +"));");
			else
				AddInit(t, std::string("tl.append(new TypeDecl(") +
					td_name + ", " + type_accessor +"));");
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

			decl = decl + tn + " " + name + ", ";
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

std::string CPPCompile::CPPEscape(const char* s) const
	{
	std::string res;

	while ( *s )
		{
		switch ( *s ) {
		case '\\':	res += "\\\\"; break;
		case '"':	res += "\\\""; break;

		default:	res += *s; break;
		}
		++s;
		}

	return res;
	}

void CPPCompile::Indent() const
	{
	for ( auto i = 0; i < block_level; ++i )
		fprintf(write_file, "%s", "\t");
	}


bool is_CPP_compilable(const ProfileFunc* pf)
	{
	if ( pf->NumWhenStmts() > 0 )
		return false;

	if ( pf->TypeSwitches().size() > 0 )
		return false;

	return true;
	}

void lock_file(const std::string& fname, FILE* f)
	{
	if ( flock(fileno(f), LOCK_EX) < 0 )
		{
		char buf[256];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("flock failed on %s: %s", fname.c_str(), buf);
		exit(1);
		}
	}

void unlock_file(const std::string& fname, FILE* f)
	{
	if ( flock(fileno(f), LOCK_UN) < 0 )
		{
		char buf[256];
		util::zeek_strerror_r(errno, buf, sizeof(buf));
		reporter->Error("un-flock failed on %s: %s", fname.c_str(), buf);
		exit(1);
		}
	}

} // zeek::detail
