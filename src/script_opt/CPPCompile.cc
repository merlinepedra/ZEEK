// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zeek/script_opt/CPPCompile.h"


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
		// We need a unique number to associate with the name
		// space for the code we're adding.  A convenient way to
		// generate this safely is to use the present size of the
		// file we're appending to.  That guarantees that every
		// incremental compilation will wind up with a different
		// number.
		struct stat st;
		if ( fstat(fileno(write_file), &st) != 0 )
			{
			char buf[256];
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Error("fstat failed on %s: %s", gen_name, buf);
			exit(1);
			}

		// We use a value of "0" to mean "we're not appending,
		// we're generating from scratch", so make sure we're
		// distinct from that.
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
	// Get the working directory so we can use it in diagnostic messages
	// as a way to identify this compilation.  Only germane when doing
	// incremental compilation (particularly of the test suite).
	char buf[8192];
	getcwd(buf, sizeof buf);
	working_dir = buf;

	if ( update && addl_tag > 0 && CheckForCollisions() )
		// Inconsistent compilation environment.
		exit(1);

	GenProlog();

	// Determine which functions we can call directly, and reuse
	// previously compiled instances of those if present.
	for ( const auto& func : funcs )
		{
		if ( func.Func()->Flavor() != FUNC_FLAVOR_FUNCTION )
			// Can't be called directly.
			continue;

		if ( IsCompilable(func) )
			compilable_funcs.insert(BodyName(func));

		auto h = func.Profile()->HashVal();
		if ( hm.HasHash(h) )
			{
			// Track the previously compiled instance
			// of this function.
			auto n = func.Func()->Name();
			hashed_funcs[n] = hm.FuncBodyName(h);
			}
		}

	// Track all of the types we'll be using.
	for ( const auto& t : pfs.RepTypes() )
		{
		TypePtr tp{NewRef{}, (Type*)(t)};
		types.AddKey(tp, pfs.HashType(t));
		}

	for ( const auto& t : types.DistinctKeys() )
		if ( ! types.IsInherited(t) )
			// Type is new to this compilation, so we'll
			// be generating it.
			Emit("TypePtr %s;", types.KeyName(t));

	NL();

	for ( const auto& c : pfs.Constants() )
		AddConstant(c);

	NL();

	for ( auto& g : pfs.AllGlobals() )
		CreateGlobal(g);

	for ( const auto& e : pfs.Events() )
		if ( AddGlobal(e, "gl", false) )
			Emit("EventHandlerPtr %s_ev;", globals[std::string(e)]);

	for ( const auto& t : pfs.RepTypes() )
		{
		ASSERT(types.HasKey(t));
		TypePtr tp{NewRef{}, (Type*)(t)};
		RegisterType(tp);
		}

	// The scaffolding is now in place to go ahead and generate
	// the functions & lambdas.  First declare them ...
	for ( const auto& func : funcs )
		DeclareFunc(func);

	for ( const auto& l : pfs.Lambdas() )
		DeclareLambda(l, pfs.ExprProf(l));

	NL();

	// ... and now generate their bodies.
	for ( const auto& func : funcs )
		CompileFunc(func);

	for ( const auto& l : pfs.Lambdas() )
		CompileLambda(l, pfs.ExprProf(l));

	for ( const auto& f : compiled_funcs )
		RegisterCompiledBody(f);

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

void CPPCompile::RegisterCompiledBody(const std::string& f)
	{
	auto h = body_hashes[f];

	// Build up an initializer of the events relevant to the function.
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
		// Hash in the location associated with this compilation
		// pass, to get a final hash that avoids conflicts with
		// identical-but-in-a-different-context function bodies
		// when compiling potentially conflicting additional code
		// (which we want to support to enable quicker test suite
		// runs by enabling multiple tests to be compiled into the
		// same binary).
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

	CheckInitConsistency(to_do);
	GenDependentInits(to_do);

	// Populate mappings for dynamic offsets.
	InitializeFieldMappings();
	InitializeEnumMappings();

	EndBlock(true);
	Emit("} // %s\n\n", scope_prefix(addl_tag).c_str());

	GenInitHook();

	if ( update )
		UpdateGlobalHashes();

	if ( addl_tag > 0 )
		return;

	Emit("#include \"zeek/script_opt/CPP-gen-addl.h\"\n");
	Emit("} // zeek::detail");
	}

bool CPPCompile::IsCompilable(const FuncInfo& func)
	{
	if ( func.ShouldSkip() )
		// Caller marked this function as one to skip.
		return false;

	if ( hm.HasHash(func.Profile()->HashVal()) )
		// We've already compiled it.
		return false;

	return is_CPP_compilable(func.Profile());
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

void CPPCompile::RegisterEvent(std::string ev_name)
	{
	body_events[body_name].emplace_back(std::move(ev_name));
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
