// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

CPPCompile::CPPCompile(vector<FuncInfo>& _funcs, ProfileFuncs& _pfs, const string& gen_name,
                       const string& _addl_name, CPPHashManager& _hm, bool _update,
                       bool _standalone, bool report_uncompilable)
	: funcs(_funcs), pfs(_pfs), hm(_hm), update(_update), standalone(_standalone)
	{
	addl_name = _addl_name;
	bool is_addl = hm.IsAppend();
	auto target_name = is_addl ? addl_name.c_str() : gen_name.c_str();
	auto mode = is_addl ? "a" : "w";

	write_file = fopen(target_name, mode);
	if ( ! write_file )
		{
		reporter->Error("can't open C++ target file %s", target_name);
		exit(1);
		}

	if ( is_addl )
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
			reporter->Error("fstat failed on %s: %s", target_name, buf);
			exit(1);
			}

		// We use a value of "0" to mean "we're not appending,
		// we're generating from scratch", so make sure we're
		// distinct from that.
		addl_tag = st.st_size + 1;
		}

	else
		{
		// Create an empty "additional" file.
		auto addl_f = fopen(addl_name.c_str(), "w");
		if ( ! addl_f )
			{
			reporter->Error("can't open C++ additional file %s", addl_name.c_str());
			exit(1);
			}

		fclose(addl_f);
		}

	Compile(report_uncompilable);
	}

CPPCompile::~CPPCompile()
	{
	fclose(write_file);
	}

void CPPCompile::Compile(bool report_uncompilable)
	{
	// Get the working directory so we can use it in diagnostic messages
	// as a way to identify this compilation.  Only germane when doing
	// incremental compilation (particularly of the test suite).
	char buf[8192];
	if ( ! getcwd(buf, sizeof buf) )
		reporter->FatalError("getcwd failed: %s", strerror(errno));

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

		const char* reason;
		if ( IsCompilable(func, &reason) )
			compilable_funcs.insert(BodyName(func));
		else
			{
			if ( reason && report_uncompilable )
				fprintf(stderr, "%s cannot be compiled to C++ due to %s\n", func.Func()->Name(),
			                reason);
			not_fully_compilable.insert(func.Func()->Name());
			}

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
		(void)RegisterType(tp);
		}

	// ### This doesn't work for -O add-C++
	Emit("TypePtr types__CPP[%s];", Fmt(static_cast<int>(types.DistinctKeys().size())));

	NL();

#if 0
	for ( auto gi : all_global_info )
		Emit(gi->Declare());

	NL();
#endif

	for ( auto& g : pfs.AllGlobals() )
		CreateGlobal(g);

	for ( const auto& e : pfs.Events() )
		if ( AddGlobal(e, "gl", false) )
			Emit("EventHandlerPtr %s_ev;", globals[string(e)]);

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

	// We track lambdas by their internal names, because two different
	// LambdaExpr's can wind up referring to the same underlying lambda
	// if the bodies happen to be identical.  In that case, we don't
	// want to generate the lambda twice.
	unordered_set<string> lambda_names;
	for ( const auto& l : pfs.Lambdas() )
		{
		const auto& n = l->Name();
		if ( lambda_names.count(n) > 0 )
			// Skip it.
			continue;

		DeclareLambda(l, pfs.ExprProf(l).get());
		lambda_names.insert(n);
		}

	NL();

	// ... and now generate their bodies.
	for ( const auto& func : funcs )
		CompileFunc(func);

	lambda_names.clear();
	for ( const auto& l : pfs.Lambdas() )
		{
		const auto& n = l->Name();
		if ( lambda_names.count(n) > 0 )
			continue;

		CompileLambda(l, pfs.ExprProf(l).get());
		lambda_names.insert(n);
		}

	NL();
	Emit("std::vector<CPP_RegisterBody> CPP__bodies_to_register = {");

	for ( const auto& f : compiled_funcs )
		RegisterCompiledBody(f);

	Emit("};");

	GenEpilog();
	}

void CPPCompile::GenProlog()
	{
	if ( addl_tag == 0 )
		{
		Emit("#include \"zeek/script_opt/CPP/Runtime.h\"\n");
		Emit("namespace zeek::detail { //\n");
		}

	Emit("namespace CPP_%s { // %s\n", Fmt(addl_tag), working_dir);

	// The following might-or-might-not wind up being populated/used.
	Emit("std::vector<int> field_mapping;");
	Emit("std::vector<int> enum_mapping;");
	NL();

	const_info[TYPE_BOOL] = CreateInitInfo("Bool", "ValPtr", "bool");
	const_info[TYPE_INT] = CreateInitInfo("Int", "ValPtr", "bro_int_t");
	const_info[TYPE_COUNT] = CreateInitInfo("Count", "ValPtr", "bro_uint_t");
	const_info[TYPE_DOUBLE] = CreateInitInfo("Double", "ValPtr", "double");
	const_info[TYPE_TIME] = CreateInitInfo("Time", "ValPtr", "double");
	const_info[TYPE_INTERVAL] = CreateInitInfo("Interval", "ValPtr", "double");
	const_info[TYPE_ADDR] = CreateInitInfo("Addr", "ValPtr", "int", false);
	const_info[TYPE_SUBNET] = CreateInitInfo("SubNet", "ValPtr", "int", false);
	const_info[TYPE_PORT] = CreateInitInfo("Port", "ValPtr", "uint32_t");

	const_info[TYPE_ENUM] = CreateInitInfo("Enum", "ValPtr");
	const_info[TYPE_STRING] = CreateInitInfo("String", "ValPtr");
	const_info[TYPE_PATTERN] = CreateInitInfo("Pattern", "ValPtr");
	const_info[TYPE_LIST] = CreateInitInfo("List", "ValPtr");
	const_info[TYPE_VECTOR] = CreateInitInfo("Vector", "ValPtr");
	const_info[TYPE_RECORD] = CreateInitInfo("Record", "ValPtr");
	const_info[TYPE_TABLE] = CreateInitInfo("Table", "ValPtr");
	const_info[TYPE_FUNC] = CreateInitInfo("Func", "ValPtr");
	const_info[TYPE_FILE] = CreateInitInfo("File", "ValPtr");

	type_info = CreateInitInfo("Type", "Ptr");
	attr_info = CreateInitInfo("Attr", "Ptr");
	attrs_info = CreateInitInfo("Attributes", "Ptr");
	call_exprs_info = CreateInitInfo("CallExpr", "Ptr");

	lambda_reg_info = CreateInitInfo("LambdaRegistration", "");
	global_id_info = CreateInitInfo("GlobalID", "");

	NL();
	DeclareDynCPPStmt();
	NL();
	}

shared_ptr<CPP_InitsInfo> CPPCompile::CreateInitInfo(const char* tag, const char* type, const char* c_type, bool is_basic)
	{
	string v_type = type[0] ? (string(tag) + type) : "void*";
	Emit("std::vector<%s> CPP__%s__;", v_type, string(tag));

	shared_ptr<CPP_InitsInfo> gi;

	if ( c_type )
		gi = make_shared<CPP_BasicConstInitsInfo>(tag, type, c_type, is_basic);
	else if ( util::streq(tag, "Enum") ||
	          util::streq(tag, "String") ||
	          util::streq(tag, "List") ||
	          util::streq(tag, "Table") ||
	          util::streq(tag, "Vector") ||
	          util::streq(tag, "Record") ||
	          util::streq(tag, "File") ||
	          util::streq(tag, "Func") ||
	          util::streq(tag, "Pattern") )
		gi = make_shared<CPP_CompoundInitsInfo>(tag, type);

	else if ( util::streq(tag, "Type") )
		gi = make_shared<CPP_CompoundInitsInfo>(tag, type);
	else if ( util::streq(tag, "Attr") )
		gi = make_shared<CPP_CompoundInitsInfo>(tag, type);
	else if ( util::streq(tag, "Attributes") )
		gi = make_shared<CPP_CompoundInitsInfo>(tag, type);
	else
		gi = make_shared<CPP_CustomInitsInfo>(tag, type);

	all_global_info.insert(gi);

	if ( type[0] == '\0' )
		gi->SetCPPType("void*");

	return gi;
	}

void CPPCompile::RegisterCompiledBody(const string& f)
	{
	auto h = body_hashes[f];
	auto p = body_priorities[f];

	// Build up an initializer of the events relevant to the function.
	string events;
	if ( body_events.count(f) > 0 )
		for ( const auto& e : body_events[f] )
			{
			if ( events.size() > 0 )
				events += ", ";
			events = events + "\"" + e + "\"";
			}

	events = string("{") + events + "}";

	if ( addl_tag > 0 )
		// Hash in the location associated with this compilation
		// pass, to get a final hash that avoids conflicts with
		// identical-but-in-a-different-context function bodies
		// when compiling potentially conflicting additional code
		// (which we want to support to enable quicker test suite
		// runs by enabling multiple tests to be compiled into the
		// same binary).
		h = merge_p_hashes(h, p_hash(cf_locs[f]));

	ASSERT(func_index.count(f) > 0);
	auto type_signature = casting_index[func_index[f]];
	Emit("\tCPP_RegisterBody(\"%s\", (void*) %s, %s, %s, %s, std::vector<std::string>(%s)),", f, f, Fmt(type_signature), Fmt(p), Fmt(h), events);

	if ( update )
		{
		fprintf(hm.HashFile(), "func\n%s%s\n", scope_prefix(addl_tag).c_str(), f.c_str());
		fprintf(hm.HashFile(), "%llu\n", h);
		}
	}

void CPPCompile::GenEpilog()
	{
	NL();
	for ( const auto& ii : init_infos )
		{
		auto& ie = ii.second;
		GenInitExpr(ie);
		if ( update )
			init_exprs.LogIfNew(ie->GetExpr(), addl_tag, hm.HashFile());
		}

	NL();
	Emit("ValPtr CPPDynStmt::Exec(Frame* f, StmtFlowType& flow)");
	StartBlock();
	Emit("flow = FLOW_RETURN;");
	Emit("switch ( type_signature )");
	StartBlock();
	for ( auto i = 0U; i < func_casting_glue.size(); ++i )
		{
		Emit("case %s:", to_string(i));
		StartBlock();
		auto& glue = func_casting_glue[i];

		auto invoke = string("(*(") + glue.cast + ")(func))(" + glue.args + ")";

		if ( glue.is_hook )
			{
			Emit("if ( ! %s )", invoke);
			StartBlock();
			Emit("flow = FLOW_BREAK;");
			EndBlock();
			Emit("return nullptr;");
			}

		else if ( IsNativeType(glue.yield) )
			GenInvokeBody(invoke, glue.yield);

		else
			Emit("return %s;", invoke);

		EndBlock();
		}

	Emit("default:");
	Emit("\treporter->InternalError(\"invalid type in CPPDynStmt::Exec\");");
	Emit("\treturn nullptr;");

	EndBlock();
	EndBlock();

	NL();

	// Generate the guts of compound types, and preserve type names
	// if present.
	for ( const auto& t : types.DistinctKeys() )
		{
		if ( update )
			types.LogIfNew(t, addl_tag, hm.HashFile());
		}

	for ( auto gi : all_global_info )
		gi->GenerateInitializers(this);

	unordered_set<const Obj*> to_do;
	for ( const auto& oi : obj_inits )
		to_do.insert(oi.first);

	if ( standalone )
		GenStandaloneActivation();

	NL();
	InitializeEnumMappings();

	NL();
	InitializeFieldMappings();

	NL();
	InitializeBiFs();

	NL();
	indices_mgr.Generate(this);

	NL();
	InitializeStrings();

	NL();
	InitializeHashes();

	NL();
	InitializeConsts();

	NL();
	Emit("void init__CPP()");

	StartBlock();

	Emit("std::vector<std::vector<int>> InitIndices;");
	Emit("generate_indices_set(CPP__Indices__init, InitIndices);");

	Emit("std::map<TypeTag, std::shared_ptr<CPP_AbstractInitAccessor>> InitConsts;");

	NL();
	for ( const auto& ci : const_info )
		{
		auto& gi = ci.second;
		Emit("InitConsts.emplace(%s, std::make_shared<CPP_InitAccessor<%s>>(%s));", TypeTagName(ci.first), gi->CPPType(), gi->InitsName());
		}

	Emit("InitsManager im(CPP__ConstVals, InitConsts, InitIndices, CPP__Strings, CPP__Hashes, CPP__Type__, CPP__Attributes__, CPP__Attr__, CPP__CallExpr__);");

	NL();
	Emit("for ( auto& b : CPP__bodies_to_register )");
	StartBlock();
	Emit("auto f = make_intrusive<CPPDynStmt>(b.func_name.c_str(), b.func, b.type_signature);");
	Emit("register_body__CPP(f, b.priority, b.h, b.events);");
	EndBlock();

	NL();
	int max_cohort = 0;
	for ( auto gi : all_global_info )
		max_cohort = std::max(max_cohort, gi->MaxCohort());

	for ( auto c = 0; c <= max_cohort; ++c )
		for ( auto gi : all_global_info )
			if ( gi->CohortSize(c) > 0 )
				Emit("%s.InitializeCohort(&im, %s);",
				     gi->InitializersName(), Fmt(c));

	NL();
	Emit("for ( auto& b : CPP__BiF_lookups__ )");
	Emit("\tb.ResolveBiF();");

	// Populate mappings for dynamic offsets.
	NL();
	Emit("for ( auto& em : CPP__enum_mappings__ )");
	Emit("\tenum_mapping.push_back(em.ComputeOffset(&im));");
	NL();
	Emit("for ( auto& fm : CPP__field_mappings__ )");
	Emit("\tfield_mapping.push_back(fm.ComputeOffset(&im));");

	if ( standalone )
		Emit("standalone_init__CPP();");

	EndBlock(true);

	GenInitHook();

	Emit("} // %s\n\n", scope_prefix(addl_tag));

	if ( update )
		UpdateGlobalHashes();

	if ( addl_tag > 0 )
		return;

	Emit("#include \"" + addl_name + "\"\n");
	Emit("} // zeek::detail");
	}

bool CPPCompile::IsCompilable(const FuncInfo& func, const char** reason)
	{
	if ( ! is_CPP_compilable(func.Profile(), reason) )
		return false;

	if ( reason )
		// Indicate that there's no fundamental reason it can't be
		// compiled.
		*reason = nullptr;

	if ( func.ShouldSkip() )
		return false;

	if ( hm.HasHash(func.Profile()->HashVal()) )
		// We've already compiled it.
		return false;

	return true;
	}

	} // zeek::detail
