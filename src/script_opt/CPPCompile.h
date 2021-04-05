// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Desc.h"
#include "zeek/script_opt/CPPFunc.h"
#include "zeek/script_opt/CPPUtil.h"
#include "zeek/script_opt/CPPTracker.h"
#include "zeek/script_opt/CPPHashMgr.h"
#include "zeek/script_opt/ScriptOpt.h"


namespace zeek::detail {

class CPPCompile {
public:
	CPPCompile(std::vector<FuncInfo>& _funcs, ProfileFuncs& pfs,
			const char* gen_name, CPPHashManager& hm,
			bool update);
	~CPPCompile();

private:
	void Compile();

	// Generate the beginning of the compiled code: run-time functions,
	// namespace, auxiliary globals.
	void GenProlog();

	// Given the name of a function body that's been compiled, generate
	// code to register it at run-time, and track its associated hash
	// so subsequent compilations can reuse it.
	void RegisterCompiledBody(const std::string& f);

	void GenEpilog();

	bool IsCompilable(const FuncInfo& func);

	// Start of methods related to script variables and their C++
	// counterparts.
	// See CPPVars.cc for definitions.
	//

	// Returns true if the current compilation context has collisions
	// with previously generated code (globals with conflicting types
	// or initialization values, or types with differing elements).
	bool CheckForCollisions();

	// Generate declarations associated with the given global, and, if
	// it's used as a variable (not just as a function being called),
	// track it as such.
	void CreateGlobal(const ID* g);

	// For the globals used in the compilation, if new then append
	// them to the hash file to make the information available
	// to subsequent compilation runs.
	void UpdateGlobalHashes();

	void AddBiF(const ID* b, bool is_var);
	bool AddGlobal(const std::string& g, const char* suffix, bool track);

	// The following match various forms of identifiers to the
	// name used for their C++ equivalent.
	const char* IDName(const ID& id)	{ return IDName(&id); }
	const char* IDName(const IDPtr& id)	{ return IDName(id.get()); }
	const char* IDName(const ID* id)	{ return IDNameStr(id).c_str(); }
	const std::string& IDNameStr(const ID* id) const;

	// Returns a canonicalized version of a variant of a global made
	// distinct by the given suffix.
	std::string GlobalName(const std::string& g, const char* suffix)
		{
		return Canonicalize(g.c_str()) + "_" + suffix;
		}

	// Returns a canonicalized form of a local identifier's name,
	// expanding its module prefix if needed.
	std::string LocalName(const ID* l) const;
	std::string LocalName(const IDPtr& l) const
		{ return LocalName(l.get()); }

	// Returns a canonicalized name, with various non-alphanumeric
	// characters stripped or transformed, and guananteed not to
	// conflict with C++ keywords.
	std::string Canonicalize(const char* name) const;

	//
	// End of methods related to script/C++ variables.

	// Start of methods related to declaring compiled script functions,
	// including related classes.
	// See CPPDeclFunc.cc for definitions.
	//

	void DeclareFunc(const FuncInfo& func);
	void DeclareLambda(const LambdaExpr* l, const ProfileFunc* pf);

	void DeclareSubclass(const FuncTypePtr& ft, const ProfileFunc* pf,
                             const std::string& fname, const StmtPtr& body,
                             const LambdaExpr* l, FunctionFlavor flavor);
	void BuildLambda(const FuncTypePtr& ft, const ProfileFunc* pf,
                         const std::string& fname, const StmtPtr& body,
                         const LambdaExpr* l, const IDPList* lambda_ids);

	std::string BindArgs(const FuncTypePtr& ft, const IDPList* lambda_ids);

	std::string ParamDecl(const FuncTypePtr& ft, const IDPList* lambda_ids,
	                      const ProfileFunc* pf);
	const ID* FindParam(int i, const ProfileFunc* pf);

	//
	// End of methods related to declaring compiled script functions.

	// Start of methods related to generating code for representing
	// script constants as run-time values.
	// See CPPCompileConsts.cc for definitions.
	//

	void AddConstant(const ConstExpr* c);
	bool AddConstant(const ValPtr& v);

	void AddStringConstant(const ValPtr& v, std::string& const_name);
	void AddPatternConstant(const ValPtr& v, std::string& const_name);
	void AddListConstant(const ValPtr& v, std::string& const_name);
	void AddRecordConstant(const ValPtr& v, std::string& const_name);
	void AddTableConstant(const ValPtr& v, std::string& const_name);
	void AddVectorConstant(const ValPtr& v, std::string& const_name);

	std::string BuildConstant(IntrusivePtr<Obj> parent, const ValPtr& vp)
		{ return BuildConstant(parent.get(), vp); }
	std::string BuildConstant(const Obj* parent, const ValPtr& vp);

	//
	// End of methods related to generating code for script constants.

	void CompileFunc(const FuncInfo& func);
	void CompileLambda(const LambdaExpr* l, const ProfileFunc* pf);

	void GenInvokeBody(const std::string& fname, const TypePtr& t,
				const std::string& args);

	void DefineBody(const FuncTypePtr& ft, const ProfileFunc* pf,
			const std::string& fname, const StmtPtr& body,
			const IDPList* lambda_ids, FunctionFlavor flavor);

	void DeclareLocals(const ProfileFunc* func, const IDPList* lambda_ids);

	std::string BodyName(const FuncInfo& func);

	// Start of methods related to generating code for AST Stmt's.
	// See CPPCompileStmts.cc for definitions.
	//

	void GenStmt(const StmtPtr& s)	{ GenStmt(s.get()); }
	void GenStmt(const Stmt* s);
	void GenInitStmt(const InitStmt* init);
	void GenIfStmt(const IfStmt* i);
	void GenWhileStmt(const WhileStmt* w);
	void GenReturnStmt(const ReturnStmt* r);
	void GenAddStmt(const ExprStmt* es);
	void GenDeleteStmt(const ExprStmt* es);
	void GenEventStmt(const EventStmt* ev);
	void GenSwitchStmt(const SwitchStmt* sw);

	void GenForStmt(const ForStmt* f);
	void GenForOverTable(const ExprPtr& tbl, const IDPtr& value_var,
                             const IDPList* loop_vars);
	void GenForOverVector(const ExprPtr& tbl, const IDPList* loop_vars);
	void GenForOverString(const ExprPtr& str, const IDPList* loop_vars);

	//
	// End of methods related to generating code for AST Stmt's.

	// Start of methods related to generating code for AST Expr's.
	// See CPPCompileExprs.cc for definitions.
	//

	// These methods are all oriented around returning strings
	// of C++ code; they do not directly emit the code, since often
	// the caller will be embedding the result in some surrounding
	// context.  No effort is made to reduce string copying; this
	// isn't worth the hassle, as it takes just a few seconds for
	// the compiler to generate 100K+ LOC that clang will then need
	// 10s of seconds to compile, so speeding up the compiler has
	// little practical advantage.

	// The following enum's represent whether, for expressions yielding
	// native values, the end goal is to have the value in (1) native
	// form, (2) instead in ValPtr form, or (3) whichever is more
	// convenient to generate (sometimes used when the caller knows
	// that the value is non-native).
	enum GenType {
		GEN_NATIVE,
		GEN_VAL_PTR,
		GEN_DONT_CARE,
	};

	// Generate an expression for which we want the result embedded
	// in {} initializers (generally to be used in calling a function
	// where we want those values to be translated to a vector<ValPtr>).
	std::string GenExprs(const Expr* e);

	// Generate the value(s) associated with a ListExpr.  If true,
	// the "nested" parameter indicates that this list is embedded
	// within an outer list, in which case it's expanded to include
	// {}'s.  It's false if the ListExpr is at the top level, such
	// as when expanding the arguments in a CallExpr.
	std::string GenListExpr(const Expr* e, GenType gt, bool nested);

	std::string GenExpr(const ExprPtr& e, GenType gt, bool top_level = false)
		{ return GenExpr(e.get(), gt, top_level); }
	std::string GenExpr(const Expr* e, GenType gt, bool top_level = false);

	std::string GenNameExpr(const NameExpr* ne, GenType gt);
	std::string GenConstExpr(const ConstExpr* c, GenType gt);
	std::string GenIncrExpr(const Expr* e, GenType gt, bool is_incr, bool top_level);
	std::string GenCondExpr(const Expr* e, GenType gt);
	std::string GenCallExpr(const CallExpr* c, GenType gt);
	std::string GenInExpr(const Expr* e, GenType gt);
	std::string GenFieldExpr(const FieldExpr* fe, GenType gt);
	std::string GenHasFieldExpr(const HasFieldExpr* hfe, GenType gt);
	std::string GenIndexExpr(const Expr* e, GenType gt);
	std::string GenAssignExpr(const Expr* e, GenType gt, bool top_level);
	std::string GenAddToExpr(const Expr* e, GenType gt, bool top_level);
	std::string GenSizeExpr(const Expr* e, GenType gt);
	std::string GenScheduleExpr(const Expr* e);
	std::string GenLambdaExpr(const Expr* e);
	std::string GenIsExpr(const Expr* e, GenType gt);

	std::string GenArithCoerceExpr(const Expr* e, GenType gt);
	std::string GenRecordCoerceExpr(const Expr* e);
	std::string GenTableCoerceExpr(const Expr* e);
	std::string GenVectorCoerceExpr(const Expr* e);

	std::string GenRecordConstructorExpr(const Expr* e);
	std::string GenSetConstructorExpr(const Expr* e);
	std::string GenTableConstructorExpr(const Expr* e);
	std::string GenVectorConstructorExpr(const Expr* e);

	std::string GenVal(const ValPtr& v);

	std::string GenUnary(const Expr* e, GenType gt,
				const char* op, const char* vec_op = nullptr);
	std::string GenBinary(const Expr* e, GenType gt,
				const char* op, const char* vec_op = nullptr);
	std::string GenBinarySet(const Expr* e, GenType gt, const char* op);
	std::string GenBinaryString(const Expr* e, GenType gt, const char* op);
	std::string GenBinaryPattern(const Expr* e, GenType gt, const char* op);
	std::string GenBinaryAddr(const Expr* e, GenType gt, const char* op);
	std::string GenBinarySubNet(const Expr* e, GenType gt, const char* op);
	std::string GenEQ(const Expr* e, GenType gt,
				const char* op, const char* vec_op);

	std::string GenAssign(const ExprPtr& lhs, const ExprPtr& rhs,
				const std::string& rhs_native,
				const std::string& rhs_val_ptr,
				GenType gt, bool top_level);
	std::string GenDirectAssign(const ExprPtr& lhs,
				const std::string& rhs_native,
				const std::string& rhs_val_ptr,
				GenType gt, bool top_level);
	std::string GenIndexAssign(const ExprPtr& lhs, const ExprPtr& rhs,
				const std::string& rhs_val_ptr,
				GenType gt, bool top_level);
	std::string GenFieldAssign(const ExprPtr& lhs, const ExprPtr& rhs,
				const std::string& rhs_val_ptr,
				GenType gt, bool top_level);
	std::string GenListAssign(const ExprPtr& lhs, const ExprPtr& rhs);

	std::string GenVectorOp(const Expr* e, std::string op,
				const char* vec_op);
	std::string GenVectorOp(const Expr* e, std::string op1,
				std::string op2, const char* vec_op);

	// If "all_deep" is true, it means make all of the captures
	// deep copies, not just the ones that were explicitly marked
	// as deep copies.
	std::string GenLambdaClone(const LambdaExpr* l, bool all_deep);

	// Returns an initializer list for a vector of integers.
	std::string GenIntVector(const std::vector<int>& vec);

	// The following are used to generate accesses to elements of
	// extensible types.  They first check whether the type has
	// been extended (for records, beyond the field of interest);
	// if not, then the access is done directly.  If the access
	// is however to an extended element, then they indirect the
	// access through a map that is generated dynamically when
	// the compiled code.  Doing so allows the compiled code to
	// work in contexts where other extensions occur that would
	// otherwise conflict with hardwired offsets/values.
	std::string GenField(const ExprPtr& rec, int field);
	std::string GenEnum(const TypePtr& et, const ValPtr& ev);

	//
	// End of methods related to generating code for AST Expr's.

	// Start of methods related to managing script types.
	// See CPPCompileTypes.cc for definitions.
	//

	// "Native" types are those Zeek scripting types that we support
	// using low-level C++ types (like "bro_uint_t" for "count").
	// Types that we instead support using some form of ValPtr
	// representation are "non-native".
	bool IsNativeType(const TypePtr& t) const;

	// Given an expression corresponding to a native type (and with
	// the given script type 't'), converts it to the given GenType.
	std::string NativeToGT(const std::string& expr, const TypePtr& t,
	                       GenType gt);

	// Given an expression with a C++ type of generic "ValPtr", of the
	// given script type 't', converts it as needed to the given GenType.
	std::string GenericValPtrToGT(const std::string& expr, const TypePtr& t,
	                              GenType gt);

	// For a given type, generates the code necessary to initialize
	// it at run time.  The term "expand" in the method's name refers
	// to the fact that the type has already been previously declared
	// (necessary to facilitate defining recursive types), so this method
	// generates the "meat" of the type but not its original declaration.
	void ExpandTypeVar(const TypePtr& t);

	// Methods for expanding specific such types.  "tn" is the name
	// of the C++ variable used for the particular type.
	void ExpandListTypeVar(const TypePtr& t, std::string& tn);
	void ExpandRecordTypeVar(const TypePtr& t, std::string& tn);
	void ExpandEnumTypeVar(const TypePtr& t, std::string& tn);
	void ExpandTableTypeVar(const TypePtr& t, std::string& tn);
	void ExpandFuncTypeVar(const TypePtr& t, std::string& tn);

	// The following assumes we're populating a type_decl_list called "tl".
	std::string GenTypeDecl(const TypeDecl* td);

	std::string GenTypeName(const Type* t);
	std::string GenTypeName(const TypePtr& t)
		{ return GenTypeName(t.get()); }

	const Type* TypeRep(const Type* t)	{ return pfs.TypeRep(t); }
	const Type* TypeRep(const TypePtr& t)	{ return TypeRep(t.get()); }

	const char* TypeTagName(TypeTag tag) const;
	const char* TypeName(const TypePtr& t);
	const char* FullTypeName(const TypePtr& t);
	const char* TypeType(const TypePtr& t);

	void RegisterType(const TypePtr& t);
	void RegisterListType(const TypePtr& t);
	void RegisterTableType(const TypePtr& t);
	void RegisterRecordType(const TypePtr& t);
	void RegisterFuncType(const TypePtr& t);

	const char* NativeAccessor(const TypePtr& t);
	const char* IntrusiveVal(const TypePtr& t);

	//
	// End of methods related to managing script types.

	// Start of methods related to managing script type attributes.
	// See CPPCompileAttrs.cc for definitions.
	//

	void BuildAttrs(const AttributesPtr& attrs, std::string& attr_tags,
	                std::string& attr_vals);

	void GenAttrs(const AttributesPtr& attrs);
	std::string GenAttrExpr(const ExprPtr& e);

	std::string AttrsName(const AttributesPtr& attrs);
	const char* AttrName(const AttrPtr& attr);

	void RegisterAttributes(const AttributesPtr& attrs);

	//
	// End of methods related to managing script type attributes.

	std::string GenArgs(const RecordTypePtr& params, const Expr* e);

	// Start of methods related to run-time initialization.
	// See CPPCompileInits.cc for definitions.
	//

	// Generates code to construct a CallExpr that can be used to
	// evaluate the expression 'e' as an initializer (typically
	// for a record &default attribute).
	void GenInitExpr(const ExprPtr& e);

	// True if the given expression is simple enough that we can
	// generate code to evaluate it directly, and don't need to
	// create a separate function per GenInitExpr().
	bool IsSimpleInitExpr(const ExprPtr& e) const;

	// Returns the name of a function used to evaluate an
	// initialization expression.
	std::string InitExprName(const ExprPtr& e);

	// Generates code to initializes the global 'g' (with C++ name "gl")
	// to the given value *if* on start-up it doesn't already have a value.
	void GenGlobalInit(const ID* g, std::string& gl, const ValPtr& v);

	// Generates code to initialize all of the function-valued globals
	// (i.e., those pointing to lambdas).
	void GenFuncVarInits();

	// Generates the "pre-initialization" for a given type.  For
	// extensible types (records, enums, lists), these are empty
	// versions that we'll later populate.
	void GenPreInit(const Type* t);

	// The following all track that for a given object, code associated
	// with initializing it.  Multiple calls for the same object append
	// additional lines of code (the order of the calls is preserved).
	//
	// Versions with "lhs" and "rhs" arguments provide an initialization
	// of the form "lhs = rhs;", as a convenience.
	void AddInit(const IntrusivePtr<Obj>& o,
			const std::string& lhs, const std::string& rhs)
		{ AddInit(o.get(), lhs + " = " + rhs + ";"); }
	void AddInit(const Obj* o,
			const std::string& lhs, const std::string& rhs)
		{ AddInit(o, lhs + " = " + rhs + ";"); }
	void AddInit(const IntrusivePtr<Obj>& o, const std::string& init)
		{ AddInit(o.get(), init); }
	void AddInit(const Obj* o, const std::string& init);

	// We do consistency checking of initialization dependencies by
	// looking for depended-on objects have initializations.  Sometimes
	// it's unclear whether the object will actually require
	// initialization, in which case we add an empty initialization
	// for it so that the consistency-checking is happy.
	void AddInit(const IntrusivePtr<Obj>& o)	{ AddInit(o.get()); }
	void AddInit(const Obj* o);

	// Records the fact that the initialization of object o1 depends
	// on that of object o2.
	void NoteInitDependency(const IntrusivePtr<Obj>& o1,
				const IntrusivePtr<Obj>& o2)
		{ NoteInitDependency(o1.get(), o2.get()); }
	void NoteInitDependency(const IntrusivePtr<Obj>& o1, const Obj* o2)
		{ NoteInitDependency(o1.get(), o2); }
	void NoteInitDependency(const Obj* o1, const IntrusivePtr<Obj>& o2)
		{ NoteInitDependency(o1, o2.get()); }
	void NoteInitDependency(const Obj* o1, const Obj* o2);

	// Records an initialization dependency of the given object
	// on the given type, unless the type is a record.  We need
	// this notion to protect against circular dependencies in
	// the face of recursive records.
	void NoteNonRecordInitDependency(const Obj* o, const TypePtr& t)
		{
		if ( t && t->Tag() != TYPE_RECORD )
			NoteInitDependency(o, TypeRep(t));
		}
	void NoteNonRecordInitDependency(const IntrusivePtr<Obj> o, const TypePtr& t)
		{ NoteNonRecordInitDependency(o.get(), t); }

	// Analyzes the initialization dependencies to ensure that they're
	// consistent, i.e., every object that either depends on another,
	// or is itself depended on, appears in the "to_do" set.
	void CheckInitConsistency(std::unordered_set<const Obj*>& to_do);

	// Generate initializations for the items in the "to_do" set,
	// in accordance with their dependencies.
	void GenDependentInits(std::unordered_set<const Obj*>& to_do);

	// Initialize the mappings for record field offsets for field
	// accesses into regions of records that can be extensible (and
	// thus can vary at run-time to the offsets encountered during
	// compilation).
	void InitializeFieldMappings();

	// Same, but for enum types.
	void InitializeEnumMappings();

	// Generate the initialization hook for this set of compiled code.
	void GenInitHook();

	//
	// End of methods related to run-time initialization.

	void RegisterEvent(std::string ev_name);

	void StartBlock();
	void EndBlock(bool needs_semi = false);

	void Emit(const std::string& str) const
		{
		Indent();
		fprintf(write_file, "%s", str.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1,
			const std::string& arg2) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1,
			const std::string& arg2, const std::string& arg3) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(),
			arg3.c_str());
		NL();
		}

	void Emit(const std::string& fmt, const std::string& arg1,
			const std::string& arg2, const std::string& arg3,
			const std::string& arg4) const
		{
		Indent();
		fprintf(write_file, fmt.c_str(), arg1.c_str(), arg2.c_str(),
			arg3.c_str(), arg4.c_str());
		NL();
		}

	std::string GenString(const char* b, int len) const;

	std::string CPPEscape(const char* b, int len) const;
	std::string CPPEscape(const char* s) const
		{ return CPPEscape(s, strlen(s)); }

	void NL() const
		{
		fputc('\n', write_file);
		}

	void Indent() const;

	std::vector<FuncInfo>& funcs;
	ProfileFuncs& pfs;
	CPPHashManager& hm;

	FILE* write_file;
	FILE* hash_file;

	// Maps global names (not identifiers) to the names we use for them.
	std::unordered_map<std::string, std::string> globals;

	// Similar for locals, for the function currently being compiled.
	std::unordered_map<const ID*, std::string> locals;

	// Maps event names to the names we use for them.
	std::unordered_map<std::string, std::string> events;

	// Globals that correspond to variables, not functions.
	std::unordered_set<const ID*> global_vars;

	// Maps functions (not hooks or events) to upstream compiled names.
	std::unordered_map<std::string, std::string> hashed_funcs;

	// Functions that we've declared/compiled.
	std::unordered_set<std::string> compiled_funcs;

	// Maps those to their associated files - used to make add-C++ body
	// hashes distinct.
	std::unordered_map<std::string, std::string> cf_locs;

	// Maps function bodies to the names we use for them.
	std::unordered_map<const Stmt*, std::string> body_names;

	// Reverse mapping.
	std::unordered_map<std::string, const Stmt*> names_to_bodies;

	// Maps function names to hashes of bodies.
	std::unordered_map<std::string, hash_type> body_hashes;

	// Maps function names to events relevant to them.
	std::unordered_map<std::string, std::vector<std::string>> body_events;

	// Function variables that we need to create dynamically for
	// initializing globals, coupled with the name of their associated
	// constant.
	std::unordered_map<FuncVal*, std::string> func_vars;

	// Script functions that we are able to compile.  We compute
	// these ahead of time so that when compiling script function A
	// which makes a call to script function B, we know whether
	// B will indeed be compiled, or if it'll be interpreted due to
	// it including some functionality we don't currently support
	// for compilation.
	//
	// Indexed by the name of the function.
	std::unordered_set<std::string> compilable_funcs;

	// Names for lambda capture ID's.  These require a separate space
	// that incorporates the lambda's name, to deal with nested lambda's
	// that refer to the identifiers with the same name.
	std::unordered_map<const ID*, std::string> lambda_names;

	// The function's parameters.  Tracked so we don't re-declare them.
	std::unordered_set<const ID*> params;

	// Maps (non-native) constants to associated C++ globals.
	std::unordered_map<const ConstExpr*, std::string> const_exprs;

	// Maps the values of (non-native) constants to associated C++ globals.
	std::unordered_map<const Val*, std::string> const_vals;

	// Used for memory management associated with const_vals's index.
	std::vector<ValPtr> cv_indices;

	// Maps string representations of (non-native) constants to
	// associated C++ globals.
	std::unordered_map<std::string, std::string> constants;

	// Maps the same representations to the Val* associated with their
	// original creation.  This enables us to construct initialization
	// dependencies for later Val*'s that are able to reuse the same
	// constant.
	std::unordered_map<std::string, const Val*> constants_to_vals;

	// Maps an object requiring initialization to its initializers.
	std::unordered_map<const Obj*, std::vector<std::string>> obj_inits;

	// Maps an object requiring initializations to its dependencies
	// on other such objects.
	std::unordered_map<const Obj*, std::unordered_set<const Obj*>> obj_deps;

	// A list of pre-initializations (those potentially required by
	// other initializations, and that themselves have no dependencies).
	std::vector<std::string> pre_inits;

	// Maps types to indices in the global "types__CPP" array.
	CPPTracker<Type> types = {"types", &compiled_items};

	// Used to prevent analysis of mutually-referring types from
	// leading to infinite recursion.
	std::unordered_set<const Type*> processed_types;

	// Similar for attributes, so we can reconstruct record types.
	CPPTracker<Attributes> attributes = {"attrs", &compiled_items};

	// Expressions for which we need to generate initialization-time
	// code.  Currently, these are only expressions appearing in
	// attributes.
	CPPTracker<Expr> init_exprs = {"gen_init_expr", &compiled_items};

	// For record that are extended via redef's, maps fields
	// beyond the original definition to locations in the
	// global (in the compiled code) "field_mapping" array.
	//
	// So for each such record, there's a second map of
	// field-in-the-record to offset-in-field_mapping.
	std::unordered_map<const RecordType*, std::unordered_map<int, int>>
		record_field_mappings;

	// Total number of such mappings (i.e., entries in the inner maps,
	// not the outer map).
	int num_rf_mappings = 0;

	// For each entry in "field_mapping", the record and TypeDecl
	// associated with the mapping.
	std::vector<std::pair<const RecordType*, const TypeDecl*>> field_decls;

	// For enums that are extended via redef's, maps each distinct
	// value (that the compiled scripts refer to) to locations in the
	// global (in the compiled code) "enum_mapping" array.
	//
	// So for each such enum, there's a second map of
	// value-during-compilation to offset-in-enum_mapping.
	std::unordered_map<const EnumType*, std::unordered_map<int, int>>
		enum_val_mappings;

	// Total number of such mappings (i.e., entries in the inner maps,
	// not the outer map).
	int num_ev_mappings = 0;

	// For each entry in "enum_mapping", the record and name
	// associated with the mapping.
	std::vector<std::pair<const EnumType*, std::string>> enum_names;

	// If non-zero, provides a tag used for auxiliary/additional
	// compilation units.
	int addl_tag = 0;

	// If true, then we're updating the C++ base (i.e., generating
	// code meant for use by subsequently generated code).
	bool update = false;

	// Internal name of the function we're currently compiling.
	std::string body_name;

	// Return type of the function we're currently compiling.
	TypePtr ret_type = nullptr;

	// Working directory in which we're compiling.  Used to quasi-locate
	// error messages when doing test-suite "add-C++" crunches.
	std::string working_dir;

	// Whether we're parsing a hook.
	bool in_hook = false;

	// Nested level of loops/switches for which "break"'s should be
	// C++ breaks rather than a "hook" break.
	int break_level = 0;

	int block_level = 0;
};

} // zeek::detail
