// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/script_opt/ScriptOpt.h"


namespace zeek::detail {

class CPPCompile {
public:
	CPPCompile(std::vector<FuncInfo>& _funcs) : funcs(_funcs) { }

	void CompileTo(FILE* f);

private:
	void GenProlog();
	void GenEpilog();

	bool IsCompilable(const FuncInfo& func)
		{ return func.Func()->Flavor() == FUNC_FLAVOR_FUNCTION; }

	void CreateGlobals(const FuncInfo& func);
	void AddBiF(const Func* b);
	void AddGlobal(const char* g, const char* suffix);
	void AddConstant(const ConstExpr* c);

	void DeclareFunc(const FuncInfo& func);
	void CompileFunc(const FuncInfo& func);

	void DeclareSubclass(const FuncInfo& func, const std::string& fname);
	void GenInvokeBody(const TypePtr& t, const char* args);

	void DefineBody(const FuncInfo& func, const std::string& fname);

	std::string BindArgs(const FuncTypePtr& ft);
	std::string ValToNative(std::string v, const TypePtr& t);

	void DeclareLocals(const FuncInfo& func);

	void GenStmt(const StmtPtr& s)	{ GenStmt(s.get()); }
	void GenStmt(const Stmt* s);

	std::string GenExpr(const ExprPtr& e)	{ return GenExpr(e.get()); }
	std::string GenExpr(const Expr* e);

	// True if the given expression corresponds to a ValPtr value
	// rather than a Val* value or a native type.
	bool ExprIsValPtr(const ExprPtr& e) const
		{ return ExprIsValPtr(e.get()); }
	bool ExprIsValPtr(const Expr* e) const;

	std::string GenValExpr(const ExprPtr& e)
		{ return GenValExpr(e.get()); }
	std::string GenValExpr(const Expr* e);

	std::string GenArgs(const Expr* e);

	std::string GenUnary(const Expr* e, const char* op);
	std::string GenBinary(const Expr* e, const char* op);
	std::string GenBinarySet(const Expr* e, const char* op);
	std::string GenBinaryString(const Expr* e, const char* op);
	std::string GenBinaryPattern(const Expr* e, const char* op);
	std::string GenBinaryAddr(const Expr* e, const char* op);
	std::string GenBinarySubNet(const Expr* e, const char* op);
	std::string GenEQ(const Expr* e, const char* op);

	void GenInitExpr(const ExprPtr& e);
	std::string InitExprName(const ExprPtr& e);

	void GenAttrs(const AttributesPtr& attrs);
	std::string AttrsName(const AttributesPtr& attrs);
	const char* AttrName(const AttrPtr& attr);

	void GenType(const TypePtr& t);
	std::string GeneratedTypeName(const TypePtr& t);

	void GenExpr(const ExprPtr& e) const
		{ return GenExpr(e.get()); }
	void GenExpr(const Expr* e) const;

	const char* TypeTagName(TypeTag tag) const;

	const char* IDName(const ID& id)	{ return IDName(&id); }
	const char* IDName(const IDPtr& id)	{ return IDName(id.get()); }
	const char* IDName(const ID* id)	{ return IDNameStr(id).c_str(); }
	const std::string& IDNameStr(const ID* id) const;

	std::string ParamDecl(const FuncTypePtr& ft);

	bool IsNativeType(const TypePtr& t) const;
	const char* FullTypeName(const TypePtr& t);
	const char* TypeName(const TypePtr& t);
	const char* TypeType(const TypePtr& t);
	int TypeIndex(const TypePtr& t);
	void RecordAttributes(const AttributesPtr& attrs);

	const char* NativeVal(const TypePtr& t);
	const char* NativeAccessor(const TypePtr& t);

	void StartBlock();
	void EndBlock(bool needs_semi = false);

	void Emit(const char* str) const
		{
		Indent();
		fprintf(write_file, "%s\n", str);
		}

	void Emit(const char* fmt, const char* arg) const
		{
		Indent();
		fprintf(write_file, fmt, arg);
		NL();
		}

	void Emit(const char* fmt, const char* arg1, const char* arg2) const
		{
		Indent();
		fprintf(write_file, fmt, arg1, arg2);
		NL();
		}

	void Emit(const char* fmt, const char* arg1, const char* arg2,
			const char* arg3) const
		{
		Indent();
		fprintf(write_file, fmt, arg1, arg2, arg3);
		NL();
		}

	void Emit(const char* fmt, const char* arg1, const char* arg2,
			const char* arg3, const char* arg4) const
		{
		Indent();
		fprintf(write_file, fmt, arg1, arg2, arg3, arg4);
		NL();
		}

	std::string GlobalName(const char* g, const char* suffix)
		{
		return Canonicalize(g) + "__" + suffix;
		}

	std::string LocalName(const ID* l) const;

	std::string Canonicalize(const char* name) const;

	std::string Fmt(int d)
		{
		char d_s[64];
		snprintf(d_s, sizeof d_s, "%d", d);
		return std::string(d_s);
		}

	std::string Fmt(bro_uint_t u)
		{
		char d_s[64];
		snprintf(d_s, sizeof d_s, "%llu", u);
		return std::string(d_s);
		}

	std::string Fmt(double d)
		{
		char d_s[64];
		snprintf(d_s, sizeof d_s, "%lf", d);
		return std::string(d_s);
		}

	void NL() const
		{
		fputc('\n', write_file);
		}

	void Indent() const;

	std::vector<FuncInfo>& funcs;
	FILE* write_file;

	// Maps global names (not identifiers) to the names we use for them.
	std::unordered_map<std::string, std::string> globals;

	// Globals that correspond to variables, not functions.
	std::unordered_set<const ID*> global_vars;

	// Functions that we've declared/compiled.
	std::unordered_set<std::string> compiled_funcs;

	// Same for locals, for the function currently being compiled.
	std::unordered_map<const ID*, std::string> locals;

	// The function's parameters.  Tracked so we don't re-declare them.
	std::unordered_set<std::string> params;

	// Maps (non-native) constants to associated C++ globals.
	std::unordered_map<const ConstExpr*, std::string> const_exprs;

	// Maps string representations of (non-native) constants to
	// associated C++ globals.
	std::unordered_map<std::string, std::string> constants;

	// Maps types to indices in the global "types__CPP" array.  We also
	// track the types in a vector so we can generate "types__CPP" in the
	// epilog.
	std::unordered_map<const Type*, int> type_map;
	std::vector<TypePtr> types;

	// Similar for attributes, so we can reconstruct record types.
	std::unordered_map<const Attributes*, int> attrs_map;
	std::vector<AttributesPtr> attributes;

	// Expressions for which we need to generate initialization-time
	// code.  Currently, these are only expressions appearing in
	// attributes.
	std::unordered_map<const Expr*, int> init_expr_map;
	std::vector<ExprPtr> init_exprs;

	// Maps function bodies to the names we use for them.
	std::unordered_map<const Stmt*, std::string> body_names;

	int block_level = 0;
};

} // zeek::detail
