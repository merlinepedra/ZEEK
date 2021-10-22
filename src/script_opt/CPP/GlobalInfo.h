// See the file "COPYING" in the main distribution directory for copyright.

// Classes for tracking information for initializing C++ globals used by the
// generated code.

#include "zeek/Val.h"
#include "zeek/File.h"
#include "zeek/script_opt/ProfileFunc.h"

#pragma once

namespace zeek::detail
	{

class CPPCompile;

// Abstract class for tracking the information about a single global.
// This might be a stand-alone global, or a global that's ultimately
// instantiated as part of a CPP_Globals object.
class CPP_GlobalInfo;

// Abstract class for tracking the information about a set of globals,
// each of which is an element of a CPP_Globals object.
class CPP_GlobalsInfo
	{
public:
	CPP_GlobalsInfo(std::string _tag, std::string type)
		: tag(std::move(_tag))
		{
		base_name = std::string("CPP__") + tag + "__";
		CPP_type = tag + type;
		}

	virtual ~CPP_GlobalsInfo() { }

	std::string InitializersName() const { return base_name + "init"; }
	const std::string& GlobalsName() const { return base_name; }

	std::string Name(int index) const;
	std::string NextName() const { return Name(Size()); }

	int Size() const { return size; }
	int MaxCohort() const { return static_cast<int>(instances.size()) - 1; }
	int CohortSize(int c) const
		{ return c > MaxCohort() ? 0 : instances[c].size(); }

	const std::string& Tag() const { return tag; }
	const std::string& CPPType() const { return CPP_type; }
	void SetCPPType(std::string ct) { CPP_type = std::move(ct); }

	virtual void AddInstance(std::shared_ptr<CPP_GlobalInfo> g);
	virtual std::string Declare() const;
	virtual void GenerateInitializers(CPPCompile* c);

protected:
	virtual std::string GlobalsType() const
		{ return std::string("CPP_Globals<") + CPPType() + ">"; }

	virtual void BuildCohort(CPPCompile* c, std::vector<std::shared_ptr<CPP_GlobalInfo>>& cohort);

	int size = 0;	// total number of globals

	// The outer vector is indexed by initialization cohort.
	std::vector<std::vector<std::shared_ptr<CPP_GlobalInfo>>> instances;

	// Tag used to distinguish a particular set of constants.
	std::string tag;

	// C++ name for this set of constants.
	std::string base_name;

	// C++ type associated with a single instance of these constants.
	std::string CPP_type;
	};

class CPP_BasicConstGlobalsInfo : public CPP_GlobalsInfo
	{
public:
	CPP_BasicConstGlobalsInfo(std::string _tag, std::string type, std::string c_type)
		: CPP_GlobalsInfo(std::move(_tag), std::move(type))
		{
		CPP_type2 = std::string("CPP_BasicConsts<") + CPP_type + ", " + c_type + ", " + tag + "Val>";
		}

	void BuildCohort(CPPCompile* c, std::vector<std::shared_ptr<CPP_GlobalInfo>>& cohort) override;

	std::string GlobalsType() const override { return CPP_type2; }

private:
	std::string CPP_type2;
	};

class CPP_GlobalInfo
	{
public:
	// Constructor used for stand-alone globals.  The second
	// argument specifies the core of the associated type.
	CPP_GlobalInfo(std::string _name, std::string _type)
		: name(std::move(_name)), type(std::move(_type))
		{ }

	// Constructor used for a global that will be part of a CPP_GlobalsInfo
	// object.  The rest of its initialization will be done by
	// CPP_GlobalsInfo::AddInstance.
	CPP_GlobalInfo() { }

	virtual ~CPP_GlobalInfo() { }

	int Offset() const { return offset; }
	void SetOffset(const CPP_GlobalsInfo* _gls, int _offset)
		{
		gls = _gls;
		offset = _offset;
		}

	// Returns the name that should be used for referring to this
	// global in the generated code.
	std::string Name() const { return gls ? gls->Name(offset) : name; }

	const CPP_GlobalsInfo* MainGlobal() { return gls; }

	int InitCohort() const { return init_cohort; }

	// Returns a C++ declaration for this global.  Not used if
	// the global is part of a CPP_Globals object.
	std::string Declare() const { return type + " " + Name() + ";"; }

	// Returns the type used for this initializer.
	virtual std::string InitializerType() const = 0;

	// Returns values used for creating this global, one element
	// per constructor parameter.
	virtual void InitializerVals(std::vector<std::string>& ivs) const = 0;

protected:
	std::string ValElem(CPPCompile* c, ValPtr v);

	std::string name;
	std::string type;

	// By default, globals have no dependencies on other globals
	// being first initialized.  Those that do must increase this
	// value in their constructors.
	int init_cohort = 0;

	const CPP_GlobalsInfo* gls = nullptr;
	int offset = -1;	// offset for CPP_GlobalsInfo, if non-nil
	};


class BasicConstInfo : public CPP_GlobalInfo
	{
public:
	BasicConstInfo(std:: string _name, std::string _cpp_type, std::string _val)
		: name(std::move(_name)), cpp_type(std::move(_cpp_type)), val(std::move(_val)) { }

	std::string InitializerType() const override
		{
		return std::string("CPP_BasicConst<") + name + "ValPtr, " + cpp_type + ", " + name + "Val>";
		}

	void InitializerVals(std::vector<std::string>& ivs) const override
		{ ivs.emplace_back(val); }

private:
	std::string name;
	std::string cpp_type;
	std::string val;
	};

class DescConstInfo : public CPP_GlobalInfo
	{
public:
	DescConstInfo(std::string _name, ValPtr v);

	std::string InitializerType() const override;
	void InitializerVals(std::vector<std::string>& ivs) const override
		{ ivs.emplace_back(init); }

private:
	std::string name;
	std::string init;
	};

class EnumConstInfo : public CPP_GlobalInfo
	{
public:
	EnumConstInfo(CPPCompile* c, ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_EnumConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(e_type));
		ivs.emplace_back(std::to_string(e_val));
		}

private:
	int e_type;
	int e_val;
	};

class StringConstInfo : public CPP_GlobalInfo
	{
public:
	StringConstInfo(ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_StringConst"; }
	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(len));
		ivs.emplace_back(rep);
		}

private:
	std::string rep;
	int len;
	};

class PatternConstInfo : public CPP_GlobalInfo
	{
public:
	PatternConstInfo(ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_PatternConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(pattern);
		ivs.emplace_back(std::to_string(is_case_insensitive));
		}

private:
	std::string pattern;
	int is_case_insensitive;
	};

class PortConstInfo : public CPP_GlobalInfo
	{
public:
	PortConstInfo(ValPtr v) : p(static_cast<UnsignedValImplementation*>(v->AsPortVal())->Get()) { }

	std::string InitializerType() const override
		{ return "CPP_PortConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(p));
		}

private:
	bro_uint_t p;
	};

class CompoundConstInfo : public CPP_GlobalInfo
	{
public:
	CompoundConstInfo(CPPCompile* c, ValPtr v);
	CompoundConstInfo(CPPCompile* _c) : c(_c) { type = 0; }

protected:
	CPPCompile* c;
	int type;
	std::string vals;
	};

class ListConstInfo : public CompoundConstInfo
	{
public:
	ListConstInfo(CPPCompile* c, ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_ListConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::string("ValElemVec({ ") + vals + "})");
		}
	};

class VectorConstInfo : public CompoundConstInfo
	{
public:
	VectorConstInfo(CPPCompile* c, ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_VectorConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(type));
		ivs.emplace_back(std::string("ValElemVec({ ") + vals + "})");
		}
	};

class RecordConstInfo : public CompoundConstInfo
	{
public:
	RecordConstInfo(CPPCompile* c, ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_RecordConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(type));
		ivs.emplace_back(std::string("ValElemVec({ ") + vals + "})");
		}
	};

class TableConstInfo : public CompoundConstInfo
	{
public:
	TableConstInfo(CPPCompile* c, ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_TableConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::to_string(type));
		ivs.emplace_back(std::string("ValElemVec({ ") + indices + "})");
		ivs.emplace_back(std::string("ValElemVec({ ") + vals + "})");
		}

private:
	std::string indices;
	};

class FileConstInfo : public CompoundConstInfo
	{
public:
	FileConstInfo(CPPCompile* c, ValPtr v)
		: CompoundConstInfo(c, v), name(cast_intrusive<FileVal>(v)->Get()->Name())
		{ }

	std::string InitializerType() const override
		{ return "CPP_FileConst"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::string("\"") + name + "\"");
		}

private:
	std::string name;
	};

class FuncConstInfo : public CompoundConstInfo
	{
public:
	FuncConstInfo(CPPCompile* _c, ValPtr v);

	std::string InitializerType() const override
		{ return "CPP_FuncConst"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	FuncVal* fv;
	};


class AttrInfo : public CPP_GlobalInfo
	{
public:
	AttrInfo(CPPCompile* c, const AttrPtr& attr);

	std::string InitializerType() const override
		{ return "CPP_Attr"; }
	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(tag);
		ivs.emplace_back(std::string("std::make_shared<") + e_init_type + ">(" + e_init_args + ")");
		}

protected:
	std::string tag;
	std::string e_init_type;
	std::string e_init_args;
	};

class AttrsInfo : public CPP_GlobalInfo
	{
public:
	AttrsInfo(CPPCompile* c, const AttributesPtr& attrs);

	std::string InitializerType() const override
		{ return "CPP_Attrs"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

protected:
	std::vector<int> attrs;
	};


class GlobalInitInfo : public CPP_GlobalInfo
	{
public:
	GlobalInitInfo(CPPCompile* c, const ID* g, std::string CPP_name);

	std::string InitializerType() const override
		{ return "CPP_GlobalInit"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

protected:
	std::string Zeek_name;
	std::string CPP_name;
	int type;
	int attrs;
	std::string val;
	bool exported;
	};


class CallExprInitInfo : public CPP_GlobalInfo
	{
public:
	CallExprInitInfo(CPPCompile* c, ExprPtr e, std::string e_name, std::string wrapper_class);

	std::string InitializerType() const override
		{ return std::string("CPP_CallExprInit<") + wrapper_class + ">"; }
	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(e_name);
		}

	const ExprPtr& GetExpr() const { return e; }
	const std::string& Name() const { return e_name; }
	const std::string& WrapperClass() const { return wrapper_class; }

protected:
	ExprPtr e;
	std::string e_name;
	std::string wrapper_class;
	};


class LambdaRegistrationInfo : public CPP_GlobalInfo
	{
public:
	LambdaRegistrationInfo(CPPCompile* c, std::string name, FuncTypePtr ft, std::string wrapper_class, p_hash_type h, bool has_captures);

	std::string InitializerType() const override
		{ return std::string("CPP_LambdaRegistration<") + wrapper_class + ">"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

protected:
	std::string name;
	int func_type;
	std::string wrapper_class;
	p_hash_type h;
	bool has_captures;
	};


class AbstractTypeInfo : public CPP_GlobalInfo
	{
public:
	AbstractTypeInfo(TypePtr _t) : CPP_GlobalInfo(), t(std::move(_t)) { }

protected:
	TypePtr t;
	};

class BaseTypeInfo : public AbstractTypeInfo
	{
public:
	BaseTypeInfo(TypePtr _t) : AbstractTypeInfo(std::move(_t)) { }

	std::string InitializerType() const override
		{ return "CPP_BaseType"; }

	void InitializerVals(std::vector<std::string>& ivs) const override;
	};

class EnumTypeInfo : public AbstractTypeInfo
	{
public:
	EnumTypeInfo(TypePtr _t) : AbstractTypeInfo(std::move(_t)) { }

	std::string InitializerType() const override
		{ return "CPP_EnumType"; }

	void InitializerVals(std::vector<std::string>& ivs) const override;
	};

class OpaqueTypeInfo : public AbstractTypeInfo
	{
public:
	OpaqueTypeInfo(TypePtr _t) : AbstractTypeInfo(std::move(_t)) { }

	std::string InitializerType() const override
		{ return "CPP_OpaqueType"; }

	void InitializerVals(std::vector<std::string>& ivs) const override
		{
		ivs.emplace_back(std::string("\"") + t->GetName() + "\"");
		}
	};


class CompoundTypeInfo : public AbstractTypeInfo
	{
public:
	CompoundTypeInfo(CPPCompile* _c, TypePtr _t)
		: AbstractTypeInfo(_t), c(_c) { }

protected:
	CPPCompile* c;
	};

class TypeTypeInfo : public CompoundTypeInfo
	{
public:
	TypeTypeInfo(CPPCompile* c, TypePtr _t);

	std::string InitializerType() const override
		{ return "CPP_TypeType"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	TypePtr tt;
	};

class VectorTypeInfo : public CompoundTypeInfo
	{
public:
	VectorTypeInfo(CPPCompile* c, TypePtr _t);

	std::string InitializerType() const override
		{ return "CPP_VectorType"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	TypePtr yield;
	};

class ListTypeInfo : public CompoundTypeInfo
	{
public:
	ListTypeInfo(CPPCompile* c, TypePtr _t);

	std::string InitializerType() const override
		{ return "CPP_TypeList"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	const std::vector<TypePtr>& types;
	};

class TableTypeInfo : public CompoundTypeInfo
	{
public:
	TableTypeInfo(CPPCompile* c, TypePtr _t);

	std::string InitializerType() const override
		{ return "CPP_TableType"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	int indices;
	TypePtr yield;
	};

class FuncTypeInfo : public CompoundTypeInfo
	{
public:
	FuncTypeInfo(CPPCompile* c, TypePtr _t);

	std::string InitializerType() const override
		{ return "CPP_FuncType"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	FunctionFlavor flavor;
	TypePtr params;
	TypePtr yield;
	};

class RecordTypeInfo : public CompoundTypeInfo
	{
public:
	RecordTypeInfo(CPPCompile* c, TypePtr _t);

	std::string InitializerType() const override
		{ return "CPP_RecordType"; }
	void InitializerVals(std::vector<std::string>& ivs) const override;

private:
	std::vector<std::string> field_names;
	std::vector<TypePtr> field_types;
	std::vector<int> field_attrs;
	};


	} // zeek::detail
