// See the file "COPYING" in the main distribution directory for copyright.

// Classes for run-time initialization and management of C++ globals used
// by the generated code.

#include "zeek/Expr.h"
#include "zeek/script_opt/CPP/RuntimeInit.h"

#pragma once

namespace zeek::detail
	{

using BoolValPtr = IntrusivePtr<BoolVal>;
using IntValPtr = IntrusivePtr<IntVal>;
using CountValPtr = IntrusivePtr<CountVal>;
using DoubleValPtr = IntrusivePtr<DoubleVal>;
using TimeValPtr = IntrusivePtr<TimeVal>;
using IntervalValPtr = IntrusivePtr<IntervalVal>;
using FileValPtr = IntrusivePtr<FileVal>;

extern std::vector<BoolValPtr> CPP__Bool__;
extern std::vector<IntValPtr> CPP__Int__;
extern std::vector<CountValPtr> CPP__Count__;
extern std::vector<EnumValPtr> CPP__Enum__;
extern std::vector<DoubleValPtr> CPP__Double__;
extern std::vector<TimeValPtr> CPP__Time__;
extern std::vector<IntervalValPtr> CPP__Interval__;
extern std::vector<StringValPtr> CPP__String__;
extern std::vector<PatternValPtr> CPP__Pattern__;
extern std::vector<AddrValPtr> CPP__Addr__;
extern std::vector<SubNetValPtr> CPP__SubNet__;
extern std::vector<PortValPtr> CPP__Port__;
extern std::vector<ListValPtr> CPP__List__;
extern std::vector<RecordValPtr> CPP__Record__;
extern std::vector<TableValPtr> CPP__Table__;
extern std::vector<VectorValPtr> CPP__Vector__;
extern std::vector<FuncValPtr> CPP__Func__;
extern std::vector<FileValPtr> CPP__File__;

extern std::vector<TypePtr> CPP__Type__;
extern std::vector<AttrPtr> CPP__Attr__;
extern std::vector<AttributesPtr> CPP__Attributes__;
extern std::vector<CallExprPtr> CPP__CallExpr__;
extern std::vector<void*> CPP__LambdaRegistration__;
extern std::vector<void*> CPP__GlobalID__;

extern std::vector<std::vector<int>> CPP__Indices__;
extern std::vector<const char*> CPP__Strings__;

template <class T>
class CPP_Global
	{
public:
	virtual ~CPP_Global() { }

	virtual void PreInit(std::vector<T>& global_vec, int offset) const { }
	virtual void Generate(std::vector<T>& global_vec, int offset) const
		{ }
	};

template <class T>
class CPP_Globals
	{
public:
	CPP_Globals(std::vector<T>& _global_vec, int _offsets_set, std::vector<std::vector<std::shared_ptr<CPP_Global<T>>>> _inits)
		: global_vec(_global_vec), offsets_set(_offsets_set), inits(std::move(_inits))
		{
		int num_globals = 0;

		for ( const auto& cohort : inits )
			num_globals += cohort.size();

		global_vec.resize(num_globals);
		}

	void InitializeCohort(int cohort)
		{
		if ( cohort == 0 )
			DoPreInits();

		std::vector<int>& offsets_vec = CPP__Indices__[offsets_set];
		auto& co = inits[cohort];
		std::vector<int>& cohort_offsets = CPP__Indices__[offsets_vec[cohort]];
		for ( auto i = 0U; i < co.size(); ++i )
			co[i]->Generate(global_vec, cohort_offsets[i]);
		}

private:
	void DoPreInits()
		{
		std::vector<int>& offsets_vec = CPP__Indices__[offsets_set];
		int cohort = 0;
		for ( const auto& co : inits )
			{
			std::vector<int>& cohort_offsets = CPP__Indices__[offsets_vec[cohort]];
			for ( auto i = 0U; i < co.size(); ++i )
				co[i]->PreInit(global_vec, cohort_offsets[i]);
			++cohort;
			}
		}

	std::vector<T>& global_vec;
	int offsets_set;

	// Indexed first by cohort, and then iterated over to get all
	// of the initializers for that cohort.
	std::vector<std::vector<std::shared_ptr<CPP_Global<T>>>> inits;
	};

template <class T1, typename T2>
class CPP_AbstractBasicConsts
	{
public:
	CPP_AbstractBasicConsts(std::vector<T1>& _global_vec, int _offsets_set, std::vector<T2> _inits)
		: global_vec(_global_vec), offsets_set(_offsets_set), inits(std::move(_inits))
		{
		global_vec.resize(inits.size());
		}

	void InitializeCohort(int cohort)
		{
		ASSERT(cohort == 0);
		std::vector<int>& offsets_vec = CPP__Indices__[offsets_set];
		std::vector<int>& cohort_offsets = CPP__Indices__[offsets_vec[cohort]];
		for ( auto i = 0U; i < inits.size(); ++i )
			InitElem(cohort_offsets[i], i);
		}

protected:
	virtual void InitElem(int offset, int index)
		{
		ASSERT(0);
		}

protected:
	std::vector<T1>& global_vec;
	int offsets_set;
	std::vector<T2> inits;
	};

template <class T1, typename T2, class T3>
class CPP_BasicConsts : public CPP_AbstractBasicConsts<T1, T2>
	{
public:
	CPP_BasicConsts(std::vector<T1>& _global_vec, int _offsets_set, std::vector<T2> _inits)
		: CPP_AbstractBasicConsts<T1, T2>(_global_vec, _offsets_set, std::move(_inits))
		{
		}

	void InitElem(int offset, int index) override
		{
		this->global_vec[offset] = make_intrusive<T3>(this->inits[index]);
		}
	};

template <class T1, typename T2, class T3>
class CPP_BasicConst : public CPP_Global<T1>
	{
public:
	CPP_BasicConst(T2 _v) : CPP_Global<T1>(), v(_v) { }

	void Generate(std::vector<T1>& global_vec, int offset) const override
		{ this->global_vec[offset] = make_intrusive<T3>(v); }

private:
	T2 v;
	};

class CPP_AddrConsts : public CPP_AbstractBasicConsts<AddrValPtr, int>
	{
public:
	CPP_AddrConsts(std::vector<AddrValPtr>& _global_vec, int _offsets_set, std::vector<int> _inits)
		: CPP_AbstractBasicConsts<AddrValPtr, int>(_global_vec, _offsets_set, std::move(_inits))
		{ }

	void InitElem(int offset, int index) override
		{
		this->global_vec[offset] = make_intrusive<AddrVal>(CPP__Strings__[this->inits[index]]);
		}
	};

class CPP_SubNetConsts : public CPP_AbstractBasicConsts<SubNetValPtr, int>
	{
public:
	CPP_SubNetConsts(std::vector<SubNetValPtr>& _global_vec, int _offsets_set, std::vector<int> _inits)
		: CPP_AbstractBasicConsts<SubNetValPtr, int>(_global_vec, _offsets_set, std::move(_inits))
		{ }

	void InitElem(int offset, int index) override
		{
		this->global_vec[offset] = make_intrusive<SubNetVal>(CPP__Strings__[this->inits[index]]);
		}
	};

class CPP_StringConst : public CPP_Global<StringValPtr>
	{
public:
	CPP_StringConst(int _len, const char* _chars)
		: CPP_Global<StringValPtr>(), len(_len), chars(_chars) { }

	void Generate(std::vector<StringValPtr>& global_vec, int offset) const override
		{ global_vec[offset] = make_intrusive<StringVal>(len, chars); }

private:
	int len;
	const char* chars;
	};

class CPP_PatternConst : public CPP_Global<PatternValPtr>
	{
public:
	CPP_PatternConst(const char* _pattern, int _is_case_insensitive)
		: CPP_Global<PatternValPtr>(), pattern(_pattern), is_case_insensitive(_is_case_insensitive) { }

	void Generate(std::vector<PatternValPtr>& global_vec, int offset) const override;

private:
	const char* pattern;
	int is_case_insensitive;
	};

class CPP_EnumConst : public CPP_Global<EnumValPtr>
	{
public:
	CPP_EnumConst(int type, int val)
		: CPP_Global<EnumValPtr>(), e_type(type), e_val(val) { }

	void Generate(std::vector<EnumValPtr>& global_vec, int offset) const override
		{ global_vec[offset] = make_enum__CPP(CPP__Type__[e_type], e_val); }

private:
	int e_type;
	int e_val;
	};

class CPP_AbstractValElem
	{
public:
	CPP_AbstractValElem() {}
	virtual ~CPP_AbstractValElem() {}

	virtual ValPtr Get() const { return nullptr; }
	};

template <class T>
class CPP_ValElem : public CPP_AbstractValElem
	{
public:
	CPP_ValElem(std::vector<T>& _vec, int _offset)
		: vec(_vec), offset(_offset) { }

	ValPtr Get() const override
		{ return offset >= 0 ? vec[offset] : nullptr; }

private:
	std::vector<T>& vec;
	int offset;
	};

using ValElemPtr = std::shared_ptr<CPP_AbstractValElem>;
using ValElemVec = std::vector<ValElemPtr>;

class CPP_ListConst : public CPP_Global<ListValPtr>
	{
public:
	CPP_ListConst(ValElemVec _vals)
		: CPP_Global<ListValPtr>(), vals(std::move(_vals)) { }

	void Generate(std::vector<ListValPtr>& global_vec, int offset) const override;

private:
	ValElemVec vals;
	};

class CPP_VectorConst : public CPP_Global<VectorValPtr>
	{
public:
	CPP_VectorConst(int type, ValElemVec vals)
		: CPP_Global<VectorValPtr>(), v_type(type), v_vals(std::move(vals)) { }

	void Generate(std::vector<VectorValPtr>& global_vec, int offset) const override;

private:
	int v_type;
	ValElemVec v_vals;
	};

class CPP_RecordConst : public CPP_Global<RecordValPtr>
	{
public:
	CPP_RecordConst(int type, ValElemVec vals)
		: CPP_Global<RecordValPtr>(), r_type(type), r_vals(std::move(vals)) { }

	void Generate(std::vector<RecordValPtr>& global_vec, int offset) const override;

private:
	int r_type;
	ValElemVec r_vals;
	};

class CPP_TableConst : public CPP_Global<TableValPtr>
	{
public:
	CPP_TableConst(int type, ValElemVec indices, ValElemVec vals)
		: CPP_Global<TableValPtr>(), t_type(type), t_indices(std::move(indices)), t_vals(std::move(vals)) { }

	void Generate(std::vector<TableValPtr>& global_vec, int offset) const override;

private:
	int t_type;
	ValElemVec t_indices;
	ValElemVec t_vals;
	};

class CPP_FuncConst : public CPP_Global<FuncValPtr>
	{
public:
	CPP_FuncConst(const char* _name, int _type, std::vector<p_hash_type> _hashes)
		: CPP_Global<FuncValPtr>(), name(_name), type(_type), hashes(std::move(_hashes)) { }

	void Generate(std::vector<FuncValPtr>& global_vec, int offset) const override
		{ global_vec[offset] = lookup_func__CPP(name, hashes, CPP__Type__[type]); }

private:
	std::string name;
	int type;
	std::vector<p_hash_type> hashes;
	};


class CPP_AbstractAttrExpr
	{
public:
	CPP_AbstractAttrExpr() {}
	virtual ~CPP_AbstractAttrExpr() {}

	virtual ExprPtr Build() const { return nullptr; }
	};

using AbstractAttrPtr = std::shared_ptr<CPP_AbstractAttrExpr>;

class CPP_ConstAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_ConstAttrExpr(ValElemPtr _v) : v(std::move(_v)) {}

	ExprPtr Build() const override
		{ return make_intrusive<ConstExpr>(v->Get()); }

private:
	ValElemPtr v;
	};

class CPP_NameAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_NameAttrExpr(IDPtr& _id_addr) : id_addr(_id_addr) {}

	ExprPtr Build() const override
		{ return make_intrusive<NameExpr>(id_addr); }

private:
	IDPtr& id_addr;
	};

class CPP_RecordAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_RecordAttrExpr(int _type) : type(_type) {}

	ExprPtr Build() const override;

private:
	int type;
	};

class CPP_CallAttrExpr : public CPP_AbstractAttrExpr
	{
public:
	CPP_CallAttrExpr(int _call) : call(_call) {}

	ExprPtr Build() const override { return CPP__CallExpr__[call]; }

private:
	int call;
	};

class CPP_Attr : public CPP_Global<AttrPtr>
	{
public:
	CPP_Attr(AttrTag t, AbstractAttrPtr _expr)
		: CPP_Global<AttrPtr>(), tag(t), expr(std::move(_expr)) { }

	void Generate(std::vector<AttrPtr>& global_vec, int offset) const override
		{ global_vec[offset] =  make_intrusive<Attr>(tag, expr->Build()); }

private:
	AttrTag tag;
	AbstractAttrPtr expr;
	};

class CPP_Attrs : public CPP_Global<AttributesPtr>
	{
public:
	CPP_Attrs(std::vector<int> _attrs)
		: CPP_Global<AttributesPtr>(), attrs(std::move(_attrs)) { }

	void Generate(std::vector<AttributesPtr>& global_vec, int offset) const override;

private:
	std::vector<int> attrs;
	};


class CPP_AbstractType : public CPP_Global<TypePtr>
	{
public:
	CPP_AbstractType() : CPP_Global<TypePtr>() { }
	CPP_AbstractType(std::string _name)
		: CPP_Global<TypePtr>(), name(std::move(_name)) { }

	void Generate(std::vector<TypePtr>& global_vec, int offset) const override
		{
		DoGenerate(global_vec, offset);
		if ( ! name.empty() )
			register_type__CPP(global_vec[offset], name);
		}

protected:
	virtual void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const
		{ global_vec[offset] = nullptr; }

	std::string name;
	};

class CPP_BaseType : public CPP_AbstractType
	{
public:
	CPP_BaseType(TypeTag t)
		: CPP_AbstractType(), tag(t) { }

	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override
		{ global_vec[offset] = base_type(tag); }

private:
	TypeTag tag;
	};

class CPP_EnumType : public CPP_AbstractType
	{
public:
	CPP_EnumType(std::string _name, std::vector<const char*> _elems, std::vector<int> _vals)
		: CPP_AbstractType(_name), elems(std::move(_elems)), vals(std::move(_vals)) { }

	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override;

private:
	std::vector<const char*> elems;
	std::vector<int> vals;
	};

class CPP_OpaqueType : public CPP_AbstractType
	{
public:
	CPP_OpaqueType(std::string _name)
		: CPP_AbstractType(_name) { }

	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override
		{ global_vec[offset] = make_intrusive<OpaqueType>(name); }
	};

class CPP_TypeType : public CPP_AbstractType
	{
public:
	CPP_TypeType(int _tt_offset)
		: CPP_AbstractType(), tt_offset(_tt_offset) { }

	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override
		{ global_vec[offset] = make_intrusive<TypeType>(global_vec[tt_offset]); }

private:
	int tt_offset;
	};

class CPP_VectorType : public CPP_AbstractType
	{
public:
	CPP_VectorType(int _yt_offset)
		: CPP_AbstractType(), yt_offset(_yt_offset) { }

	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override
		{ global_vec[offset] = make_intrusive<VectorType>(global_vec[yt_offset]); }

private:
	int yt_offset;
	};

class CPP_TypeList : public CPP_AbstractType
	{
public:
	CPP_TypeList(std::vector<int> _types)
		: CPP_AbstractType(), types(std::move(_types)) { }

	void PreInit(std::vector<TypePtr>& global_vec, int offset) const override
		{ global_vec[offset] = make_intrusive<TypeList>(); }
	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override
		{
		const auto& tl = cast_intrusive<TypeList>(global_vec[offset]);

		for ( auto t : types )
			tl->Append(global_vec[t]);
		}

private:
	std::vector<int> types;
	};

class CPP_TableType : public CPP_AbstractType
	{
public:
	CPP_TableType(int _indices, int _yield)
		: CPP_AbstractType(), indices(std::move(_indices)), yield(_yield) { }

	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override;

private:
	int indices;
	int yield;
	};

class CPP_FuncType : public CPP_AbstractType
	{
public:
	CPP_FuncType(int _params, int _yield, FunctionFlavor _flavor)
		: CPP_AbstractType(), params(std::move(_params)), yield(_yield), flavor(_flavor) { }

	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override;

private:
	int params;
	int yield;
	FunctionFlavor flavor;
	};

class CPP_RecordType : public CPP_AbstractType
	{
public:
	CPP_RecordType(std::vector<const char*> _field_names, std::vector<int> _field_types, std::vector<int> _field_attrs)
		: CPP_AbstractType(), field_names(std::move(_field_names)), field_types(_field_types), field_attrs(_field_attrs) { }

	void PreInit(std::vector<TypePtr>& global_vec, int offset) const override;
	void DoGenerate(std::vector<TypePtr>& global_vec, int offset) const override;

private:
	std::vector<const char*> field_names;
	std::vector<int> field_types;
	std::vector<int> field_attrs;
	};


class CPP_FieldMapping
	{
public:
	CPP_FieldMapping(int _rec, std::string _field_name, int _field_type, int _field_attrs)
		: rec(_rec), field_name(std::move(_field_name)), field_type(_field_type), field_attrs(_field_attrs)
		{ }

	int ComputeOffset() const;

private:
	int rec;
	std::string field_name;
	int field_type;
	int field_attrs;
	};


class CPP_EnumMapping
	{
public:
	CPP_EnumMapping(int _e_type, std::string _e_name)
		: e_type(_e_type), e_name(std::move(_e_name))
		{ }

	int ComputeOffset() const;

private:
	int e_type;
	std::string e_name;
	};


class CPP_RegisterBody
	{
public:
	CPP_RegisterBody(std::string _func_name, void* _func, int _type_signature, int _priority, p_hash_type _h, std::vector<std::string> _events)
		: func_name(std::move(_func_name)), func(_func), type_signature(_type_signature), priority(_priority), h(_h), events(std::move(_events))
		{ }
	virtual ~CPP_RegisterBody() { }

	virtual void Register() const { }

	std::string func_name;
	void* func;
	int type_signature;
	int priority;
	p_hash_type h;
	std::vector<std::string> events;
	};

class CPP_LookupBiF
	{
public:
	CPP_LookupBiF(zeek::Func*& _bif_func, std::string _bif_name)
		: bif_func(_bif_func), bif_name(std::move(_bif_name))
		{ }

	void ResolveBiF() const { bif_func = lookup_bif__CPP(bif_name.c_str()); }

protected:
	zeek::Func*& bif_func;
	std::string bif_name;
	};

class CPP_GlobalInit : public CPP_Global<void*>
	{
public:
	CPP_GlobalInit(IDPtr& _global, const char* _name, int _type, int _attrs, std::shared_ptr<CPP_AbstractValElem> _val, bool _exported)
		: CPP_Global<void*>(), global(_global), name(_name), type(_type), attrs(_attrs), val(std::move(_val)), exported(_exported)
		{ }

	void Generate(std::vector<void*>& /* global_vec */, int /* offset */) const override;

protected:
	IDPtr& global;
	const char* name;
	int type;
	int attrs;
	std::shared_ptr<CPP_AbstractValElem> val;
	bool exported;
	};

class CPP_AbstractCallExprInit : public CPP_Global<CallExprPtr>
	{
public:
	CPP_AbstractCallExprInit()
		: CPP_Global<CallExprPtr>() {}
	};

template <class T>
class CPP_CallExprInit : public CPP_AbstractCallExprInit
	{
public:
	CPP_CallExprInit(CallExprPtr& _e_var)
		: CPP_AbstractCallExprInit(), e_var(_e_var)
		{ }

	void Generate(std::vector<CallExprPtr>& global_vec, int offset) const override
		{
		auto wrapper_class = make_intrusive<T>();
		auto func_val = make_intrusive<FuncVal>(wrapper_class);
		auto func_expr = make_intrusive<ConstExpr>(func_val);
		auto empty_args = make_intrusive<ListExpr>();

		e_var = make_intrusive<CallExpr>(func_expr, empty_args);
		global_vec[offset] = e_var;
		}

protected:
	CallExprPtr& e_var;
	};

class CPP_AbstractLambdaRegistration : public CPP_Global<void*>
	{
public:
	CPP_AbstractLambdaRegistration()
		: CPP_Global<void*>() { }
	};

template <class T>
class CPP_LambdaRegistration : public CPP_AbstractLambdaRegistration
	{
public:
	CPP_LambdaRegistration(const char* _name, int _func_type, p_hash_type _h, bool _has_captures)
		: CPP_AbstractLambdaRegistration(), name(_name), func_type(_func_type), h(_h), has_captures(_has_captures)
		{ }

	void Generate(std::vector<void*>& global_vec, int offset) const override
		{
		auto l = make_intrusive<T>(name);
		auto& ft = CPP__Type__[func_type];
		register_lambda__CPP(l, h, name, ft, has_captures);
		}

protected:
	const char* name;
	int func_type;
	p_hash_type h;
	bool has_captures;
	};


extern void generate_indices_set(int* inits, std::vector<std::vector<int>>& indices_set);


	} // zeek::detail
