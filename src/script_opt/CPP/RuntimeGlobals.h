// See the file "COPYING" in the main distribution directory for copyright.

// Classes for run-time initialization and management of C++ globals used
// by the generated code.

#include "zeek/Expr.h"
#include "zeek/module_util.h"
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
extern std::vector<p_hash_type> CPP__Hashes__;

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


class CPP_AbstractGlobalAccessor
	{
public:
	virtual ~CPP_AbstractGlobalAccessor() {}
	virtual ValPtr Get(int index) const { return nullptr; }
	};

template <class T>
class CPP_GlobalAccessor : public CPP_AbstractGlobalAccessor
	{
public:
	CPP_GlobalAccessor(std::vector<T>& _global_vec) : global_vec(_global_vec) {}

	ValPtr Get(int index) const override { return global_vec[index]; }

private:
	std::vector<T>& global_vec;
	};

extern std::map<TypeTag, std::shared_ptr<CPP_AbstractGlobalAccessor>> CPP__Consts__;


class CPP_ValElem
	{
public:
	CPP_ValElem(TypeTag _tag, int _offset)
		: tag(_tag), offset(_offset) { }

	ValPtr Get() const
		{ return offset >= 0 ? CPP__Consts__[tag]->Get(offset) : nullptr; }

private:
	TypeTag tag;
	int offset;
	};

extern std::vector<CPP_ValElem> CPP__ConstVals__;

using ValElemVec = std::vector<int>;


template <class T>
class CPP_GlobalsNEW
	{
public:
	CPP_GlobalsNEW(std::vector<T>& _global_vec, int _offsets_set, std::vector<std::vector<ValElemVec>> _inits)
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
			PreInit();

		std::vector<int>& offsets_vec = CPP__Indices__[offsets_set];
		auto& co = inits[cohort];
		std::vector<int>& cohort_offsets = CPP__Indices__[offsets_vec[cohort]];
		for ( auto i = 0U; i < co.size(); ++i )
			Generate(global_vec, cohort_offsets[i], co[i]);
		}

protected:
	virtual void PreInit() { }

	void Generate(std::vector<EnumValPtr>& gvec, int offset, ValElemVec& init_vals)
		{
		auto& e_type = CPP__Type__[init_vals[0]];
		int val = init_vals[1];
		gvec[offset] = make_enum__CPP(e_type, val);
		}

	void Generate(std::vector<StringValPtr>& gvec, int offset, ValElemVec& init_vals)
		{
		auto chars = CPP__Strings__[init_vals[0]];
		int len = init_vals[1];
		gvec[offset] = make_intrusive<StringVal>(len, chars);
		}

	void Generate(std::vector<PatternValPtr>& gvec, int offset, ValElemVec& init_vals)
		{
		auto re = new RE_Matcher(CPP__Strings__[init_vals[0]]);
		if ( init_vals[1] )
			re->MakeCaseInsensitive();

		re->Compile();

		gvec[offset] = make_intrusive<PatternVal>(re);
		}

	void Generate(std::vector<ListValPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto n = init_vals.size();
		auto i = 0U;

		auto l = make_intrusive<ListVal>(TYPE_ANY);

		while ( i < n )
			l->Append(CPP__ConstVals__[init_vals[i++]].Get());

		global_vec[offset] = l;
		}

	void Generate(std::vector<VectorValPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto n = init_vals.size();
		auto i = 0U;
		auto t = init_vals[i++];

		auto vt = cast_intrusive<VectorType>(CPP__Type__[t]);
		auto vv = make_intrusive<VectorVal>(vt);

		while ( i < n )
			vv->Append(CPP__ConstVals__[init_vals[i++]].Get());

		global_vec[offset] = vv;
		}

	void Generate(std::vector<RecordValPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto n = init_vals.size();
		auto i = 0U;
		auto t = init_vals[i++];

		auto rt = cast_intrusive<RecordType>(CPP__Type__[t]);
		auto rv = make_intrusive<RecordVal>(rt);

		while ( i < n )
			{
			auto v = init_vals[i];
			if ( v >= 0 )
				rv->Assign(i - 1, CPP__ConstVals__[v].Get());
			++i;
			}

		global_vec[offset] = rv;
		}

	void Generate(std::vector<TableValPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto n = init_vals.size();
		auto i = 0U;
		auto t = init_vals[i++];

		auto tt = cast_intrusive<TableType>(CPP__Type__[t]);
		auto tv = make_intrusive<TableVal>(tt);

		while ( i < n )
			{
			auto index = CPP__ConstVals__[init_vals[i++]].Get();
			auto v = init_vals[i++];
			auto value = v >= 0 ? CPP__ConstVals__[v].Get() : nullptr;
			tv->Assign(index, value);
			}

		global_vec[offset] = tv;
		}

	void Generate(std::vector<FileValPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto n = init_vals.size();
		auto i = 0U;
		auto t = init_vals[i++];	// not used

		auto fn = CPP__Strings__[init_vals[i++]];
		auto fv = make_intrusive<FileVal>(fn, "w");

		global_vec[offset] = fv;
		}

	void Generate(std::vector<FuncValPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto n = init_vals.size();
		auto i = 0U;
		auto t = init_vals[i++];

		auto fn = CPP__Strings__[init_vals[i++]];

		std::vector<p_hash_type> hashes;

		while ( i < n )
			hashes.push_back(CPP__Hashes__[init_vals[i++]]);

		global_vec[offset] = lookup_func__CPP(fn, hashes, CPP__Type__[t]);
		}

	virtual void Generate(std::vector<AttrPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto tag = static_cast<AttrTag>(init_vals[0]);
		auto ae_tag = static_cast<AttrExprType>(init_vals[1]);

		ExprPtr e;
		auto e_arg = init_vals[2];

		switch ( ae_tag )
			{
			case AE_NONE:
				break;

			case AE_CONST:
				e = make_intrusive<ConstExpr>(CPP__ConstVals__[e_arg].Get());
				break;

			case AE_NAME:
				{
				auto name = CPP__Strings__[e_arg];
				auto gl = lookup_ID(name, GLOBAL_MODULE_NAME, false, false, false);
				ASSERT(gl);
				e = make_intrusive<NameExpr>(gl);
				break;
				}

			case AE_RECORD:
				{
				auto t = CPP__Type__[e_arg];
				auto rt = cast_intrusive<RecordType>(t);
				auto empty_vals = make_intrusive<ListExpr>();
				auto construct = make_intrusive<RecordConstructorExpr>(empty_vals);
				e = make_intrusive<RecordCoerceExpr>(construct, rt);
				break;
				}

			case AE_CALL:
				e = CPP__CallExpr__[e_arg];
				break;
			}

		global_vec[offset] = make_intrusive<Attr>(tag, e);
		}

	virtual void Generate(std::vector<AttributesPtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		auto n = init_vals.size();
		auto i = 0U;

		std::vector<AttrPtr> a_list;
		while ( i < n )
			a_list.emplace_back(CPP__Attr__[init_vals[i++]]);

		global_vec[offset] = make_intrusive<Attributes>(a_list, nullptr, false, false);
		}

	virtual void Generate(std::vector<TypePtr>& global_vec, int offset, ValElemVec& init_vals) const
		{
		ASSERT(0);
		}

protected:
	std::vector<T>& global_vec;
	int offsets_set;

	// Indexed first by cohort, and then iterated over to get all
	// of the initializers for that cohort.
	std::vector<std::vector<std::vector<int>>> inits;
	};

class CPP_TypeGlobals : public CPP_GlobalsNEW<TypePtr>
	{
public:
	CPP_TypeGlobals(std::vector<TypePtr>& _global_vec, int _offsets_set, std::vector<std::vector<ValElemVec>> _inits)
		: CPP_GlobalsNEW<TypePtr>(_global_vec, _offsets_set, _inits)
		{ }

protected:
	void PreInit() override
		{
		std::vector<int>& offsets_vec = CPP__Indices__[offsets_set];
		for ( auto cohort = 0U; cohort < offsets_vec.size(); ++cohort )
			{
			auto& co = inits[cohort];
			std::vector<int>& cohort_offsets = CPP__Indices__[offsets_vec[cohort]];
			for ( auto i = 0U; i < co.size(); ++i )
				PreInit(cohort_offsets[i], co[i]);
			}
		}

	void PreInit(int offset, ValElemVec& init_vals)
		{
		auto tag = static_cast<TypeTag>(init_vals[0]);

		if ( tag == TYPE_LIST )
			global_vec[offset] = make_intrusive<TypeList>();

		else if ( tag == TYPE_RECORD )
			{
			auto name = CPP__Strings__[init_vals[1]];
			if ( name[0] )
				global_vec[offset] = get_record_type__CPP(name);
			else
				global_vec[offset] = get_record_type__CPP(nullptr);
			}
		}

	void Generate(std::vector<TypePtr>& gvec, int offset, ValElemVec& init_vals) const override
		{
		auto tag = static_cast<TypeTag>(init_vals[0]);
		TypePtr t;
		switch ( tag )
			{
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
			case TYPE_SUBNET:
			case TYPE_FILE:
				t = base_type(tag);
				break;

			case TYPE_ENUM:
				t = BuildEnumType(init_vals);
				break;

			case TYPE_OPAQUE:
				t = BuildOpaqueType(init_vals);
				break;

			case TYPE_TYPE:
				t = BuildTypeType(init_vals);
				break;

			case TYPE_VECTOR:
				t = BuildVectorType(init_vals);
				break;

			case TYPE_LIST:
				t = BuildTypeList(init_vals, offset);
				break;

			case TYPE_TABLE:
				t = BuildTableType(init_vals);
				break;

			case TYPE_FUNC:
				t = BuildFuncType(init_vals);
				break;

			case TYPE_RECORD:
				t = BuildRecordType(init_vals, offset);
				break;

			default:
				ASSERT(0);
			}

		gvec[offset] = t;
		}

	TypePtr BuildEnumType(ValElemVec& init_vals) const
		{
		auto& name = CPP__Strings__[init_vals[1]];
		auto et = get_enum_type__CPP(name);

		if ( et->Names().empty() )
			{
			auto n = init_vals.size();
			auto i = 2U;

			while ( i < n )
				{
				auto e_name = CPP__Strings__[init_vals[i++]];
				auto e_val = init_vals[i++];
				et->AddNameInternal(e_name, e_val);
				}
			}

		return et;
		}

	TypePtr BuildOpaqueType(ValElemVec& init_vals) const
		{
		auto& name = CPP__Strings__[init_vals[1]];
		return make_intrusive<OpaqueType>(name);
		}

	TypePtr BuildTypeType(ValElemVec& init_vals) const
		{
		auto& t = CPP__Type__[init_vals[1]];
		return make_intrusive<TypeType>(t);
		}

	TypePtr BuildVectorType(ValElemVec& init_vals) const
		{
		auto& t = CPP__Type__[init_vals[1]];
		return make_intrusive<VectorType>(t);
		}

	TypePtr BuildTypeList(ValElemVec& init_vals, int offset) const
		{
		const auto& tl = cast_intrusive<TypeList>(global_vec[offset]);

		auto n = init_vals.size();
		auto i = 1U;

		while ( i < n )
			tl->Append(CPP__Type__[init_vals[i++]]);

		return tl;
		}

	TypePtr BuildTableType(ValElemVec& init_vals) const
		{
		auto index = cast_intrusive<TypeList>(CPP__Type__[init_vals[1]]);
		auto yield_i = init_vals[2];
		auto yield = yield_i >= 0 ? CPP__Type__[yield_i] : nullptr;

		return make_intrusive<TableType>(index, yield);
		}

	TypePtr BuildFuncType(ValElemVec& init_vals) const
		{
		auto p = cast_intrusive<RecordType>(CPP__Type__[init_vals[1]]);
		auto yield_i = init_vals[2];
		auto flavor = static_cast<FunctionFlavor>(init_vals[3]);

		TypePtr y;

		if ( yield_i >= 0 )
			y = CPP__Type__[yield_i];

		else if ( flavor == FUNC_FLAVOR_FUNCTION || flavor == FUNC_FLAVOR_HOOK )
			y = base_type(TYPE_VOID);

		return make_intrusive<FuncType>(p, y, flavor);
		}

	TypePtr BuildRecordType(ValElemVec& init_vals, int offset) const
		{
		auto r = cast_intrusive<RecordType>(global_vec[offset]);
		ASSERT(r);

		if ( r->NumFields() == 0 )
			{
			type_decl_list tl;

			auto n = init_vals.size();
			auto i = 2U;

			while ( i < n )
				{
				auto id = util::copy_string(CPP__Strings__[init_vals[i++]]);
				auto type = CPP__Type__[init_vals[i++]];
				auto attrs_i = init_vals[i++];

				AttributesPtr attrs;
				if ( attrs_i >= 0 )
					attrs = CPP__Attributes__[attrs_i];

				tl.append(new TypeDecl(id, type, attrs));
				}

			r->AddFieldsDirectly(tl);
			}

		return r;
		}
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
	CPP_GlobalInit(IDPtr& _global, const char* _name, int _type, int _attrs, int _val, bool _exported)
		: CPP_Global<void*>(), global(_global), name(_name), type(_type), attrs(_attrs), val(_val), exported(_exported)
		{ }

	void Generate(std::vector<void*>& /* global_vec */, int /* offset */) const override;

protected:
	IDPtr& global;
	const char* name;
	int type;
	int attrs;
	int val;
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
