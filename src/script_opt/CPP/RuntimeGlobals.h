// See the file "COPYING" in the main distribution directory for copyright.

// Classes for run-time initialization and management of C++ globals used
// by the generated code.

#include "zeek/Expr.h"
#include "zeek/module_util.h"
#include "zeek/script_opt/CPP/RuntimeInit.h"

#pragma once

namespace zeek::detail
	{

using FileValPtr = IntrusivePtr<FileVal>;
using FuncValPtr = IntrusivePtr<FuncVal>;


class InitsManager;

class CPP_AbstractGlobalAccessor
	{
public:
	virtual ~CPP_AbstractGlobalAccessor() {}
	virtual ValPtr Get(int index) const { return nullptr; }
	};

struct CPP_ValElem
	{
	CPP_ValElem(TypeTag _tag, int _offset)
		: tag(_tag), offset(_offset) { }

	TypeTag tag;
	int offset;
	};


class InitsManager
	{
public:
	InitsManager(
		std::vector<CPP_ValElem>& _const_vals,
		std::map<TypeTag, std::shared_ptr<CPP_AbstractGlobalAccessor>>& _consts,
		std::vector<std::vector<int>>& _indices,
		std::vector<const char*>& _strings,
		std::vector<p_hash_type>& _hashes,
		std::vector<TypePtr>& _types,
		std::vector<AttributesPtr>& _attributes,
		std::vector<AttrPtr>& _attrs,
		std::vector<CallExprPtr>& _call_exprs)
		:
		const_vals(_const_vals),
		consts(_consts),
		indices(_indices),
		strings(_strings),
		hashes(_hashes),
		types(_types),
		attributes(_attributes),
		attrs(_attrs),
		call_exprs(_call_exprs)
		{ }

	ValPtr ConstVals(int offset) const
		{
		auto& cv = const_vals[offset];
		return Consts(cv.tag, cv.offset);
		}
	ValPtr Consts(TypeTag tag, int index) const { return consts[tag]->Get(index); }

	const std::vector<int>& Indices(int offset) const { return indices[offset]; }
	const char* Strings(int offset) const { return strings[offset]; }
	const p_hash_type Hashes(int offset) const { return hashes[offset]; }
	const TypePtr& Types(int offset) const { return types[offset]; }
	const AttributesPtr& Attributes(int offset) const { return attributes[offset]; }
	const AttrPtr& Attrs(int offset) const { return attrs[offset]; }
	const CallExprPtr& CallExprs(int offset) const { return call_exprs[offset]; }

private:
	std::vector<CPP_ValElem>& const_vals;
	std::map<TypeTag, std::shared_ptr<CPP_AbstractGlobalAccessor>>& consts;
	std::vector<std::vector<int>>& indices;
	std::vector<const char*>& strings;
	std::vector<p_hash_type>& hashes;
	std::vector<TypePtr>& types;
	std::vector<AttributesPtr>& attributes;
	std::vector<AttrPtr>& attrs;
	std::vector<CallExprPtr>& call_exprs;
	};

template <class T>
class CPP_Global
	{
public:
	virtual ~CPP_Global() { }

	virtual void PreInit(InitsManager* im, std::vector<T>& global_vec, int offset) const { }
	virtual void Generate(InitsManager* im, std::vector<T>& global_vec, int offset) const
		{ }
	};

template <class T>
class CPP_MiscGlobals
	{
public:
	CPP_MiscGlobals(std::vector<T>& _global_vec, int _offsets_set, std::vector<std::vector<std::shared_ptr<CPP_Global<T>>>> _inits)
		: global_vec(_global_vec), offsets_set(_offsets_set), inits(std::move(_inits))
		{
		int num_globals = 0;

		for ( const auto& cohort : inits )
			num_globals += cohort.size();

		global_vec.resize(num_globals);
		}

	void InitializeCohort(InitsManager* im, int cohort)
		{
		if ( cohort == 0 )
			DoPreInits(im);

		auto& offsets_vec = im->Indices(offsets_set);
		auto& co = inits[cohort];
		auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
		for ( auto i = 0U; i < co.size(); ++i )
			co[i]->Generate(im, global_vec, cohort_offsets[i]);
		}

private:
	void DoPreInits(InitsManager* im)
		{
		auto& offsets_vec = im->Indices(offsets_set);
		int cohort = 0;
		for ( const auto& co : inits )
			{
			auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
			for ( auto i = 0U; i < co.size(); ++i )
				co[i]->PreInit(im, global_vec, cohort_offsets[i]);
			++cohort;
			}
		}

	std::vector<T>& global_vec;
	int offsets_set;

	// Indexed first by cohort, and then iterated over to get all
	// of the initializers for that cohort.
	std::vector<std::vector<std::shared_ptr<CPP_Global<T>>>> inits;
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

using ValElemVec = std::vector<int>;


template <class T>
class CPP_Globals
	{
public:
	CPP_Globals(std::vector<T>& _global_vec, int _offsets_set, std::vector<std::vector<ValElemVec>> _inits);

	void InitializeCohort(InitsManager* im, int cohort);

protected:
	virtual void PreInit(InitsManager* im) { }

	// Note, in the following we pass in the global_vec even though
	// the method will have direct access to it, because we want to
	// use overloading to dispatch to custom generation for different
	// types of values.
	void Generate(InitsManager* im, std::vector<EnumValPtr>& gvec, int offset, ValElemVec& init_vals);
	void Generate(InitsManager* im, std::vector<StringValPtr>& gvec, int offset, ValElemVec& init_vals);
	void Generate(InitsManager* im, std::vector<PatternValPtr>& gvec, int offset, ValElemVec& init_vals);
	void Generate(InitsManager* im, std::vector<ListValPtr>& gvec, int offset, ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<VectorValPtr>& gvec, int offset, ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<RecordValPtr>& gvec, int offset, ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<TableValPtr>& gvec, int offset, ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<FileValPtr>& gvec, int offset, ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<FuncValPtr>& gvec, int offset, ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<AttrPtr>& gvec, int offset, ValElemVec& init_vals) const;
	void Generate(InitsManager* im, std::vector<AttributesPtr>& gvec, int offset, ValElemVec& init_vals) const;

	virtual void Generate(InitsManager* im, std::vector<TypePtr>& gvec, int offset, ValElemVec& init_vals) const
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

class CPP_TypeGlobals : public CPP_Globals<TypePtr>
	{
public:
	CPP_TypeGlobals(std::vector<TypePtr>& _global_vec, int _offsets_set, std::vector<std::vector<ValElemVec>> _inits)
		: CPP_Globals<TypePtr>(_global_vec, _offsets_set, _inits)
		{ }

protected:
	void PreInit(InitsManager* im) override;
	void PreInit(InitsManager* im, int offset, ValElemVec& init_vals);

	void Generate(InitsManager* im, std::vector<TypePtr>& gvec, int offset, ValElemVec& init_vals) const override;

	TypePtr BuildEnumType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildOpaqueType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildTypeType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildVectorType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildTypeList(InitsManager* im, ValElemVec& init_vals, int offset) const;
	TypePtr BuildTableType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildFuncType(InitsManager* im, ValElemVec& init_vals) const;
	TypePtr BuildRecordType(InitsManager* im, ValElemVec& init_vals, int offset) const;
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

	void InitializeCohort(InitsManager* im, int cohort)
		{
		ASSERT(cohort == 0);
		auto& offsets_vec = im->Indices(offsets_set);
		auto& cohort_offsets = im->Indices(offsets_vec[cohort]);
		for ( auto i = 0U; i < inits.size(); ++i )
			InitElem(im, cohort_offsets[i], i);
		}

protected:
	virtual void InitElem(InitsManager* im, int offset, int index)
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

	void InitElem(InitsManager* /* im */, int offset, int index) override
		{
		this->global_vec[offset] = make_intrusive<T3>(this->inits[index]);
		}
	};

template <class T1, typename T2, class T3>
class CPP_BasicConst : public CPP_Global<T1>
	{
public:
	CPP_BasicConst(T2 _v) : CPP_Global<T1>(), v(_v) { }

	void Generate(InitsManager* /* im */, std::vector<T1>& global_vec, int offset) const override
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

	void InitElem(InitsManager* im, int offset, int index) override
		{
		auto s = im->Strings(this->inits[index]);
		this->global_vec[offset] = make_intrusive<AddrVal>(s);
		}
	};

class CPP_SubNetConsts : public CPP_AbstractBasicConsts<SubNetValPtr, int>
	{
public:
	CPP_SubNetConsts(std::vector<SubNetValPtr>& _global_vec, int _offsets_set, std::vector<int> _inits)
		: CPP_AbstractBasicConsts<SubNetValPtr, int>(_global_vec, _offsets_set, std::move(_inits))
		{ }

	void InitElem(InitsManager* im, int offset, int index) override
		{
		auto s = im->Strings(this->inits[index]);
		this->global_vec[offset] = make_intrusive<SubNetVal>(s);
		}
	};


class CPP_GlobalInit : public CPP_Global<void*>
	{
public:
	CPP_GlobalInit(IDPtr& _global, const char* _name, int _type, int _attrs, int _val, bool _exported)
		: CPP_Global<void*>(), global(_global), name(_name), type(_type), attrs(_attrs), val(_val), exported(_exported)
		{ }

	void Generate(InitsManager* im, std::vector<void*>& /* global_vec */, int /* offset */) const override;

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

	void Generate(InitsManager* /* im */, std::vector<CallExprPtr>& global_vec, int offset) const override
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

	void Generate(InitsManager* im, std::vector<void*>& global_vec, int offset) const override
		{
		auto l = make_intrusive<T>(name);
		auto& ft = im->Types(func_type);
		register_lambda__CPP(l, h, name, ft, has_captures);
		}

protected:
	const char* name;
	int func_type;
	p_hash_type h;
	bool has_captures;
	};


class CPP_FieldMapping
	{
public:
	CPP_FieldMapping(int _rec, std::string _field_name, int _field_type, int _field_attrs)
		: rec(_rec), field_name(std::move(_field_name)), field_type(_field_type), field_attrs(_field_attrs)
		{ }

	int ComputeOffset(InitsManager* im) const;

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

	int ComputeOffset(InitsManager* im) const;

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


extern void generate_indices_set(int* inits, std::vector<std::vector<int>>& indices_set);


	} // zeek::detail
