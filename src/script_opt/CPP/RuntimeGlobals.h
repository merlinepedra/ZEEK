// See the file "COPYING" in the main distribution directory for copyright.

// Classes for run-time initialization and management of C++ globals used
// by the generated code.

#include "zeek/Val.h"

#pragma once

namespace zeek::detail
	{

template <class T>
class CPP_Global
	{
public:
	virtual ~CPP_Global() { }

	virtual T PreInit() const { return nullptr; }
	virtual T Generate(std::vector<T>& global_vec, int offset) const
		{ return Generate(global_vec); }
	virtual T Generate(std::vector<T>& global_vec) const
		{ return nullptr; }
	};

template <class T>
class CPP_Globals
	{
public:
	CPP_Globals(std::vector<T>& _global_vec, std::vector<std::vector<CPP_Global<T>>> _inits)
		: global_vec(_global_vec), inits(std::move(_inits))
		{
		int num_globals = 0;

		for ( const auto& cohort : inits )
			{
			cohort_offsets.push_back(num_globals);
			num_globals += cohort.size();
			}

		global_vec.reserve(num_globals);

		DoPreInits();
		}

	void InitializeCohort(int cohort)
		{
		int offset = cohort_offsets[cohort];

		for ( const auto& i : inits[cohort] )
			{
			global_vec[offset] = i.Generate(global_vec, offset);
			++offset;
			}
		}

private:
	void DoPreInits()
		{
		int offset = 0;

		for ( const auto& cohort : inits )
			for ( const auto& i : cohort )
				global_vec[offset++] = i.PreInit();
		}

	std::vector<T>& global_vec;

	// Indexed first by cohort, and then iterated over to get all
	// of the initializers for that cohort.
	std::vector<std::vector<CPP_Global<T>>> inits;

	std::vector<int> cohort_offsets;
	};

class CPP_StringConst : public CPP_Global<StringValPtr>
	{
public:
	CPP_StringConst(int _len, const char* _chars)
		: len(_len), chars(_chars) { }

	StringValPtr Generate(std::vector<StringValPtr>& global_vec) const override
		{ return make_intrusive<StringVal>(len, chars); }

private:
	int len;
	const char* chars;
	};

class CPP_PatternConst : public CPP_Global<PatternValPtr>
	{
public:
	CPP_PatternConst(const char* _pattern, int _is_case_insensitive)
		: pattern(_pattern), is_case_insensitive(_is_case_insensitive) { }

	PatternValPtr Generate(std::vector<PatternValPtr>& global_vec) const override;

private:
	const char* pattern;
	int is_case_insensitive;
	};

class CPP_AddrConst : public CPP_Global<AddrValPtr>
	{
public:
	CPP_AddrConst(const char* _init)
		: init(_init) { }

	AddrValPtr Generate(std::vector<AddrValPtr>& global_vec) const override
		{ return make_intrusive<AddrVal>(init); }

private:
	const char* init;
	};

class CPP_SubNetConst : public CPP_Global<SubNetValPtr>
	{
public:
	CPP_SubNetConst(const char* _init)
		: init(_init) { }

	SubNetValPtr Generate(std::vector<SubNetValPtr>& global_vec) const override
		{ return make_intrusive<SubNetVal>(init); }

private:
	const char* init;
	};


class CPP_AbstractType : public CPP_Global<TypePtr>
	{
public:
	CPP_AbstractType() { }
	CPP_AbstractType(std::string _name) : name(std::move(_name)) { }

protected:
	std::string name;
	};

class CPP_BaseType : public CPP_AbstractType
	{
public:
	CPP_BaseType(TypeTag t)
		: CPP_AbstractType(), tag(t) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec) const override
		{ return base_type(tag); }

private:
	TypeTag tag;
	};

class CPP_EnumType : public CPP_AbstractType
	{
public:
	CPP_EnumType(std::string _name, std::vector<std::string> _elems, std::vector<int> _vals)
		: CPP_AbstractType(_name), elems(std::move(_elems)), vals(std::move(_vals)) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec) const override;

private:
	std::vector<std::string> elems;
	std::vector<int> vals;
	};

class CPP_OpaqueType : public CPP_AbstractType
	{
public:
	CPP_OpaqueType(std::string _name) : CPP_AbstractType(_name) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec) const override
		{ return make_intrusive<OpaqueType>(name); }
	};

class CPP_TypeType : public CPP_AbstractType
	{
public:
	CPP_TypeType(int _tt_offset)
		: CPP_AbstractType(), tt_offset(_tt_offset) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec) const override
		{ return make_intrusive<TypeType>(global_vec[tt_offset]); }

private:
	int tt_offset;
	};

class CPP_VectorType : public CPP_AbstractType
	{
public:
	CPP_VectorType(int _yt_offset)
		: CPP_AbstractType(), yt_offset(_yt_offset) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec) const override
		{ return make_intrusive<VectorType>(global_vec[yt_offset]); }

private:
	int yt_offset;
	};

class CPP_TypeList : public CPP_AbstractType
	{
public:
	CPP_TypeList(std::vector<int> _types)
		: CPP_AbstractType(), types(std::move(_types)) { }

	TypePtr PreInit() const override { return make_intrusive<TypeList>(); }
	TypePtr Generate(std::vector<TypePtr>& global_vec, int offset) const override
		{
		const auto& tl = cast_intrusive<TypeList>(global_vec[offset]);

		for ( auto t : types )
			tl->Append(global_vec[t]);

		return tl;
		}

private:
	std::vector<int> types;
	};

class CPP_TableType : public CPP_AbstractType
	{
public:
	CPP_TableType(int _indices, int _yield)
		: CPP_AbstractType(), indices(std::move(_indices)), yield(_yield) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec) const override;

private:
	int indices;
	int yield;
	};

class CPP_FuncType : public CPP_AbstractType
	{
public:
	CPP_FuncType(int _params, int _yield, FunctionFlavor _flavor)
		: CPP_AbstractType(), params(std::move(_params)), yield(_yield), flavor(_flavor) { }

	TypePtr Generate(std::vector<TypePtr>& global_vec) const override;

private:
	int params;
	int yield;
	FunctionFlavor flavor;
	};


	} // zeek::detail

// get_enum_type__CPP(" + char* + ");
// get_record_type__CPP(" + char* + ");
// get_record_type__CPP(nullptr);
// 
// make_intrusive<FuncType>(cast_intrusive<RecordType>(TYPEINDEX), TYPEINDEX|nullpt
// r, FLAVOR);
