// See the file "COPYING" in the main distribution directory for copyright.

// Classes for run-time initialization and management of C++ globals used
// by the generated code.

#include "zeek/Val.h"

#pragma once

namespace zeek::detail
	{

extern std::vector<TypePtr> CPP__TypeConst__;

template <class T>
class CPP_Global
	{
public:
	virtual ~CPP_Global() { }
	virtual T Generate() const { return nullptr; }
	};

template <class T>
class CPP_Globals
	{
public:
	CPP_Globals(std::vector<std::vector<CPP_Global<T>>> _inits)
		: inits(std::move(_inits))
		{ }

	void InitializeCohort(std::vector<T>& global_vec, int cohort)
		{
		for ( const auto& i : inits[cohort] )
			global_vec.emplace_back(i.Generate());
		}

private:
	// Indexed first by cohort, and then iterated over to get all
	// of the initializers for that cohort.
	std::vector<std::vector<CPP_Global<T>>> inits;
	};

class CPP_StringConst : public CPP_Global<StringValPtr>
	{
public:
	CPP_StringConst(int _len, const char* _chars)
		: len(_len), chars(_chars) { }

	StringValPtr Generate() const override
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

	PatternValPtr Generate() const override;

private:
	const char* pattern;
	int is_case_insensitive;
	};

class CPP_AddrConst : public CPP_Global<AddrValPtr>
	{
public:
	CPP_AddrConst(const char* _init)
		: init(_init) { }

	AddrValPtr Generate() const override
		{ return make_intrusive<AddrVal>(init); }

private:
	const char* init;
	};

class CPP_SubNetConst : public CPP_Global<SubNetValPtr>
	{
public:
	CPP_SubNetConst(const char* _init)
		: init(_init) { }

	SubNetValPtr Generate() const override
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

	TypePtr Generate() const override
		{ return base_type(tag); }

private:
	TypeTag tag;
	};

class CPP_EnumType : public CPP_AbstractType
	{
public:
	CPP_EnumType(std::string _name, std::vector<std::string> _elems, std::vector<int> _vals)
		: CPP_AbstractType(_name), elems(std::move(_elems)), vals(std::move(_vals)) { }

	TypePtr Generate() const override;

private:
	std::vector<std::string> elems;
	std::vector<int> vals;
	};

class CPP_OpaqueType : public CPP_AbstractType
	{
public:
	CPP_OpaqueType(std::string _name) : CPP_AbstractType(_name) { }

	TypePtr Generate() const override
		{ return make_intrusive<OpaqueType>(name); }
	};

class CPP_TypeType : public CPP_AbstractType
	{
public:
	CPP_TypeType(int _tt_offset)
		: CPP_AbstractType(), tt_offset(_tt_offset) { }

	TypePtr Generate() const override
		{ return make_intrusive<TypeType>(CPP__TypeConst__[tt_offset]); }

private:
	int tt_offset;
	};


	} // zeek::detail

// base_type(char*)
// get_enum_type__CPP(" + char* + ");
// get_record_type__CPP(" + char* + ");
// get_record_type__CPP(nullptr);
// make_intrusive<SubNetType>();
// make_intrusive<TypeList>();
// make_intrusive<OpaqueType>(" char* + ");
// 
// make_intrusive<FileType>(TYPEINDEX);
// make_intrusive<FuncType>(cast_intrusive<RecordType>(TYPEINDEX), TYPEINDEX|nullpt
// r, FLAVOR);
// make_intrusive<SetType>(cast_intrusive<TypeList>(TYPEINDEX), nullptr);
// make_intrusive<TableType>(cast_intrusive<TypeList>(TYPEINDEX), TYPEINDEX);
// make_intrusive<TypeType>(TYPEINDEX);
// make_intrusive<VectorType>(TYPEINDEX);
