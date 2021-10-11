// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/Compile.h"

using namespace std;

namespace zeek::detail
	{

string CPP_GlobalsInfo::Name(int index) const
	{
	return base_name + "[" + Fmt(index) + "]";
	}

void CPP_GlobalsInfo::AddInstance(shared_ptr<CPP_GlobalInfo> g)
	{
	auto init_cohort = g->InitCohort();

	if ( static_cast<int>(instances.size()) <= init_cohort )
		instances.resize(init_cohort + 1);

	g->SetOffset(this, size++);

	instances[init_cohort].push_back(move(g));
	}

string CPP_GlobalsInfo::Declare() const
	{
	return string("std::vector<") + CPPType() + "> " + base_name + ";";
	}

void CPP_GlobalsInfo::GenerateInitializers(CPPCompile* cc)
	{
	cc->NL();

	cc->Emit("CPP_Globals<%s> %s = CPP_Globals<%s>(%s, ", CPPType(),
	         InitializersName(), CPPType(), base_name);

	cc->IndentUp();
	cc->Emit("{");

	for ( auto& cohort : instances )
		{
		cc->Emit("{");

		for ( auto& c : cohort )
			cc->Emit("%s,", c->Initializer());

		cc->Emit("},");
		}

	cc->Emit("}");
	cc->IndentDown();
	cc->Emit(");");
	}


StringConstantInfo::StringConstantInfo(ValPtr v)
	: CPP_GlobalInfo()
	{
	auto s = v->AsString();
	const char* b = (const char*)(s->Bytes());

	len = s->Len();
	rep = CPPEscape(b, len);
	}

string StringConstantInfo::Initializer() const
	{
	return string("CPP_StringConst(") + Fmt(len) + ", " + rep + ")";
	}

PatternConstantInfo::PatternConstantInfo(ValPtr v)
	: CPP_GlobalInfo()
	{
	auto re = v->AsPatternVal()->Get();
	pattern = CPPEscape(re->OrigText());
	is_case_insensitive = re->IsCaseInsensitive();
	}

string PatternConstantInfo::Initializer() const
	{
	return string("CPP_PatternConst(") + pattern + ", " + Fmt(is_case_insensitive) + ")";
	}

DescConstantInfo::DescConstantInfo(ValPtr v)
	: CPP_GlobalInfo()
	{
	ODesc d;
	v->Describe(&d);
	init = d.Description();
	}

string DescConstantInfo::Initializer() const
	{
	return string("CPP_") + gls->Tag() + "Const(\"" + init + "\")";
	}


string BaseTypeInfo::Initializer() const
	{
	return string("CPP_BaseType(") + CPPCompile::TypeTagName(t->Tag()) + ")";
	}

string EnumTypeInfo::Initializer() const
	{
	string elem_list, val_list;
	auto et = t->AsEnumType();

	for ( const auto& name_pair : et->Names() )
		{
		elem_list += string("\"") + name_pair.first + "\", ";
		val_list += Fmt(int(name_pair.second)) + ", ";
		}

	return string("CPP_EnumType(\"") + t->GetName() + "\", { " + elem_list + "}, { " + val_list + "})";
	}

string OpaqueTypeInfo::Initializer() const
	{
	return string("CPP_OpaqueType(\"") + t->GetName() + "\")";
	}

TypeTypeInfo::TypeTypeInfo(CPPCompile* c, TypePtr _t)
	: AbstractTypeInfo(move(_t))
	{
	auto gi = c->RegisterType(t->AsTypeType()->GetType());
	tt_offset = gi->Offset();
	init_cohort = gi->InitCohort();
	}

string TypeTypeInfo::Initializer() const
	{
	return string("CPP_TypeType(") + Fmt(tt_offset) + ")";
	}

VectorTypeInfo::VectorTypeInfo(CPPCompile* c, TypePtr _t)
	: AbstractTypeInfo(move(_t))
	{
	auto gi = c->RegisterType(t->Yield());
	yt_offset = gi->Offset();
	init_cohort = gi->InitCohort();
	}

string VectorTypeInfo::Initializer() const
	{
	return string("CPP_VectorType(") + Fmt(yt_offset) + ")";
	}

ListTypeInfo::ListTypeInfo(CPPCompile* c, TypePtr _t)
	: AbstractTypeInfo(move(_t))
	{
	const auto& tl = t->AsTypeList()->GetTypes();

	for ( auto& tl_i : tl )
		{
		auto gi = c->RegisterType(tl_i);
		type_offsets.push_back(gi->Offset());
		init_cohort = max(init_cohort, gi->InitCohort());
		}
	}

string ListTypeInfo::Initializer() const
	{
	string type_list;
	for ( auto& t : type_offsets )
		type_list += Fmt(t) + ", ";

	return string("CPP_TypeList({ ") + type_list + "})";
	}

TableTypeInfo::TableTypeInfo(CPPCompile* c, TypePtr _t)
	: AbstractTypeInfo(move(_t))
	{
	auto tbl = t->AsTableType();

	auto gi = c->RegisterType(tbl->GetIndices());
	indices = gi->Offset();
	init_cohort = gi->InitCohort();

	if ( tbl->Yield() )
		{
		gi = c->RegisterType(tbl->Yield());
		yield = gi->Offset();
		init_cohort = max(init_cohort, gi->InitCohort());
		}
	}

string TableTypeInfo::Initializer() const
	{
	return string("CPP_TableType(") + Fmt(indices) + ", " + Fmt(yield) + ")";
	}

FuncTypeInfo::FuncTypeInfo(CPPCompile* c, TypePtr _t)
	: AbstractTypeInfo(move(_t))
	{
	auto f = t->AsFuncType();

	flavor = f->Flavor();
	auto gi = c->RegisterType(f->Params());
	params = gi->Offset();
	init_cohort = gi->InitCohort();

	if ( f->Yield() )
		{
		gi = c->RegisterType(f->Yield());
		yield = gi->Offset();
		init_cohort = max(init_cohort, gi->InitCohort());
		}
	}

string FuncTypeInfo::Initializer() const
	{
	string fl_name;
	if ( flavor == FUNC_FLAVOR_FUNCTION )
		fl_name = "FUNC_FLAVOR_FUNCTION";
	else if ( flavor == FUNC_FLAVOR_EVENT )
		fl_name = "FUNC_FLAVOR_EVENT";
	else if ( flavor == FUNC_FLAVOR_HOOK )
		fl_name = "FUNC_FLAVOR_HOOK";

	return string("CPP_FuncType(") + Fmt(params) + ", " + Fmt(yield) + ", " + fl_name + ")";
	}

	} // zeek::detail
