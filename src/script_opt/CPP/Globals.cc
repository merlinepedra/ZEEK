// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/Compile.h"
#include "zeek/script_opt/CPP/RunTimeInit.h"

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

	g->SetOffset(this, ++size);

	instances[init_cohort].push_back(move(g));
	}

string CPP_GlobalsInfo::Declare() const
	{
	return string("std::vector<") + CPPType() + "> " + base_name + ";";
	}

void CPP_GlobalsInfo::GenerateInitializers(CPPCompile* cc)
	{
	cc->NL();

	cc->Emit("CPP_Globals<%s> %s = CPP_Globals<%s>(", CPPType(),
	         InitializersName(), CPPType());

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
	: CPP_GlobalInfo(0)
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
	: CPP_GlobalInfo(0)
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
	: CPP_GlobalInfo(0)
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


PatternValPtr CPP_PatternConst::Generate() const
	{
	auto re = new RE_Matcher(pattern);
	if ( is_case_insensitive )
		re->MakeCaseInsensitive();

	re->Compile();

	return make_intrusive<PatternVal>(re);
	}

TypePtr CPP_EnumType::Generate() const
	{
	auto et = get_enum_type__CPP(name);

	if ( et->Names().empty() )
		for ( auto i = 0U; i < elems.size(); ++i )
			et->AddNameInternal(elems[i], vals[i]);

	return et;
	}

	} // zeek::detail
