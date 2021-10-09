// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/Compile.h"

using namespace std;

namespace zeek::detail
	{

std::string CPP_GlobalsInfo::Name(int index) const
	{
	return base_name + "[" + Fmt(index) + "]";
	}

void CPP_GlobalsInfo::AddInstance(std::shared_ptr<CPP_GlobalInfo> g)
	{
	auto init_cohort = g->InitCohort();

	if ( static_cast<int>(instances.size()) <= init_cohort )
		instances.resize(init_cohort + 1);

	g->SetOffset(this, ++size);

	instances[init_cohort].push_back(std::move(g));
	}

std::string CPP_GlobalsInfo::Declare() const
	{
	return std::string("std::vector<") + CPPType() + "> " + base_name + ";";
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

std::string StringConstantInfo::Initializer() const
	{
	return std::string("CPP_StringConst(") + Fmt(len) + ", " + rep + ")";
	}

PatternConstantInfo::PatternConstantInfo(ValPtr v)
	: CPP_GlobalInfo(0)
	{
	auto re = v->AsPatternVal()->Get();
	pattern = CPPEscape(re->OrigText());
	is_case_insensitive = re->IsCaseInsensitive();
	}

std::string PatternConstantInfo::Initializer() const
	{
	return std::string("CPP_PatternConst(") + pattern + ", " + Fmt(is_case_insensitive) + ")";
	}

DescConstantInfo::DescConstantInfo(ValPtr v)
	: CPP_GlobalInfo(0)
	{
	ODesc d;
	v->Describe(&d);
	init = d.Description();
	}

std::string DescConstantInfo::Initializer() const
	{
	return std::string("CPP_") + gls->Type() + "Const(\"" + init + "\")";
	}


PatternValPtr CPP_PatternConst::Generate() const
	{
	auto re = new RE_Matcher(pattern);
	if ( is_case_insensitive )
		re->MakeCaseInsensitive();

	re->Compile();

	return make_intrusive<PatternVal>(re);
	}


	} // zeek::detail
