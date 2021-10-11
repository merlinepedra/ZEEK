// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/RunTimeGlobals.h"
#include "zeek/script_opt/CPP/RunTimeInit.h"

using namespace std;

namespace zeek::detail
	{

PatternValPtr CPP_PatternConst::Generate(std::vector<PatternValPtr>& global_vec) const
	{
	auto re = new RE_Matcher(pattern);
	if ( is_case_insensitive )
		re->MakeCaseInsensitive();

	re->Compile();

	return make_intrusive<PatternVal>(re);
	}

TypePtr CPP_EnumType::Generate(std::vector<TypePtr>& global_vec) const
	{
	auto et = get_enum_type__CPP(name);

	if ( et->Names().empty() )
		for ( auto i = 0U; i < elems.size(); ++i )
			et->AddNameInternal(elems[i], vals[i]);

	return et;
	}

TypePtr CPP_TableType::Generate(std::vector<TypePtr>& global_vec) const
	{
	if ( yield >= 0 )
		return make_intrusive<SetType>(cast_intrusive<TypeList>(global_vec[indices]), nullptr);

	return make_intrusive<TableType>(cast_intrusive<TypeList>(global_vec[indices]), global_vec[yield]);
	}

TypePtr CPP_FuncType::Generate(std::vector<TypePtr>& global_vec) const
	{
	auto p = cast_intrusive<RecordType>(global_vec[params]);
	auto y = yield >= 0 ? global_vec[yield] : nullptr;

	return make_intrusive<FuncType>(p, y, flavor);
	}

	} // zeek::detail
