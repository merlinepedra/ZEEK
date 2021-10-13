// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/RunTimeGlobals.h"
#include "zeek/script_opt/CPP/RunTimeInit.h"

using namespace std;

namespace zeek::detail
	{

std::vector<StringValPtr> CPP__String__;
std::vector<PatternValPtr> CPP__Pattern__;
std::vector<AddrValPtr> CPP__Addr__;
std::vector<SubNetValPtr> CPP__SubNet__;
std::vector<TypePtr> CPP__Type__;
std::vector<AttrPtr> CPP__Attr__;
std::vector<AttributesPtr> CPP__Attributes__;

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

TypePtr CPP_RecordType::PreInit() const
	{
	if ( name.empty() )
		return get_record_type__CPP(nullptr);
	else
		return get_record_type__CPP(name.c_str());
	}

TypePtr CPP_RecordType::Generate(std::vector<TypePtr>& global_vec, int offset) const
	{
	auto t = global_vec[offset];
	auto r = t->AsRecordType();
	ASSERT(r);

	if ( r->NumFields() == 0 )
		{
		type_decl_list tl;
		int n = field_names.size();
		for ( auto i = 0; i < n; ++i )
			{
			auto id = util::copy_string(field_names[i].c_str());
			auto type = global_vec[field_types[i]];

			AttributesPtr attrs;
			if ( field_attrs[i] >= 0 )
				attrs = CPP__Attributes__[field_attrs[i]];

			tl.append(new TypeDecl(id, type, attrs));
			}

		r->AddFieldsDirectly(tl);
		}

	return t;
	}

AttributesPtr CPP_Attrs::Generate(std::vector<AttributesPtr>& global_vec) const
	{
	vector<AttrPtr> a_list;
	for ( auto a : attrs )
		a_list.push_back(CPP__Attr__[a]);

	return make_intrusive<Attributes>(a_list, nullptr, false, false);
	}

	} // zeek::detail
