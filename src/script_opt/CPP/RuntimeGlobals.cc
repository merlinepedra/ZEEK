// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZeekString.h"
#include "zeek/Desc.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/RunTimeGlobals.h"
#include "zeek/script_opt/CPP/RunTimeInit.h"

using namespace std;

namespace zeek::detail
	{

std::vector<BoolValPtr> CPP__Bool__;
std::vector<IntValPtr> CPP__Int__;
std::vector<CountValPtr> CPP__Count__;
std::vector<EnumValPtr> CPP__Enum__;
std::vector<DoubleValPtr> CPP__Double__;
std::vector<TimeValPtr> CPP__Time__;
std::vector<IntervalValPtr> CPP__Interval__;
std::vector<StringValPtr> CPP__String__;
std::vector<PatternValPtr> CPP__Pattern__;
std::vector<AddrValPtr> CPP__Addr__;
std::vector<SubNetValPtr> CPP__SubNet__;
std::vector<PortValPtr> CPP__Port__;
std::vector<ListValPtr> CPP__List__;
std::vector<RecordValPtr> CPP__Record__;
std::vector<TableValPtr> CPP__Table__;
std::vector<VectorValPtr> CPP__Vector__;
std::vector<FuncValPtr> CPP__Func__;
std::vector<FileValPtr> CPP__File__;

std::vector<TypePtr> CPP__Type__;
std::vector<AttrPtr> CPP__Attr__;
std::vector<AttributesPtr> CPP__Attributes__;
std::vector<CallExprPtr> CPP__CallExpr__;
std::vector<void*> CPP__LambdaRegistration__;
std::vector<void*> CPP__GlobalID__;

void CPP_PatternConst::Generate(std::vector<PatternValPtr>& global_vec) const
	{
	auto re = new RE_Matcher(pattern);
	if ( is_case_insensitive )
		re->MakeCaseInsensitive();

	re->Compile();

	global_vec[offset] = make_intrusive<PatternVal>(re);
	}

void CPP_ListConst::Generate(std::vector<ListValPtr>& global_vec) const
	{
	auto l = make_intrusive<ListVal>(TYPE_ANY);

	for ( auto& v : vals )
		l->Append(v->Get());

	global_vec[offset] = l;
	}

void CPP_VectorConst::Generate(std::vector<VectorValPtr>& global_vec) const
	{
	auto vt = cast_intrusive<VectorType>(CPP__Type__[v_type]);
	auto vv = make_intrusive<VectorVal>(vt);

	for ( auto& v : v_vals )
		vv->Append(v->Get());

	global_vec[offset] = vv;
	}

void CPP_RecordConst::Generate(std::vector<RecordValPtr>& global_vec) const
	{
	auto rt = cast_intrusive<RecordType>(CPP__Type__[r_type]);
	auto rv = make_intrusive<RecordVal>(rt);

	for ( auto i = 0U; i < r_vals.size(); ++i )
		rv->Assign(i, r_vals[i]->Get());

	global_vec[offset] = rv;
	}

void CPP_TableConst::Generate(std::vector<TableValPtr>& global_vec) const
	{
	auto tt = cast_intrusive<TableType>(CPP__Type__[t_type]);
	auto tv = make_intrusive<TableVal>(tt);

	for ( auto i = 0U; i < t_vals.size(); ++i )
		tv->Assign(t_indices[i]->Get(), t_vals[i]->Get());

	global_vec[offset] = tv;
	}


ExprPtr CPP_RecordAttrExpr::Build() const
	{
	auto t = CPP__Type__[type];
	auto rt = cast_intrusive<RecordType>(t);
	auto empty_vals = make_intrusive<ListExpr>();
	auto construct = make_intrusive<RecordConstructorExpr>(empty_vals);
	return make_intrusive<RecordCoerceExpr>(construct, rt);
	}

void CPP_Attrs::Generate(std::vector<AttributesPtr>& global_vec) const
	{
	vector<AttrPtr> a_list;
	for ( auto a : attrs )
		a_list.push_back(CPP__Attr__[a]);

	global_vec[offset] = make_intrusive<Attributes>(a_list, nullptr, false, false);
	}


void CPP_EnumType::DoGenerate(std::vector<TypePtr>& global_vec) const
	{
	auto et = get_enum_type__CPP(name);

	if ( et->Names().empty() )
		for ( auto i = 0U; i < elems.size(); ++i )
			et->AddNameInternal(string(elems[i]), vals[i]);

	global_vec[offset] = et;
	}

void CPP_TableType::DoGenerate(std::vector<TypePtr>& global_vec) const
	{
	TypePtr t;

	if ( yield < 0 )
		t = make_intrusive<SetType>(cast_intrusive<TypeList>(global_vec[indices]), nullptr);
	else
		t = make_intrusive<TableType>(cast_intrusive<TypeList>(global_vec[indices]), global_vec[yield]);

	global_vec[offset] = t;
	}

void CPP_FuncType::DoGenerate(std::vector<TypePtr>& global_vec) const
	{
	auto p = cast_intrusive<RecordType>(global_vec[params]);

	TypePtr y;

	if ( yield >= 0 )
		y = global_vec[yield];

	else if ( flavor == FUNC_FLAVOR_FUNCTION || flavor == FUNC_FLAVOR_HOOK )
		y = base_type(TYPE_VOID);

	global_vec[offset] = make_intrusive<FuncType>(p, y, flavor);
	}

void CPP_RecordType::PreInit(std::vector<TypePtr>& global_vec) const
	{
	if ( name.empty() )
		global_vec[offset] = get_record_type__CPP(nullptr);
	else
		global_vec[offset] = get_record_type__CPP(name.c_str());
	}

void CPP_RecordType::DoGenerate(std::vector<TypePtr>& global_vec) const
	{
	auto r = global_vec[offset]->AsRecordType();
	ASSERT(r);

	if ( r->NumFields() == 0 )
		{
		type_decl_list tl;
		int n = field_names.size();
		for ( auto i = 0; i < n; ++i )
			{
			auto id = util::copy_string(field_names[i]);
			auto type = global_vec[field_types[i]];

			AttributesPtr attrs;
			if ( field_attrs[i] >= 0 )
				attrs = CPP__Attributes__[field_attrs[i]];

			tl.append(new TypeDecl(id, type, attrs));
			}

		r->AddFieldsDirectly(tl);
		}
	}


int CPP_FieldMapping::ComputeOffset() const
	{
	auto r = CPP__Type__[rec]->AsRecordType();
	auto fm_offset = r->FieldOffset(field_name.c_str());

	if ( fm_offset < 0 )
		{
                // field does not exist, create it
                fm_offset = r->NumFields();

		auto id = util::copy_string(field_name.c_str());
		auto type = CPP__Type__[field_type];

		AttributesPtr attrs;
		if ( field_attrs >= 0 )
			attrs = CPP__Attributes__[field_attrs];

		type_decl_list tl;
		tl.append(new TypeDecl(id, type, attrs));

		r->AddFieldsDirectly(tl);
		}

	return fm_offset;
	}


int CPP_EnumMapping::ComputeOffset() const
	{
	auto e = CPP__Type__[e_type]->AsEnumType();

	auto em_offset = e->Lookup(e_name);
	if ( em_offset < 0 )
		{
		em_offset = e->Names().size();
		if ( e->Lookup(em_offset) )
			reporter->InternalError("enum inconsistency while initializing compiled scripts");
		e->AddNameInternal(e_name, em_offset);
		}

	return em_offset;
	}


void CPP_GlobalInit::Generate(std::vector<void*>& /* global_vec */) const
	{
	global = lookup_global__CPP(name, CPP__Type__[type], exported);

	if ( ! global->HasVal() )
		{
		global->SetVal(val->Get());
		if ( attrs >= 0 )
			global->SetAttrs(CPP__Attributes__[attrs]);
		}
	}


	} // zeek::detail
