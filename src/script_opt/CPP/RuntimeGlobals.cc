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

std::vector<std::vector<int>> CPP__Indices__;
std::vector<const char*> CPP__Strings__;
std::vector<p_hash_type> CPP__Hashes__;

std::map<TypeTag, std::shared_ptr<CPP_AbstractGlobalAccessor>> CPP__Consts__;
std::vector<CPP_ValElem> CPP__ConstVals__;


void CPP_TypeGlobals::PreInit()
	{
	vector<int>& offsets_vec = CPP__Indices__[offsets_set];
	for ( auto cohort = 0U; cohort < offsets_vec.size(); ++cohort )
		{
		auto& co = inits[cohort];
		vector<int>& cohort_offsets = CPP__Indices__[offsets_vec[cohort]];
		for ( auto i = 0U; i < co.size(); ++i )
			PreInit(cohort_offsets[i], co[i]);
		}
	}

void CPP_TypeGlobals::PreInit(int offset, ValElemVec& init_vals)
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

void CPP_TypeGlobals::Generate(vector<TypePtr>& gvec, int offset, ValElemVec& init_vals) const
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

TypePtr CPP_TypeGlobals::BuildEnumType(ValElemVec& init_vals) const
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

TypePtr CPP_TypeGlobals::BuildOpaqueType(ValElemVec& init_vals) const
	{
	auto& name = CPP__Strings__[init_vals[1]];
	return make_intrusive<OpaqueType>(name);
	}

TypePtr CPP_TypeGlobals::BuildTypeType(ValElemVec& init_vals) const
	{
	auto& t = CPP__Type__[init_vals[1]];
	return make_intrusive<TypeType>(t);
	}

TypePtr CPP_TypeGlobals::BuildVectorType(ValElemVec& init_vals) const
	{
	auto& t = CPP__Type__[init_vals[1]];
	return make_intrusive<VectorType>(t);
	}

TypePtr CPP_TypeGlobals::BuildTypeList(ValElemVec& init_vals, int offset) const
	{
	const auto& tl = cast_intrusive<TypeList>(global_vec[offset]);

	auto n = init_vals.size();
	auto i = 1U;

	while ( i < n )
		tl->Append(CPP__Type__[init_vals[i++]]);

	return tl;
	}

TypePtr CPP_TypeGlobals::BuildTableType(ValElemVec& init_vals) const
	{
	auto index = cast_intrusive<TypeList>(CPP__Type__[init_vals[1]]);
	auto yield_i = init_vals[2];
	auto yield = yield_i >= 0 ? CPP__Type__[yield_i] : nullptr;

	return make_intrusive<TableType>(index, yield);
	}

TypePtr CPP_TypeGlobals::BuildFuncType(ValElemVec& init_vals) const
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

TypePtr CPP_TypeGlobals::BuildRecordType(ValElemVec& init_vals, int offset) const
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


void CPP_GlobalInit::Generate(std::vector<void*>& /* global_vec */, int /* offset */) const
	{
	global = lookup_global__CPP(name, CPP__Type__[type], exported);

	if ( ! global->HasVal() && val >= 0 )
		{
		global->SetVal(CPP__ConstVals__[val].Get());
		if ( attrs >= 0 )
			global->SetAttrs(CPP__Attributes__[attrs]);
		}
	}


void generate_indices_set(int* inits, std::vector<std::vector<int>>& indices_set)
	{
	// First figure out how many groups of indices there are, so we
	// can pre-allocate the outer vector.
	auto i_ptr = inits;
	int num_inits = 0;
	while ( *i_ptr >= 0 )
		{
		++num_inits;
		int n = *i_ptr;
		i_ptr += n + 1;
		}

	indices_set.reserve(num_inits);

	i_ptr = inits;
	while ( *i_ptr >= 0 )
		{
		int n = *i_ptr;
		++i_ptr;
		std::vector<int> indices;
		indices.reserve(n);
		for ( int i = 0; i < n; ++i )
			indices.push_back(i_ptr[i]);
		i_ptr += n;

		indices_set.emplace_back(move(indices));
		}
	}


	} // zeek::detail
