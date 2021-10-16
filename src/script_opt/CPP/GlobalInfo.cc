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

void CPP_GlobalsInfo::GenerateInitializers(CPPCompile* c)
	{
	c->NL();

	c->Emit("CPP_Globals<%s> %s = CPP_Globals<%s>(%s, ", CPPType(),
	        InitializersName(), CPPType(), base_name);

	c->IndentUp();
	c->Emit("{");

	for ( auto& cohort : instances )
		{
		c->Emit("{");

		for ( auto& co : cohort )
			c->Emit("%s,", co->Initializer());

		c->Emit("},");
		}

	c->Emit("}");
	c->IndentDown();
	c->Emit(");");
	}

DescConstInfo::DescConstInfo(std::string _name, ValPtr v)
	: CPP_GlobalInfo(), name(std::move(_name))
	{
	ODesc d;
	v->Describe(&d);
	init = d.Description();
	}

string DescConstInfo::Initializer() const
	{
	return string("CPP_BasicConst<") + name + "ValPtr, const char*, " + name + "Val>(\"" + init + "\")";
	}

EnumConstInfo::EnumConstInfo(CPPCompile* c, ValPtr v)
	{
	auto ev = v->AsEnumVal();
	e_type = c->TypeOffset(ev->GetType());
	e_val = v->AsEnum();
	}

StringConstInfo::StringConstInfo(ValPtr v)
	: CPP_GlobalInfo()
	{
	auto s = v->AsString();
	const char* b = (const char*)(s->Bytes());

	len = s->Len();
	rep = CPPEscape(b, len);
	}

string StringConstInfo::Initializer() const
	{
	return string("CPP_StringConst(") + Fmt(len) + ", " + rep + ")";
	}

PatternConstInfo::PatternConstInfo(ValPtr v)
	: CPP_GlobalInfo()
	{
	auto re = v->AsPatternVal()->Get();
	pattern = CPPEscape(re->OrigText());
	is_case_insensitive = re->IsCaseInsensitive();
	}

string PatternConstInfo::Initializer() const
	{
	return string("CPP_PatternConst(") + pattern + ", " + Fmt(is_case_insensitive) + ")";
	}

CompoundConstInfo::CompoundConstInfo(CPPCompile* _c, ValPtr v)
	: CPP_GlobalInfo(), c(_c)
	{
	auto& t = v->GetType();
	type = c->TypeOffset(t);
	init_cohort = c->TypeCohort(t) + 1;
	}

std::string CompoundConstInfo::ValElem(ValPtr v)
	{
	if ( ! v )
		return string("CPP_AbstractValElem()");

	auto gi = c->RegisterConstant(v);
	init_cohort = max(init_cohort, gi->InitCohort() + 1);

	auto gl = gi->MainGlobal();
	return string("CPP_ValElem<") + gl->CPPType() + ">(" + gl->GlobalsName() + ", " + Fmt(gi->Offset()) + ")";
	}

ListConstInfo::ListConstInfo(CPPCompile* _c, ValPtr v)
	: CompoundConstInfo(_c)
	{
	auto lv = cast_intrusive<ListVal>(v);
	auto n = lv->Length();

	for ( auto i = 0; i < n; ++i )
		vals += ValElem(lv->Idx(i)) + ", ";
	}

string ListConstInfo::Initializer() const
	{
	return string("CPP_ListConst({ " + vals + "})");
	}

VectorConstInfo::VectorConstInfo(CPPCompile* c, ValPtr v)
	: CompoundConstInfo(c, v)
	{
	auto vv = cast_intrusive<VectorVal>(v);
	auto n = vv->Size();

	for ( auto i = 0; i < n; ++i )
		vals += ValElem(vv->ValAt(i)) + ", ";
	}

RecordConstInfo::RecordConstInfo(CPPCompile* c, ValPtr v)
	: CompoundConstInfo(c, v)
	{
	auto r = cast_intrusive<RecordVal>(v);
	auto n = r->NumFields();

	type = c->TypeOffset(r->GetType());

	for ( auto i = 0; i < n; ++i )
		vals += ValElem(r->GetField(i)) + ", ";
	}

TableConstInfo::TableConstInfo(CPPCompile* c, ValPtr v)
	: CompoundConstInfo(c, v)
	{
	auto tv = cast_intrusive<TableVal>(v);

	for ( auto& tv_i : tv->ToMap() )
		{
		auto gi = c->RegisterConstant(tv_i.first);
		init_cohort = max(init_cohort, gi->InitCohort());
		indices += Fmt(gi->Offset()) + ", ";

		if ( tv_i.second )
			{
			gi = c->RegisterConstant(tv_i.second);
			init_cohort = max(init_cohort, gi->InitCohort());
			vals += Fmt(gi->Offset()) + ", ";
			}
		}
	}

string FuncConstInfo::Initializer() const
	{
	auto f = fv->AsFunc();
	const auto& fn = f->Name();

	const auto& bodies = f->GetBodies();

	string hashes;

	for ( const auto& b : bodies )
		hashes += Fmt(c->BodyHash(b.stmts.get())) + ", ";

	return string("CPP_FuncConst(\"") + fn + "\", " + Fmt(type) + ", { " + hashes + "})";
	}


AttrInfo::AttrInfo(CPPCompile* c, const AttrPtr& attr)
	: CPP_GlobalInfo()
	{
	tag = c->AttrName(attr->Tag());
	auto a_e = attr->GetExpr();

	expr1 = expr2 = "nullptr";

	if ( a_e )
		{
		auto gi = c->RegisterType(a_e->GetType());
		init_cohort = max(init_cohort, gi->InitCohort() + 1);

		auto expr_type = gi->Name();

		if ( ! CPPCompile::IsSimpleInitExpr(a_e) )
			expr2 = string("&") + c->InitExprName(a_e);

		else if ( a_e->Tag() == EXPR_CONST )
			expr1 = string("make_intrusive<ConstExpr>(") + c->GenExpr(a_e, CPPCompile::GEN_VAL_PTR) + ")";

		else if ( a_e->Tag() == EXPR_NAME )
                        expr1 = string("make_intrusive<NameExpr>(") + c->GlobalName(a_e) + ")";

		else
			{
			ASSERT(a_e->Tag() == EXPR_RECORD_COERCE);
                        expr1 = "make_intrusive<RecordCoerceExpr>(make_intrusive<RecordConstructorExpr>(";
			expr1 += "make_intrusive<ListExpr>()), cast_intrusive<RecordType>(";
			expr1 += expr_type + "))";
			}
		}
	}

string AttrInfo::Initializer() const
	{
	return string("CPP_Attr(") + tag + ", " + expr1 + ", " + expr2 + ")";
	}

AttrsInfo::AttrsInfo(CPPCompile* c, const AttributesPtr& _attrs)
	: CPP_GlobalInfo()
	{
	for ( const auto& a : _attrs->GetAttrs() )
		{
		ASSERT(c->processed_attr.count(a.get()) > 0);
		auto gi = c->processed_attr[a.get()];
		init_cohort = max(init_cohort, gi->InitCohort() + 1);
		attrs.push_back(gi->Offset());
		}
	}

string AttrsInfo::Initializer() const
	{
	string attr_list;

	for ( auto a : attrs )
		attr_list += Fmt(a) + ", ";

	return string("CPP_Attrs({ ") + attr_list + "})";
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


TypeTypeInfo::TypeTypeInfo(CPPCompile* _c, TypePtr _t)
	: CompoundTypeInfo(_c, move(_t))
	{
	tt = t->AsTypeType()->GetType();
	auto gi = c->RegisterType(tt);
	if ( gi )
		init_cohort = gi->InitCohort();
	}

string TypeTypeInfo::Initializer() const
	{
	return string("CPP_TypeType(") + Fmt(c->TypeOffset(tt)) + ")";
	}

VectorTypeInfo::VectorTypeInfo(CPPCompile* _c, TypePtr _t)
	: CompoundTypeInfo(_c, move(_t))
	{
	yield = t->Yield();
	auto gi = c->RegisterType(yield);
	if ( gi )
		init_cohort = gi->InitCohort();
	}

string VectorTypeInfo::Initializer() const
	{
	return string("CPP_VectorType(") + Fmt(c->TypeOffset(yield)) + ")";
	}

ListTypeInfo::ListTypeInfo(CPPCompile* _c, TypePtr _t)
	: CompoundTypeInfo(_c, move(_t)), types(t->AsTypeList()->GetTypes())
	{
	for ( auto& tl_i : types )
		{
		auto gi = c->RegisterType(tl_i);
		if ( gi )
			init_cohort = max(init_cohort, gi->InitCohort());
		}
	}

string ListTypeInfo::Initializer() const
	{
	string type_list;
	for ( auto& t : types )
		type_list += Fmt(c->TypeOffset(t)) + ", ";

	return string("CPP_TypeList({ ") + type_list + "})";
	}

TableTypeInfo::TableTypeInfo(CPPCompile* _c, TypePtr _t)
	: CompoundTypeInfo(_c, move(_t))
	{
	auto tbl = t->AsTableType();

	auto gi = c->RegisterType(tbl->GetIndices());
	ASSERT(gi);
	indices = gi->Offset();
	init_cohort = gi->InitCohort();

	yield = tbl->Yield();

	if ( yield )
		{
		gi = c->RegisterType(yield);
		if ( gi )
			init_cohort = max(init_cohort, gi->InitCohort());
		}
	}

string TableTypeInfo::Initializer() const
	{
	auto y = Fmt(yield ? c->TypeOffset(yield) : -1);
	return string("CPP_TableType(") + Fmt(indices) + ", " + y + ")";
	}

FuncTypeInfo::FuncTypeInfo(CPPCompile* _c, TypePtr _t)
	: CompoundTypeInfo(_c, move(_t))
	{
	auto f = t->AsFuncType();

	flavor = f->Flavor();
	params = f->Params();
	yield = f->Yield();

	auto gi = c->RegisterType(f->Params());
	if ( gi )
		init_cohort = gi->InitCohort();

	if ( yield )
		{
		gi = c->RegisterType(f->Yield());
		if ( gi )
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

	auto y = Fmt(yield ? c->TypeOffset(yield) : -1);

	return string("CPP_FuncType(") + Fmt(c->TypeOffset(params)) + ", " + y + ", " + fl_name + ")";
	}

RecordTypeInfo::RecordTypeInfo(CPPCompile* _c, TypePtr _t)
	: CompoundTypeInfo(_c, move(_t))
	{
	auto r = t->AsRecordType()->Types();

	if ( ! r )
		return;

	for ( const auto& r_i : *r )
		{
		field_names.emplace_back(r_i->id);

		auto gi = c->RegisterType(r_i->type);
		if ( gi )
			init_cohort = max(init_cohort, gi->InitCohort());
		// else it's a recursive type, no need to adjust cohort here

		field_types.push_back(r_i->type);

		if ( r_i->attrs )
			{
			gi = c->RegisterAttributes(r_i->attrs);
			init_cohort = max(init_cohort, gi->InitCohort() + 1);
			field_attrs.push_back(gi->Offset());
			}
		else
			field_attrs.push_back(-1);
		}
	}

string RecordTypeInfo::Initializer() const
	{
	string names, types, attrs;

	for ( auto& n : field_names )
		names += string("\"") + n + "\", ";

	for ( auto& t : field_types )
		{
		// Because RecordType's can be recursively defined,
		// during construction we couldn't reliably access
		// the field type's offsets.  At this point, though,
		// they should all be available.
		types += Fmt(c->TypeOffset(t)) + ", ";
		}

	for ( auto& a : field_attrs )
		attrs += Fmt(a) + ", ";

	return string("CPP_RecordType({ ") + names + "}, { " + types + "}, { " + attrs + "})";
	}

	} // zeek::detail
