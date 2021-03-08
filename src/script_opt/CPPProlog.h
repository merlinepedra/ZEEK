// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/module_util.h"
#include "zeek/ZeekString.h"
#include "zeek/Func.h"
#include "zeek/Frame.h"
#include "zeek/Scope.h"
#include "zeek/RE.h"
#include "zeek/IPAddr.h"
#include "zeek/Val.h"
#include "zeek/OpaqueVal.h"
#include "zeek/Expr.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/script_opt/CPPFunc.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek {

using BoolValPtr = IntrusivePtr<zeek::BoolVal>;
using CountValPtr = IntrusivePtr<zeek::CountVal>;
using DoubleValPtr = IntrusivePtr<zeek::DoubleVal>;
using StringValPtr = IntrusivePtr<zeek::StringVal>;
using IntervalValPtr = IntrusivePtr<zeek::IntervalVal>;
using PatternValPtr = IntrusivePtr<zeek::PatternVal>;
using FuncValPtr = IntrusivePtr<zeek::FuncVal>;
using FileValPtr = IntrusivePtr<zeek::FileVal>;
using SubNetValPtr = IntrusivePtr<zeek::SubNetVal>;

namespace detail {

// Helper functions.

typedef void (*CPP_init_func)();

std::vector<CPP_init_func> CPP_init_funcs;

void init_CPPs()
	{
	for ( auto f : CPP_init_funcs )
		f();
	}

int flag_init_CPP()
	{
	CPP_init_hook = init_CPPs;
	return 0;
	}

static int dummy = flag_init_CPP();

void register_body__CPP(IntrusivePtr<CPPStmt> body, hash_type hash,
			std::vector<std::string> events)
	{
	compiled_bodies[hash] = body;
	compiled_bodies_events[hash] = std::move(events);
	}

IDPtr lookup_global__CPP(const char* g, const TypePtr& t)
	{
	auto gl = lookup_ID(g, GLOBAL_MODULE_NAME, false, false, false);

	if ( gl )
		{
		ASSERT(same_type(t, gl->GetType()));
		}

	else
		{
		gl = install_ID(g, GLOBAL_MODULE_NAME, true, false);
		gl->SetType(t);
		}

	return gl;
	}

Func* lookup_bif__CPP(const char* bif)
	{
	auto b = lookup_ID(bif, GLOBAL_MODULE_NAME, false, false, false);
	ASSERT(b != nullptr && b->GetType()->Tag() == TYPE_FUNC);
	return b->GetVal()->AsFunc();
	}

StringValPtr str_concat__CPP(const String* s1, const String* s2)
	{
	std::vector<const String*> strings(2);
	strings[0] = s1;
	strings[1] = s2;

	return make_intrusive<StringVal>(concatenate(strings));
	}

bool str_in__CPP(const String* s1, const String* s2)
	{
	auto s = reinterpret_cast<const unsigned char*>(s1->CheckString());
	return util::strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1;
	}

ListValPtr index_val__CPP(std::vector<ValPtr> indices)
	{
	auto ind_v = make_intrusive<ListVal>(TYPE_ANY);

	// In the future, we could provide N versions of this that
	// unroll the loop.
	for ( auto i : indices )
		ind_v->Append(i);

	return ind_v;
	}

ValPtr index_table__CPP(TableValPtr t, std::vector<ValPtr> indices)
	{
	return t->FindOrDefault(index_val__CPP(std::move(indices)));
	}

ValPtr index_string__CPP(StringValPtr svp, std::vector<ValPtr> indices)
	{
	return index_string(svp->AsString(),
				index_val__CPP(std::move(indices)).get());
	}

// Call out to the given script or BiF function.
inline ValPtr invoke__CPP(Func* f, std::vector<ValPtr> args, Frame* frame)
	{
	return f->Invoke(&args, frame);
	}

// Convert a bare Val* to its corresponding IntrusivePtr.
template <typename T>
IntrusivePtr<T> val_to_valptr__CPP(T* v) { return {NewRef{}, v}; }

ValPtr set_global__CPP(IDPtr g, ValPtr v)
	{
	g->SetVal(v);
	return v;
	}

SubNetValPtr addr_mask__CPP(const IPAddr& a, uint32_t mask)
	{
        if ( a.GetFamily() == IPv4 )
                {
                if ( mask > 32 )
                        reporter->RuntimeError(&no_location, "bad IPv4 subnet prefix length: %d", int(mask));
                }
        else
                {
                if ( mask > 128 )
                        reporter->RuntimeError(&no_location, "bad IPv6 subnet prefix length: %d", int(mask));
                }

        return make_intrusive<SubNetVal>(a, mask);
	}

ValPtr assign_field__CPP(RecordValPtr rec, int field, ValPtr v)
	{
	rec->Assign(field, v);
	return v;
	}

// Execute an assignment "v1[v2] = v3".
TableValPtr assign_to_index__CPP(TableValPtr v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated;
	auto err_msg = zeek::detail::assign_to_index(v1, std::move(v2),
							std::move(v3),
							iterators_invalidated);
	if ( err_msg )
		reporter->Error("%s", err_msg);

	return v1;
	}

VectorValPtr assign_to_index__CPP(VectorValPtr v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated;
	auto err_msg = zeek::detail::assign_to_index(v1, std::move(v2),
							std::move(v3),
							iterators_invalidated);
	if ( err_msg )
		reporter->Error("%s", err_msg);

	return v1;
	}

StringValPtr assign_to_index__CPP(StringValPtr v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated;
	auto err_msg = zeek::detail::assign_to_index(v1, std::move(v2),
							std::move(v3),
							iterators_invalidated);
	if ( err_msg )
		reporter->Error("%s", err_msg);

	return v1;
	}

ValPtr vector_append__CPP(VectorValPtr v1, ValPtr v2)
	{
	v1->Assign(v1->Size(), v2);
	return v2;
	}

TableValPtr table_coerce__CPP(const ValPtr& v, const TypePtr& t)
	{
	TableVal* tv = v->AsTableVal();

	if ( tv->Size() > 0 )
		reporter->Error("coercion of non-empty table/set");

	return make_intrusive<TableVal>(cast_intrusive<TableType>(t),
					tv->GetAttrs());
	}

VectorValPtr vector_coerce__CPP(const ValPtr& v, const TypePtr& t)
	{
	VectorVal* vv = v->AsVectorVal();

	if ( vv->Size() > 0 )
		reporter->Error("coercion of non-empty vector");

	return make_intrusive<VectorVal>(cast_intrusive<VectorType>(t));
	}

AttributesPtr build_attrs__CPP(std::vector<int> attr_tags,
				std::vector<ValPtr> attr_vals)
	{
	std::vector<AttrPtr> attrs;
	int nattrs = attr_tags.size();
	for ( auto i = 0; i < nattrs; ++i )
		{
		auto t_i = AttrTag(attr_tags[i]);
		const auto& v_i = attr_vals[i];
		ExprPtr e;

		if ( v_i )
			e = make_intrusive<ConstExpr>(v_i);

		attrs.emplace_back(make_intrusive<Attr>(t_i, e));
		}

	return make_intrusive<Attributes>(std::move(attrs), nullptr, false, false);
	}

TableValPtr set_constructor__CPP(std::vector<ValPtr> elements, TableTypePtr t,
					std::vector<int> attr_tags,
					std::vector<ValPtr> attr_vals)
	{
	auto attrs = build_attrs__CPP(std::move(attr_tags), std::move(attr_vals));
	auto aggr = make_intrusive<TableVal>(t, std::move(attrs));

	for ( const auto& elem : elements )
		aggr->Assign(std::move(elem), nullptr);

	return aggr;
	}

TableValPtr table_constructor__CPP(std::vector<ValPtr> indices,
					std::vector<ValPtr> vals,
					TableTypePtr t,
					std::vector<int> attr_tags,
					std::vector<ValPtr> attr_vals)
	{
	const auto& yt = t->Yield().get();
	auto n = indices.size();

	auto attrs = build_attrs__CPP(std::move(attr_tags), std::move(attr_vals));
	auto aggr = make_intrusive<TableVal>(t, std::move(attrs));

	for ( auto i = 0; i < n; ++i )
		{
		auto v = check_and_promote(vals[i], yt, true);
		if ( v )
			aggr->Assign(std::move(indices[i]), std::move(v));
		}

	return aggr;
	}

RecordValPtr record_constructor__CPP(std::vector<ValPtr> vals, RecordTypePtr t)
	{
	auto rv = make_intrusive<RecordVal>(std::move(t));
	auto n = vals.size();

	rv->Reserve(n);

	for ( auto i = 0; i < n; ++i )
		rv->Assign(i, vals[i]);

	return rv;
	}

VectorValPtr vector_constructor__CPP(std::vector<ValPtr> vals, VectorTypePtr t)
	{
	auto vv = make_intrusive<VectorVal>(std::move(t));
	auto n = vals.size();

	for ( auto i = 0; i < n; ++i )
		vv->Assign(i, vals[i]);

	return vv;
	}

ValPtr schedule__CPP(double dt, EventHandlerPtr event, std::vector<ValPtr> args)
	{
	timer_mgr->Add(new ScheduleTimer(event, std::move(args), dt));
	return nullptr;
	}

RecordTypePtr get_record_type__CPP(const char* record_type_name)
	{
	IDPtr existing_type;

	if ( record_type_name &&
	     (existing_type = global_scope()->Find(record_type_name)) )
		{
		ASSERT(existing_type->GetType()->Tag() == TYPE_RECORD);
		return cast_intrusive<RecordType>(existing_type->GetType());
		}

	return make_intrusive<RecordType>(new type_decl_list());
	}

EnumTypePtr get_enum_type__CPP(const std::string& enum_type_name)
	{
	auto existing_type = global_scope()->Find(enum_type_name);

	if ( existing_type )
		return cast_intrusive<EnumType>(existing_type->GetType());
	else
		return make_intrusive<EnumType>(enum_type_name);
	}

EnumValPtr make_enum__CPP(TypePtr t, int i)
	{
	auto et = cast_intrusive<EnumType>(t);
	return make_intrusive<EnumVal>(et, i);
	}

bro_uint_t abs__CPP(bro_int_t v)
	{
	return v < 0 ? -v : v;
	}

bro_uint_t abs__CPP(double v)
	{
	return v < 0.0 ? -v : v;
	}

bool check_vec_sizes(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	if ( v1->Size() == v2->Size() )
		return true;

	reporter->RuntimeError(&no_location, "vector operands are of different sizes");
	return false;
	}

#define VEC_OP1_KERNEL(accessor, type, op) \
	for ( unsigned int i = 0; i < v->Size(); ++i ) \
		{ \
		auto v_i = v->At(i)->accessor(); \
		v_result->Assign(i, make_intrusive<type>(op v_i)); \
		}

#define VEC_OP1(name, op, double_kernel) \
VectorValPtr vec_op_ ## name ## __CPP(const VectorValPtr& v) \
	{ \
	auto vt = v->GetType<VectorType>(); \
	auto v_result = make_intrusive<VectorVal>(vt); \
 \
	switch ( vt->InternalType() ) { \
	case TYPE_INTERNAL_INT: \
		{ \
		VEC_OP1_KERNEL(AsInt, IntVal, op) \
		break; \
		} \
 \
	case TYPE_INTERNAL_UNSIGNED: \
		{ \
		VEC_OP1_KERNEL(AsCount, CountVal, op) \
		break; \
		} \
 \
	double_kernel \
 \
	default: \
		break; \
	} \
 \
	return v_result; \
	}

#define VEC_OP1_WITH_DOUBLE(name, op) \
	VEC_OP1(name, op, case TYPE_INTERNAL_DOUBLE: { VEC_OP1_KERNEL(AsDouble, DoubleVal, op) break; })

VEC_OP1_WITH_DOUBLE(pos, +)
VEC_OP1_WITH_DOUBLE(neg, -)
VEC_OP1(not, !,)
VEC_OP1(comp, ~,)

#define VEC_OP2_KERNEL(accessor, type, op) \
	for ( unsigned int i = 0; i < v1->Size(); ++i ) \
		{ \
		auto v1_i = v1->At(i)->accessor(); \
		auto v2_i = v2->At(i)->accessor(); \
		v_result->Assign(i, make_intrusive<type>(v1_i op v2_i)); \
		}

#define VEC_OP2(name, op, double_kernel) \
VectorValPtr vec_op_ ## name ## __CPP(const VectorValPtr& v1, const VectorValPtr& v2) \
	{ \
	if ( ! check_vec_sizes(v1, v2) ) \
		return nullptr; \
 \
	auto vt = v1->GetType<VectorType>(); \
	auto v_result = make_intrusive<VectorVal>(vt); \
 \
	switch ( vt->InternalType() ) { \
	case TYPE_INTERNAL_INT: \
		{ \
		VEC_OP2_KERNEL(AsInt, IntVal, op) \
		break; \
		} \
 \
	case TYPE_INTERNAL_UNSIGNED: \
		{ \
		VEC_OP2_KERNEL(AsCount, CountVal, op) \
		break; \
		} \
 \
	double_kernel \
 \
	default: \
		break; \
	} \
 \
	return v_result; \
	}

#define VEC_OP2_WITH_DOUBLE(name, op) \
	VEC_OP2(name, op, case TYPE_INTERNAL_DOUBLE: { VEC_OP2_KERNEL(AsDouble, DoubleVal, op) break; })

VEC_OP2_WITH_DOUBLE(add, +)
VEC_OP2_WITH_DOUBLE(sub, -)
VEC_OP2_WITH_DOUBLE(mul, *)
VEC_OP2_WITH_DOUBLE(div, /)
VEC_OP2(mod, %,)
VEC_OP2(and, &,)
VEC_OP2(or, |,)
VEC_OP2(xor, ^,)
VEC_OP2(andand, &&,)
VEC_OP2(oror, ||,)

#define VEC_REL_OP(name, op) \
VectorValPtr vec_op_ ## name ## __CPP(const VectorValPtr& v1, const VectorValPtr& v2) \
	{ \
	if ( ! check_vec_sizes(v1, v2) ) \
		return nullptr; \
 \
	auto vt = v1->GetType<VectorType>(); \
	auto res_type = make_intrusive<VectorType>(base_type(TYPE_BOOL)); \
	auto v_result = make_intrusive<VectorVal>(res_type); \
 \
	switch ( vt->InternalType() ) { \
	case TYPE_INTERNAL_INT: \
		{ \
		VEC_OP2_KERNEL(AsInt, BoolVal, op) \
		break; \
		} \
 \
	case TYPE_INTERNAL_UNSIGNED: \
		{ \
		VEC_OP2_KERNEL(AsCount, BoolVal, op) \
		break; \
		} \
 \
	case TYPE_INTERNAL_DOUBLE: \
		{ \
		VEC_OP2_KERNEL(AsDouble, BoolVal, op) \
		break; \
		} \
 \
	default: \
		break; \
	} \
 \
	return v_result; \
	}

VEC_REL_OP(lt, <)
VEC_REL_OP(gt, >)
VEC_REL_OP(eq, ==)
VEC_REL_OP(ne, !=)
VEC_REL_OP(le, <=)
VEC_REL_OP(ge, >=)

// The following are to support ++/-- operations on vectors.
VectorValPtr vec_op_add__CPP(VectorValPtr v, int incr)
	{
	const auto& yt = v->GetType()->Yield();
	auto is_signed = yt->InternalType() == TYPE_INTERNAL_INT;
	auto n = v->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		auto v_i = v->At(i);
		ValPtr new_v_i;

		if ( is_signed )
			new_v_i = val_mgr->Int(v_i->AsInt() + incr);
		else
			new_v_i = val_mgr->Count(v_i->AsCount() + incr);

		v->Assign(i, new_v_i);
		}

	return v;
	}

VectorValPtr vec_op_sub__CPP(VectorValPtr v, int i)
	{
	return vec_op_add__CPP(std::move(v), -i);
	}
