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
#include "zeek/RunState.h"
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

// An initialization hook for a collection of compiled-to-C++ functions
// (the result of a single invocation of the compiler on a set of scripts).
typedef void (*CPP_init_func)();

// Tracks the initialization hooks for different compilation runs.
std::vector<CPP_init_func> CPP_init_funcs;

// Calls all of the initialization hooks, in the order they were added.
void init_CPPs()
	{
	for ( auto f : CPP_init_funcs )
		f();
	}

// This is a trick used to register the presence of compiled code.
// The initialization of the static variable will make CPP_init_hook
// non-null, which the main part of Zeek uses to tell that there's
// CPP code available.
int flag_init_CPP()
	{
	CPP_init_hook = init_CPPs;
	return 0;
	}

static int dummy = flag_init_CPP();


// Registers the given compiled function body as associated
// with the given hash.  "events" is a list of event handlers
// relevant for the function body, which should be registered if
// the function body is going to be used.
void register_body__CPP(CPPStmtPtr body, hash_type hash,
			std::vector<std::string> events)
	{
	compiled_scripts[hash] = { std::move(body), std::move(events) };
	}

// Registers a lambda body as associated with the given hash.  Includes
// the name of the lambda (so it can be made available as a quasi-global
// identifier), its type, and whether it needs captures.
void register_lambda__CPP(CPPStmtPtr body, hash_type hash, const char* name,
			  TypePtr t, bool has_captures)
	{
	auto ft = cast_intrusive<FuncType>(t);

	// Create the quasi-global.
	auto id = install_ID(name, GLOBAL_MODULE_NAME, true, false);
	auto func = make_intrusive<CPPLambdaFunc>(name, ft, body);
	func->SetName(name);

	auto v = make_intrusive<FuncVal>(std::move(func));
	id->SetVal(std::move(v));
	id->SetType(ft);

	// Lambdas used in initializing global functions need to
	// be registered, so that the initialization can find them.
	// We do not, however, want to register *all* lambdas, because
	// the ones that use captures cannot be used as regular
	// function bodies.
	if ( ! has_captures )
		// Note, no support for lambdas that themselves refer
		// to events.
		register_body__CPP(body, hash, {});
	}

// Looks for a global with the given name.  If not present, creates it
// with the given type.
IDPtr lookup_global__CPP(const char* g, const TypePtr& t)
	{
	auto gl = lookup_ID(g, GLOBAL_MODULE_NAME, false, false, false);

	if ( ! gl )
		{
		gl = install_ID(g, GLOBAL_MODULE_NAME, true, false);
		gl->SetType(t);
		}

	return gl;
	}

// Looks for a BiF with the given name.  Returns nil if not present.
Func* lookup_bif__CPP(const char* bif)
	{
	auto b = lookup_ID(bif, GLOBAL_MODULE_NAME, false, false, false);
	return b ? b->GetVal()->AsFunc() : nullptr;
	}

// For the function body associated with the given hash, creates and
// returns an associated FuncVal.  It's a fatal error for the hash
// not to exist, because this function should only be called by compiled
// code that has ensured its existence.
FuncValPtr lookup_func__CPP(std::string name, hash_type h, const TypePtr& t)
	{
	ASSERT(compiled_scripts.count(h) > 0);

	const auto& f = compiled_scripts[h];
	auto ft = cast_intrusive<FuncType>(t);
	auto sf = make_intrusive<ScriptFunc>(std::move(name), std::move(ft), f.body);

	for ( auto& e : f.events )
		{
		auto eh = event_registry->Register(e);
		eh->SetUsed();
		}

	return make_intrusive<FuncVal>(std::move(sf));
	}

// Returns the concatenation of the given strings.
StringValPtr str_concat__CPP(const String* s1, const String* s2)
	{
	std::vector<const String*> strings(2);
	strings[0] = s1;
	strings[1] = s2;

	return make_intrusive<StringVal>(concatenate(strings));
	}

// Returns true if string "s2" is in string "s1".
bool str_in__CPP(const String* s1, const String* s2)
	{
	auto s = reinterpret_cast<const unsigned char*>(s1->CheckString());
	return util::strstr_n(s2->Len(), s2->Bytes(), s1->Len(), s) != -1;
	}

// Converts a vector of individual ValPtr's into a single ListValPtr
// suitable for indexing an aggregate.
ListValPtr index_val__CPP(std::vector<ValPtr> indices)
	{
	auto ind_v = make_intrusive<ListVal>(TYPE_ANY);

	// In the future, we could provide N versions of this that
	// unroll the loop.
	for ( auto i : indices )
		ind_v->Append(i);

	return ind_v;
	}

// Returns the value corresponding to indexing the given table with
// the given set of indices.  This is a function rather than something
// generated directly so that it can package up the error handling
// for the case where there's no such item in the table.
ValPtr index_table__CPP(const TableValPtr& t, std::vector<ValPtr> indices)
	{
	auto v = t->FindOrDefault(index_val__CPP(std::move(indices)));
	if ( ! v )
		reporter->CPPRuntimeError("no such index");
	return v;
	}

// Same, for indexing vectors.
ValPtr index_vec__CPP(const VectorValPtr& vec, int index)
	{
	auto v = vec->At(index);
	if ( ! v )
		reporter->CPPRuntimeError("no such index");
	return v;
	}

// Same, for indexing strings.
ValPtr index_string__CPP(const StringValPtr& svp, std::vector<ValPtr> indices)
	{
	return index_string(svp->AsString(),
				index_val__CPP(std::move(indices)).get());
	}

// Calls out to the given script or BiF function.  A separate function because
// of the need to (1) construct the "args" vector using {} initializers,
// but (2) needing to have the address of that vector.
inline ValPtr invoke__CPP(Func* f, std::vector<ValPtr> args, Frame* frame)
	{
	return f->Invoke(&args, frame);
	}

// Assigns the given value to the given global.  A separate function because
// we also need to return the value, for use in assignment cascades.
ValPtr set_global__CPP(IDPtr g, ValPtr v)
	{
	g->SetVal(v);
	return v;
	}

// Assigns the given global to the given value, which corresponds to an
// event handler.
ValPtr set_event__CPP(IDPtr g, ValPtr v, EventHandlerPtr& gh)
	{
	g->SetVal(std::move(v));
	gh = event_registry->Register(g->Name());
	return v;
	}

// Convert (in terms of the Zeek language) the given value to the given type.
// A separate function in order to package up the error handling.
ValPtr cast_value_to_type__CPP(const ValPtr& v, const TypePtr& t)
	{
	auto result = cast_value_to_type(v.get(), t.get());
	if ( ! result )
		reporter->CPPRuntimeError("invalid cast of value with type '%s' to type '%s'",
			type_name(v->GetType()->Tag()), type_name(t->Tag()));
	return result;
	}

// Returns the subnet corresponding to the given mask of the given address.
// A separate function in order to package up the error handling.
SubNetValPtr addr_mask__CPP(const IPAddr& a, uint32_t mask)
	{
        if ( a.GetFamily() == IPv4 )
                {
                if ( mask > 32 )
                        reporter->CPPRuntimeError("bad IPv4 subnet prefix length: %d", int(mask));
                }
        else
                {
                if ( mask > 128 )
                        reporter->CPPRuntimeError("bad IPv6 subnet prefix length: %d", int(mask));
                }

        return make_intrusive<SubNetVal>(a, mask);
	}

// Assigns the given field in the given record to the given value.  A
// separate function to allow for assignment cascades.
ValPtr assign_field__CPP(RecordValPtr rec, int field, ValPtr v)
	{
	rec->Assign(field, v);
	return v;
	}

// Returns the given field in the given record.  A separate function to
// support error handling.
ValPtr field_access__CPP(const RecordValPtr& rec, int field)
	{
	auto v = rec->GetFieldOrDefault(field);
	if ( ! v )
		reporter->CPPRuntimeError("field value missing");

	return v;
	}

// Helper function for reporting invalidation of interators.
static void check_iterators__CPP(bool invalid)
	{
	if ( invalid )
		reporter->Warning("possible loop/iterator invalidation in compiled code");
	}

template <typename T>
ValPtr assign_to_index__CPP(T v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated = false;
	auto err_msg = zeek::detail::assign_to_index(std::move(v1),
							std::move(v2), v3,
							iterators_invalidated);

	check_iterators__CPP(iterators_invalidated);

	if ( err_msg )
		reporter->CPPRuntimeError("%s", err_msg);

	return v3;
	}

// Using shims for the following, each of which executes the
// assignment "v1[v2] = v3" for tables/vectors/strings, keeps
// the generation logic in the compiler simple.
ValPtr assign_to_index__CPP(TableValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<TableValPtr>(v1, v2, v3);
	}
ValPtr assign_to_index__CPP(VectorValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<VectorValPtr>(v1, v2, v3);
	}
ValPtr assign_to_index__CPP(StringValPtr v1, ValPtr v2, ValPtr v3)
	{
	return assign_to_index__CPP<StringValPtr>(v1, v2, v3);
	}

// Executes an "add" statement for the given set.
void add_element__CPP(TableValPtr aggr, ListValPtr indices)
	{
	bool iterators_invalidated = false;
	aggr->Assign(indices, nullptr, true, &iterators_invalidated);
	check_iterators__CPP(iterators_invalidated);
	}

// Executes a "delete" statement for the given set.
void remove_element__CPP(TableValPtr aggr, ListValPtr indices)
	{
	bool iterators_invalidated = false;
	aggr->Remove(*indices.get(), true, &iterators_invalidated);
	check_iterators__CPP(iterators_invalidated);
	}

// Appends v2 to the vector v1.  A separate function because of the
// need to support assignment cascades.
ValPtr vector_append__CPP(VectorValPtr v1, ValPtr v2)
	{
	v1->Assign(v1->Size(), v2);
	return v2;
	}

// Returns the given table/set (which should be empty) coerced to
// the given Zeek type.  A separate function in order to deal with
// error handling.
TableValPtr table_coerce__CPP(const ValPtr& v, const TypePtr& t)
	{
	TableVal* tv = v->AsTableVal();

	if ( tv->Size() > 0 )
		reporter->CPPRuntimeError("coercion of non-empty table/set");

	return make_intrusive<TableVal>(cast_intrusive<TableType>(t),
					tv->GetAttrs());
	}

// The same, for an empty record.
VectorValPtr vector_coerce__CPP(const ValPtr& v, const TypePtr& t)
	{
	VectorVal* vv = v->AsVectorVal();

	if ( vv->Size() > 0 )
		reporter->CPPRuntimeError("coercion of non-empty vector");

	return make_intrusive<VectorVal>(cast_intrusive<VectorType>(t));
	}

// A helper function that takes a parallel vectors of attribute tags
// and values and returns a collective AttributesPtr corresponding to
// those instantiated attributes.  For attributes that don't have
// associated expressions, the correspoinding value should be nil.
static AttributesPtr build_attrs__CPP(std::vector<int> attr_tags,
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

// Constructs a set of the given type, containing the given elements, and
// with the associated attributes.
TableValPtr set_constructor__CPP(std::vector<ValPtr> elements, TableTypePtr t,
					std::vector<int> attr_tags,
					std::vector<ValPtr> attr_vals)
	{
	auto attrs = build_attrs__CPP(std::move(attr_tags), std::move(attr_vals));
	auto aggr = make_intrusive<TableVal>(std::move(t), std::move(attrs));

	for ( const auto& elem : elements )
		aggr->Assign(std::move(elem), nullptr);

	return aggr;
	}

// Constructs a set of the given type, containing the given elements
// (specified as parallel index/value vectors), and with the associated
// attributes.
TableValPtr table_constructor__CPP(std::vector<ValPtr> indices,
					std::vector<ValPtr> vals,
					TableTypePtr t,
					std::vector<int> attr_tags,
					std::vector<ValPtr> attr_vals)
	{
	const auto& yt = t->Yield().get();
	auto n = indices.size();

	auto attrs = build_attrs__CPP(std::move(attr_tags), std::move(attr_vals));
	auto aggr = make_intrusive<TableVal>(std::move(t), std::move(attrs));

	for ( auto i = 0; i < n; ++i )
		{
		auto v = check_and_promote(vals[i], yt, true);
		if ( v )
			aggr->Assign(std::move(indices[i]), std::move(v));
		}

	return aggr;
	}

// Constructs a record of the given type, whose (ordered) fields are
// assigned to the corresponding elements of the given vector of values.
RecordValPtr record_constructor__CPP(std::vector<ValPtr> vals, RecordTypePtr t)
	{
	auto rv = make_intrusive<RecordVal>(std::move(t));
	auto n = vals.size();

	rv->Reserve(n);

	for ( auto i = 0; i < n; ++i )
		rv->Assign(i, vals[i]);

	return rv;
	}

// Constructs a vector of the given type, populated with the given values.
VectorValPtr vector_constructor__CPP(std::vector<ValPtr> vals, VectorTypePtr t)
	{
	auto vv = make_intrusive<VectorVal>(std::move(t));
	auto n = vals.size();

	for ( auto i = 0; i < n; ++i )
		vv->Assign(i, vals[i]);

	return vv;
	}

// Schedules an event to occur at the given absolute time, parameterized
// with the given set of values.  A separate function to facilitate avoiding
// the scheduling if Zeek is terminating.
ValPtr schedule__CPP(double dt, EventHandlerPtr event, std::vector<ValPtr> args)
	{
	if ( ! run_state::terminating )
		timer_mgr->Add(new ScheduleTimer(event, std::move(args), dt));

	return nullptr;
	}

// Returns the record corresponding to the given name, as long as the
// name is indeed a record type.  Otherwise (or if the name is nil)
// creates a new empty record.
RecordTypePtr get_record_type__CPP(const char* record_type_name)
	{
	IDPtr existing_type;

	if ( record_type_name &&
	     (existing_type = global_scope()->Find(record_type_name)) &&
	      existing_type->GetType()->Tag() == TYPE_RECORD )
		return cast_intrusive<RecordType>(existing_type->GetType());

	return make_intrusive<RecordType>(new type_decl_list());
	}

// Returns the "enum" type corresponding to the given name, as long as
// the name is indeed an enum type.  Otherwise, creates a new enum
// type with the given name.
EnumTypePtr get_enum_type__CPP(const std::string& enum_type_name)
	{
	auto existing_type = global_scope()->Find(enum_type_name);

	if ( existing_type && existing_type->GetType()->Tag() == TYPE_ENUM )
		return cast_intrusive<EnumType>(existing_type->GetType());
	else
		return make_intrusive<EnumType>(enum_type_name);
	}

// Returns an enum value corresponding to the given low-level value 'i'
// in the context of the given enum type 't'.
EnumValPtr make_enum__CPP(TypePtr t, int i)
	{
	auto et = cast_intrusive<EnumType>(std::move(t));
	return make_intrusive<EnumVal>(et, i);
	}

// Simple helper functions for supporting absolute value.
bro_uint_t abs__CPP(bro_int_t v)
	{
	return v < 0 ? -v : v;
	}

double abs__CPP(double v)
	{
	return v < 0.0 ? -v : v;
	}

// Helper function for ensuring that two vectors have matching sizes.
static bool check_vec_sizes__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	if ( v1->Size() == v2->Size() )
		return true;

	reporter->CPPRuntimeError("vector operands are of different sizes");
	return false;
	}

// Helper function that returns a VectorTypePtr apt for use with the
// the given yield type.  We don't just use the yield type directly
// because here we're supporting low-level arithmetic operations
// (for example, adding one vector of "interval" to another), which
// we want to do using the low-level representations.  We'll later
// convert the vector to the high-level representation if needed.
static VectorTypePtr base_vector_type__CPP(const VectorTypePtr& vt)
	{
	switch ( vt->Yield()->InternalType() ) {
	case TYPE_INTERNAL_INT:
		return make_intrusive<VectorType>(base_type(TYPE_INT));

	case TYPE_INTERNAL_UNSIGNED:
		return make_intrusive<VectorType>(base_type(TYPE_COUNT));

	case TYPE_INTERNAL_DOUBLE:
		return make_intrusive<VectorType>(base_type(TYPE_DOUBLE));

	default:
		return nullptr;
	}
	}

// The kernel used for unary vector operations.
#define VEC_OP1_KERNEL(accessor, type, op) \
	for ( unsigned int i = 0; i < v->Size(); ++i ) \
		{ \
		auto v_i = v->At(i)->accessor(); \
		v_result->Assign(i, make_intrusive<type>(op v_i)); \
		}

// A macro (since it's beyond my templating skillz to deal with the
// "op" operator) for unary vector operations, invoking the kernel
// per the underlying representation used by the vector.  "double_kernel"
// is an optional kernel to use for vectors whose underlying type
// is "double".  It needs to be optional because C++ will (rightfully)
// complain about applying certain C++ unary operations to doubles.
#define VEC_OP1(name, op, double_kernel) \
VectorValPtr vec_op_ ## name ## __CPP(const VectorValPtr& v) \
	{ \
	auto vt = base_vector_type__CPP(v->GetType<VectorType>()); \
	auto v_result = make_intrusive<VectorVal>(vt); \
 \
	switch ( vt->Yield()->InternalType() ) { \
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

// Instantiates a double_kernel for a given operation.
#define VEC_OP1_WITH_DOUBLE(name, op) \
	VEC_OP1(name, op, case TYPE_INTERNAL_DOUBLE: { VEC_OP1_KERNEL(AsDouble, DoubleVal, op) break; })

// The unary operations supported for vectors.
VEC_OP1_WITH_DOUBLE(pos, +)
VEC_OP1_WITH_DOUBLE(neg, -)
VEC_OP1(not, !,)
VEC_OP1(comp, ~,)

// A kernel for applying a binary operation element-by-element to two
// vectors of a given low-level type.
#define VEC_OP2_KERNEL(accessor, type, op) \
	for ( unsigned int i = 0; i < v1->Size(); ++i ) \
		{ \
		auto v1_i = v1->At(i)->accessor(); \
		auto v2_i = v2->At(i)->accessor(); \
		v_result->Assign(i, make_intrusive<type>(v1_i op v2_i)); \
		}

// Analogous to VEC_OP1, instantiates a function for a given binary operation,
// which might-or-might-not be supported for low-level "double" types.
// This version is for operations whose result type is the same as the
// operand type.
#define VEC_OP2(name, op, double_kernel) \
VectorValPtr vec_op_ ## name ## __CPP(const VectorValPtr& v1, const VectorValPtr& v2) \
	{ \
	if ( ! check_vec_sizes__CPP(v1, v2) ) \
		return nullptr; \
 \
	auto vt = base_vector_type__CPP(v1->GetType<VectorType>()); \
	auto v_result = make_intrusive<VectorVal>(vt); \
 \
	switch ( vt->Yield()->InternalType() ) { \
	case TYPE_INTERNAL_INT: \
		{ \
		if ( vt->Yield()->Tag() == TYPE_BOOL ) \
			VEC_OP2_KERNEL(AsBool, BoolVal, op) \
		else \
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

// Instantiates a double_kernel for a binary operation.
#define VEC_OP2_WITH_DOUBLE(name, op) \
	VEC_OP2(name, op, case TYPE_INTERNAL_DOUBLE: { VEC_OP2_KERNEL(AsDouble, DoubleVal, op) break; })

// The binary operations supported for vectors.
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

// A version of VEC_OP2 that instead supports relational operations, so
// the result type is always vector-of-bool.
#define VEC_REL_OP(name, op) \
VectorValPtr vec_op_ ## name ## __CPP(const VectorValPtr& v1, const VectorValPtr& v2) \
	{ \
	if ( ! check_vec_sizes__CPP(v1, v2) ) \
		return nullptr; \
 \
	auto vt = v1->GetType<VectorType>(); \
	auto res_type = make_intrusive<VectorType>(base_type(TYPE_BOOL)); \
	auto v_result = make_intrusive<VectorVal>(res_type); \
 \
	switch ( vt->Yield()->InternalType() ) { \
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

// The relational operations supported for vectors.
VEC_REL_OP(lt, <)
VEC_REL_OP(gt, >)
VEC_REL_OP(eq, ==)
VEC_REL_OP(ne, !=)
VEC_REL_OP(le, <=)
VEC_REL_OP(ge, >=)

// The following are to support ++/-- operations on vectors ...

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

// ... and these for vector-plus-scalar string operations.

// This function provides the core functionality.  The arguments
// are applied as though they appeared left-to-right in a statement
// "s1 + v2 + v3 + s4".  For any invocation, v2 will always be
// non-nil, and one-and-only-one of s1, v3, or s4 will be non-nil.
VectorValPtr str_vec_op_str_vec_add__CPP(const StringValPtr& s1,
					const VectorValPtr& v2,
					const VectorValPtr& v3,
					const StringValPtr& s4)
	{
	auto vt = v2->GetType<VectorType>();
	auto v_result = make_intrusive<VectorVal>(vt);
	auto n = v2->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		std::vector<const String*> strings;

		auto v2_i = v2->At(i);
		if ( ! v2_i )
			continue;

		auto s2 = v2_i->AsString();
		const String* s3 = nullptr;

		if ( v3 )
			{
			auto v3_i = v3->At(i);
			if ( ! v3_i )
				continue;
			s3 = v3_i->AsString();
			}

		if ( s1 ) strings.push_back(s1->AsString());
		strings.push_back(s2);
		if ( s3 ) strings.push_back(s3);
		if ( s4 ) strings.push_back(s4->AsString());

		auto res = make_intrusive<StringVal>(concatenate(strings));
		v_result->Assign(i, res);
		}

	return v_result;
	}

// Vector operations to add strings, with at least one operand being a
// vector, and the other either a vector or a scalar string.
VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_str_vec_add__CPP(nullptr, v1, v2, nullptr);
	}

VectorValPtr str_vec_op_add__CPP(const VectorValPtr& v1, const StringValPtr& s2)
	{
	return str_vec_op_str_vec_add__CPP(nullptr, v1, nullptr, s2);
	}

VectorValPtr str_vec_op_add__CPP(const StringValPtr& s1, const VectorValPtr& v2)
	{
	return str_vec_op_str_vec_add__CPP(s1, v2, nullptr, nullptr);
	}

// Kernel for element-by-element string relationals.  "rel1" and "rel2"
// codify which relational (</<=/==/!=/>=/>) we're aiming to support,
// in terms of how a Bstr_cmp() comparison should be assessed.
static VectorValPtr str_vec_op_kernel__CPP(const VectorValPtr& v1,
				           const VectorValPtr& v2,
					   int rel1, int rel2)
	{
	auto res_type = make_intrusive<VectorType>(base_type(TYPE_BOOL));
	auto v_result = make_intrusive<VectorVal>(res_type);
	auto n = v1->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		auto v1_i = v1->At(i);
		auto v2_i = v2->At(i);
		if ( ! v1_i || ! v2_i )
			continue;

		auto s1 = v1_i->AsString();
		auto s2 = v2_i->AsString();

		auto cmp = Bstr_cmp(s1, s2);
		auto rel = (cmp == rel1) || (cmp == rel2);

		v_result->Assign(i, val_mgr->Bool(rel));
		}

	return v_result;
	}

// Kernel wrappers to support specific string vector relationals.
VectorValPtr str_vec_op_lt__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, -1, -1);
	}

VectorValPtr str_vec_op_le__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, -1, 0);
	}

VectorValPtr str_vec_op_eq__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, 0, 0);
	}

VectorValPtr str_vec_op_ne__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, -1, 1);
	}

VectorValPtr str_vec_op_gt__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, 1, 1);
	}

VectorValPtr str_vec_op_ge__CPP(const VectorValPtr& v1, const VectorValPtr& v2)
	{
	return str_vec_op_kernel__CPP(v1, v2, 0, 1);
	}

// Support for vector conditional ('?:') expressions.  Using the boolean
// vector v1 as a selector, returns a new vector populated with the
// elements selected out of v2 and v3.
VectorValPtr vector_select__CPP(const VectorValPtr& v1, VectorValPtr v2,
				VectorValPtr v3)
	{
	auto vt = v2->GetType<VectorType>();
	auto v_result = make_intrusive<VectorVal>(vt);

	if ( ! check_vec_sizes__CPP(v1, v2) || ! check_vec_sizes__CPP(v1, v3) )
		return nullptr;

	auto n = v1->Size();

	for ( unsigned int i = 0; i < n; ++i )
		{
		auto vr_i = v1->At(i)->AsBool() ? v2->At(i) : v3->At(i);
		v_result->Assign(i, std::move(vr_i));
		}

	return v_result;
	}

// Returns a new vector reflecting the given vector coerced to the given
// type.  Assumes v already has the correct internal type.  This can go
// away after we finish migrating to ZVal's.
VectorValPtr vector_coerce_to__CPP(const VectorValPtr& v, const TypePtr& targ)
	{
	auto res_t = cast_intrusive<VectorType>(targ);
	auto v_result = make_intrusive<VectorVal>(std::move(res_t));
	auto n = v->Size();
	auto yt = targ->Yield();
	auto ytag = yt->Tag();

	for ( unsigned int i = 0; i < n; ++i )
		{
		ValPtr v_i = v->At(i);
		ValPtr r_i;
		switch ( ytag ) {
		case TYPE_BOOL:
			r_i = val_mgr->Bool(v_i->AsBool());
			break;

		case TYPE_ENUM:
			r_i = yt->AsEnumType()->GetEnumVal(v_i->AsInt());
			break;

		case TYPE_PORT:
			r_i = make_intrusive<PortVal>(v_i->AsCount());
			break;

		case TYPE_INTERVAL:
			r_i = make_intrusive<IntervalVal>(v_i->AsDouble());
			break;

		case TYPE_TIME:
			r_i = make_intrusive<TimeVal>(v_i->AsDouble());
			break;

		default:
			reporter->InternalError("bad vector type in vector_coerce_to__CPP");
		}

		v_result->Assign(i, std::move(r_i));
		}

	return v_result;
	}

// Similar coercion, but works for v having perhaps not the correct type.
VectorValPtr vec_coerce_to_bro_int_t__CPP(const VectorValPtr& v, TypePtr targ)
	{
	auto res_t = cast_intrusive<VectorType>(targ);
	auto v_result = make_intrusive<VectorVal>(std::move(res_t));
	auto n = v->Size();

	for ( unsigned int i = 0; i < n; ++i )
		v_result->Assign(i, val_mgr->Int(v->At(i)->CoerceToInt()));

	return v_result;
	}

// Same for Unsigned ...
VectorValPtr vec_coerce_to_bro_uint_t__CPP(const VectorValPtr& v, TypePtr targ)
	{
	auto res_t = cast_intrusive<VectorType>(targ);
	auto v_result = make_intrusive<VectorVal>(std::move(res_t));
	auto n = v->Size();

	for ( unsigned int i = 0; i < n; ++i )
		v_result->Assign(i, val_mgr->Count(v->At(i)->CoerceToUnsigned()));

	return v_result;
	}

// ... and Double.
VectorValPtr vec_coerce_to_double__CPP(const VectorValPtr& v, TypePtr targ)
	{
	auto res_t = cast_intrusive<VectorType>(targ);
	auto v_result = make_intrusive<VectorVal>(std::move(res_t));
	auto n = v->Size();

	for ( unsigned int i = 0; i < n; ++i )
		v_result->Assign(i, make_intrusive<DoubleVal>(v->At(i)->CoerceToDouble()));

	return v_result;
	}

// The following operations are provided using functions to support
// error checking/reporting.
bro_int_t div__CPP(bro_int_t v1, bro_int_t v2)
	{
	if ( v2 == 0 )
		reporter->CPPRuntimeError("division by zero");
	return v1 / v2;
	}

bro_int_t mod__CPP(bro_int_t v1, bro_int_t v2)
	{
	if ( v2 == 0 )
		reporter->CPPRuntimeError("modulo by zero");
	return v1 % v2;
	}

bro_uint_t div__CPP(bro_uint_t v1, bro_uint_t v2)
	{
	if ( v2 == 0 )
		reporter->CPPRuntimeError("division by zero");
	return v1 / v2;
	}

bro_uint_t mod__CPP(bro_uint_t v1, bro_uint_t v2)
	{
	if ( v2 == 0 )
		reporter->CPPRuntimeError("modulo by zero");
	return v1 % v2;
	}

double div__CPP(double v1, double v2)
	{
	if ( v2 == 0.0 )
		reporter->CPPRuntimeError("division by zero");
	return v1 / v2;
	}
