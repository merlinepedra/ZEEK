#include "zeek/Func.h"
#include "zeek/RE.h"
#include "zeek/Val.h"
#include "zeek/Expr.h"
#include "zeek/OpaqueVal.h"
#include "zeek/ZeekString.h"

namespace zeek {

using BoolValPtr = IntrusivePtr<zeek::BoolVal>;
using CountValPtr = IntrusivePtr<zeek::CountVal>;
using DoubleValPtr = IntrusivePtr<zeek::DoubleVal>;
using StringValPtr = IntrusivePtr<zeek::StringVal>;
using IntervalValPtr = IntrusivePtr<zeek::IntervalVal>;
using PatternValPtr = IntrusivePtr<zeek::PatternVal>;
using FuncValPtr = IntrusivePtr<zeek::FuncVal>;
using SubNetValPtr = IntrusivePtr<zeek::SubNetVal>;

namespace detail {

// Helper functions.

extern TypePtr types__CPP[];
Val* index_table__CPP(TableVal* t, std::vector<ValPtr> indices);
// std::vector<const String*> strings;
// strings.push_back(s1);
// strings.push_back(s2);
//
//return make_intrusive<StringVal>(concatenate(strings));
StringVal* str_concat__CPP(const String* s1, const String* s2);

ValPtr index_val__CPP(std::vector<ValPtr> indices);
ValPtr invoke__CPP(Func* f, std::vector<ValPtr> args) { return f->Invoke(&args, nullptr); }
template <typename T>
IntrusivePtr<T> val_to_valptr__CPP(T* v) { return {NewRef{}, v}; }

void assign_to_index__CPP(ValPtr v1, ValPtr v2, ValPtr v3)
	{
	bool iterators_invalidated;
	auto err_msg = zeek::detail::assign_to_index(v1, v2, v3, iterators_invalidated);
	if ( err_msg ) reporter->Error("%s", err_msg);
	}

RecordVal* record_coerce();
TableVal* table_coerce();
RecordVal* record_constructor();
TableVal* table_constructor();
TableVal* set_constructor();
VectorVal* vector_constructor();
void schedule();
