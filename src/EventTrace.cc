// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/EventTrace.h"
#include "zeek/IPAddr.h"
#include "zeek/Reporter.h"
#include "zeek/ZeekString.h"


namespace zeek::detail
	{

ValTrace::ValTrace(const ValPtr& _v)
	{
	v = _v;
	t = v->GetType();

	switch ( t->Tag() )
		{
		case TYPE_LIST:
			TraceList(cast_intrusive<ListVal>(v));
			break;

		case TYPE_RECORD:
			TraceRecord(cast_intrusive<RecordVal>(v));
			break;

		case TYPE_TABLE:
			TraceTable(cast_intrusive<TableVal>(v));
			break;

		case TYPE_VECTOR:
			TraceVector(cast_intrusive<VectorVal>(v));
			break;

		default:
			break;
		}
	}

ValTrace::~ValTrace()
	{
	}

bool ValTrace::operator==(const ValTrace& vt) const
	{
	auto& vt_v = vt.GetVal();
	if ( vt_v == v )
		return true;

	auto tag = t->Tag();

	if ( vt.GetType()->Tag() != tag )
		return false;

	switch ( tag )
		{
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_ENUM:
			return v->AsInt() == vt_v->AsInt();

		case TYPE_COUNT:
		case TYPE_PORT:
			return v->AsCount() == vt_v->AsCount();

		case TYPE_DOUBLE:
		case TYPE_INTERVAL:
		case TYPE_TIME:
			return v->AsDouble() == vt_v->AsDouble();

		case TYPE_STRING:
			return (*v->AsString()) == (*vt_v->AsString());

		case TYPE_ADDR:
			return v->AsAddr() == vt_v->AsAddr();

		case TYPE_SUBNET:
			return v->AsSubNet() == vt_v->AsSubNet();

		case TYPE_FUNC:
			return v->AsFile() == vt_v->AsFile();

		case TYPE_FILE:
			return v->AsFile() == vt_v->AsFile();

		case TYPE_PATTERN:
			return v->AsPattern() == vt_v->AsPattern();

		case TYPE_ANY:
			return v->AsSubNet() == vt_v->AsSubNet();

		case TYPE_TYPE:
			return v->AsType() == vt_v->AsType();

		case TYPE_OPAQUE:
			return false; // needs pointer equivalence

		case TYPE_LIST:
			return SameList(vt);

		case TYPE_RECORD:
			return SameRecord(vt);

		case TYPE_TABLE:
			return SameTable(vt);

		case TYPE_VECTOR:
			return SameVector(vt);

		default:
			reporter->InternalError("bad type in ValTrace::operator==");
		}
	}

void ValTrace::ComputeDelta(const ValTrace& prev, DeltaVector& deltas) const
	{
	auto tag = t->Tag();

	ASSERT(prev.GetType()->Tag() == tag);

	auto& prev_v = prev.GetVal();

	if ( prev_v != v )
		{
		if ( *this != prev )
			deltas.emplace_back(DeltaReplaceValue(this, v));
		return;
		}

	switch ( tag )
		{
		case TYPE_BOOL:
		case TYPE_INT:
		case TYPE_ENUM:
		case TYPE_COUNT:
		case TYPE_PORT:
		case TYPE_DOUBLE:
		case TYPE_INTERVAL:
		case TYPE_TIME:
		case TYPE_STRING:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_FUNC:
		case TYPE_FILE:
		case TYPE_OPAQUE:
		case TYPE_PATTERN:
		case TYPE_ANY:
		case TYPE_TYPE:
			// These don't change in place.
			break;

		case TYPE_LIST:
			// We shouldn't see these exposed directly, as
			// they're not manipulable at script-level.
			reporter->InternalError("list type seen in ValTrace::ComputeDelta");
			break;

		case TYPE_RECORD:
			ComputeRecordDelta(prev, deltas);
			break;

		case TYPE_TABLE:
			ComputeTableDelta(prev, deltas);
			break;

		case TYPE_VECTOR:
			ComputeVectorDelta(prev, deltas);
			break;

		default:
			reporter->InternalError("bad type in ValTrace::ComputeDelta");
		}
	}

void ValTrace::TraceList(const ListValPtr& lv)
	{
	auto vals = lv->Vals();
	for ( auto& v : vals )
		elems.emplace_back(std::make_shared<ValTrace>(v));
	}

void ValTrace::TraceRecord(const RecordValPtr& rv)
	{
	auto n = rv->NumFields();
	auto rt = rv->GetType<RecordType>();

	for ( auto i = 0U; i < n; ++i )
		{
		auto f = rv->RawOptField(i);
		if ( f )
			{
			auto val = f->ToVal(rt->GetFieldType(i));
			elems.emplace_back(std::make_shared<ValTrace>(val));
			}
		else
			elems.emplace_back(nullptr);
		}
	}

void ValTrace::TraceTable(const TableValPtr& tv)
	{
	for ( auto& elem : tv->ToMap() )
		{
		auto& key = elem.first;
		elems.emplace_back(std::make_shared<ValTrace>(key));

		auto& val = elem.second;
		if ( val )
			elems2.emplace_back(std::make_shared<ValTrace>(val));
		}
	}

void ValTrace::TraceVector(const VectorValPtr& vv)
	{
	auto& vec = vv->RawVec();
	auto n = vec->size();
	auto& yt = vv->RawYieldType();
	auto& yts = vv->RawYieldTypes();

	for ( auto i = 0U; i < n; ++i )
		{
		auto& elem = (*vec)[i];
		if ( elem )
			{
			auto& t = yts ? (*yts)[i] : yt;
			auto val = elem->ToVal(t);
			elems.emplace_back(std::make_shared<ValTrace>(val));
			}
		else
			elems.emplace_back(nullptr);
		}
	}

bool ValTrace::SameList(const ValTrace& vt) const
	{
	return SameElems(vt);
	}

bool ValTrace::SameRecord(const ValTrace& vt) const
	{
	return SameElems(vt);
	}

bool ValTrace::SameTable(const ValTrace& vt) const
	{
	auto& vt_elems = vt.elems;
	auto n = elems.size();
	if ( n != vt_elems.size() )
		return false;

	auto& vt_elems2 = vt.elems2;
	auto n2 = elems2.size();
	if ( n2 != vt_elems2.size() )
		return false;

	ASSERT(n2 == 0 || n == n2);

	// We accommodate the possibility that keys are out-of-order
	// between the two sets of elements.

	// The following is O(N^2), but presumably if tables are somehow
	// involved (in fact we can only get here if they're used as
	// indices into other tables), then they'll likely be small.
	for ( auto i = 0U; i < n; ++i )
		{
		auto& elem_i = elems[i];

		// See if we can find a match for it.  If we do, we don't
		// have to worry that another entry matched it too, since
		// all table/set indices will be distinct.
		auto j = 0U;
		for ( ; j < n; ++j )
			{
			auto& vt_elem_j = vt_elems[j];
			if ( *elem_i == *vt_elem_j )
				break;
			}

		if ( j == n )
			// No match for the index.
			return false;

		if ( n2 > 0 )
			{
			// Need a match for the corresponding yield values.
			if ( *elems2[i] != *vt_elems2[j] )
				return false;
			}
		}

	return true;
	}

bool ValTrace::SameVector(const ValTrace& vt) const
	{
	return SameElems(vt);
	}

bool ValTrace::SameElems(const ValTrace& vt) const
	{
	auto& vt_elems = vt.elems;
	auto n = elems.size();
	if ( n != vt_elems.size() )
		return false;

	for ( auto i = 0U; i < n; ++i )
		{
		auto& trace_i = elems[i];
		auto& vt_trace_i = vt_elems[i];

		if ( trace_i && vt_trace_i )
			{
			if ( *trace_i != *vt_trace_i )
				return false;
			}

		else if ( trace_i || vt_trace_i )
			return false;
		}

	return true;
	}

void ValTrace::ComputeRecordDelta(const ValTrace& prev, DeltaVector& deltas) const
	{
	auto& prev_elems = prev.elems;
	auto n = elems.size();
	if ( n != prev_elems.size() )
		reporter->InternalError("size inconsistency in ValTrace::ComputeRecordDelta");

	for ( auto i = 0U; i < n; ++i )
		{
		auto& trace_i = elems[i];
		auto& prev_trace_i = prev_elems[i];

		if ( trace_i )
			{
			if ( prev_trace_i )
				{
				auto& v = trace_i->GetVal();
				auto& prev_v = prev_trace_i->GetVal();

				if ( v == prev_v )
					{
					trace_i->ComputeDelta(*prev_trace_i, deltas);
					continue;
					}
				}

			deltas.emplace_back(DeltaSetField(this, i, v));
			}

		else if ( prev_trace_i )
			deltas.emplace_back(DeltaSetField(this, i, nullptr));
		}
	}

void ValTrace::ComputeTableDelta(const ValTrace& prev, DeltaVector& deltas) const
	{
	auto& prev_elems = prev.elems;
	auto& prev_elems2 = prev.elems2;

	auto n = elems.size();
	auto is_set = elems2.size() == 0;
	auto prev_n = prev_elems.size();

	// We can't compare pointers for the indices because they're
	// new objects generated afresh by TableVal::ToMap.  So we do
	// explict full comparisons for equality, distinguishing values
	// newly added, common to both, or (implicitly) removed.  We'll
	// then go through the common to check them further.
	//
	// Our approach is O(N^2), but presumably these tables aren't
	// large, and in any case generating event traces is not something
	// requiring high performance, so we opt for conceptual simplicity.

	// Track which index values are newly added:
	std::set<const Val*> added_indices;

	// Track which entry traces are in common.  Indexed by previous
	// trace elem index, yielding current trace elem index.
	std::map<int, int> common_entries;

	for ( auto i = 0U; i < n; ++i )
		{
		auto& trace_i = elems[i];

		bool common = false;

		for ( auto j = 0U; j < prev_n; ++j )
			{
			auto& prev_trace_j = prev_elems[j];

			if ( *trace_i == *prev_trace_j )
				{
				common_entries[j] = i;
				common = true;
				break;
				}
			}

		if ( ! common )
			{
			auto v = trace_i->GetVal();
			auto yield = is_set ? nullptr : elems2[i]->GetVal();
			deltas.emplace_back(DeltaSetTableEntry(this, v, yield));
			added_indices.insert(v.get());
			}
		}

	for ( auto j = 0U; j < prev_n; ++j )
		{
		auto& prev_trace = prev_elems2[j];
		auto common_pair = common_entries.find(j);

		if ( common_pair == common_entries.end() )
			{
			deltas.emplace_back(DeltaRemoveTableEntry(this, prev_trace->GetVal()));
			continue;
			}

		if ( is_set )
			continue;

		// If we get here, we're analyzing a table for which there's
		// a common index.  The remaining question is whether the
		// yield has changed.
		auto i = common_pair->second;
		auto& trace = elems2[i];

		auto& yield = trace->GetVal();
		auto& prev_yield = prev_trace->GetVal();

		if ( yield == prev_yield )
			trace->ComputeDelta(*prev_trace, deltas);
		else
			deltas.emplace_back(DeltaSetTableEntry(this, elems[i]->GetVal(), yield));
		}
	}

void ValTrace::ComputeVectorDelta(const ValTrace& prev, DeltaVector& deltas) const
	{
	auto& prev_elems = prev.elems;
	auto n = elems.size();
	auto prev_n = prev_elems.size();

	if ( n < prev_n )
		{
		// The vector shrank in size.  Easiest to just build it
		// from scratch.
		deltas.emplace_back(DeltaVectorCreate(this));
		return;
		}

	// Look for existing entries that need reassigment.
	auto i = 0U;
	for ( ; i < prev_n; ++i )
		{
		auto& trace_i = elems[i];
		auto& prev_trace_i = prev_elems[i];

		auto& elem_i = trace_i->GetVal();
		auto& prev_elem_i = prev_trace_i->GetVal();

		if ( elem_i == prev_elem_i )
			trace_i->ComputeDelta(*prev_trace_i, deltas);
		else
			deltas.emplace_back(DeltaVectorSet(this, i, elem_i));
		}

	// Now append any new entries.
	for ( ; i < n; ++i )
		{
		auto& trace_i = elems[i];
		auto& elem_i = trace_i->GetVal();
		deltas.emplace_back(DeltaVectorAppend(this, i, elem_i));
		}
	}

	} // namespace zeek::detail
