// Classes for tracing/dumping Zeek events.

#pragma once

#include "zeek/Val.h"

namespace zeek::detail
	{

// Abstract class for capturing a single difference between two values.
// Includes notions of inserting, changing, or deleting a value.
class ValDelta
	{
public:
	};

// Captures the notion of a singleton (non-aggregate) value being assigned
// to a new value.
class DeltaChangeSingleton : public ValDelta
	{
public:
	DeltaChangeSingleton(ValPtr _new_val) : new_val(std::move(_new_val)) {}

private:
	ValPtr new_val;
	};

using DeltaVector = std::vector<ValDelta>;

// A single value element: either a ZVal or a pointer to a ValTrace.
class ValTraceElem;

// Tracks the elements of a value as seen at a given point in execution.
// For non-aggregates, this is simply the Val object, but for aggregates
// it is (recursively) each of the sub-elements, in a manner that can then
// be readily compared against future instances.
class ValTrace
	{
public:
	ValTrace(const ValPtr& v);
	~ValTrace();

	const ValPtr& GetVal() const { return v; }
	const TypePtr& GetType() const { return t; }

	// Returns true if this trace and the given one represent the
	// same underlying value.
	bool operator==(const ValTrace& vt) const;
	bool operator!=(const ValTrace& vt) const
		{ return ! ((*this) == vt); }

	// Computes the deltas between a previous ValTrace and this one.
	//
	// Returns the accumulated differences in deltas.  If on return
	// nothing was added to deltas then the two ValTrace's are equivalent
	// (no changes between them).
	void ComputeDelta(const ValTrace& prev, DeltaVector& deltas);

private:
	void TraceList(const ListValPtr& lv);
	void TraceRecord(const RecordValPtr& rv);
	void TraceTable(const TableValPtr& tv);
	void TraceVector(const VectorValPtr& vv);

	bool SameList(const ValTrace& vt) const;
	bool SameRecord(const ValTrace& vt) const;
	bool SameTable(const ValTrace& vt) const;
	bool SameVector(const ValTrace& vt) const;

	bool SameElems(const ValTrace& vt) const;

	bool ComputeListDelta(const ValTrace& prev, DeltaVector& deltas);
	bool ComputeRecordDelta(const ValTrace& prev, DeltaVector& deltas);
	bool ComputeTableDelta(const ValTrace& prev, DeltaVector& deltas);
	bool ComputeVectorDelta(const ValTrace& prev, DeltaVector& deltas);

	// Holds sub-elements.
	std::vector<std::shared_ptr<ValTrace>> elems;

	// A parallel vector used for the yield values of tables.
	std::vector<std::shared_ptr<ValTrace>> elems2;

	ValPtr v;
	TypePtr t;
	};

class ValTraceMgr
	{
public:
	std::shared_ptr<ValTrace> GetTrace(const ValPtr& v);
	};

	} // namespace zeek::detail
