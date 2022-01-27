// Classes for tracing/dumping Zeek events.

#pragma once

#include "zeek/Val.h"

namespace zeek::detail
	{

class ValTrace;
class ValTraceMgr;

// Abstract class for capturing a single difference between two values.
// Includes notions of inserting, changing, or deleting a value.
class ValDelta
	{
public:
	ValDelta(const ValTrace* _vt) : vt(_vt) {}
	virtual ~ValDelta() {}

	virtual std::string Generate(ValTraceMgr* vtm) const;
	virtual bool NeedsLHS() const { return true; }

	const ValTrace* GetValTrace() const { return vt; }

	virtual void Dump() const;

protected:
	std::string ValDesc(const ValPtr& v) const;

	const ValTrace* vt;
	};

using DeltaVector = std::vector<std::unique_ptr<ValDelta>>;

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
	const auto& GetElems() const { return elems; }

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
	void ComputeDelta(const ValTrace& prev, DeltaVector& deltas) const;

	void Dump(int indent_level) const;

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

	void ComputeRecordDelta(const ValTrace& prev, DeltaVector& deltas) const;
	void ComputeTableDelta(const ValTrace& prev, DeltaVector& deltas) const;
	void ComputeVectorDelta(const ValTrace& prev, DeltaVector& deltas) const;

	void Indent(int indent_level) const;

	// Holds sub-elements.
	std::vector<std::shared_ptr<ValTrace>> elems;

	// A parallel vector used for the yield values of tables.
	std::vector<std::shared_ptr<ValTrace>> elems2;

	ValPtr v;
	TypePtr t;
	};

// Captures the basic notion of a new, non-equivalent value being assigned.
class DeltaReplaceValue : public ValDelta
	{
public:
	DeltaReplaceValue(const ValTrace* _vt, ValPtr _new_val)
		: ValDelta(_vt), new_val(std::move(_new_val)) {}

	std::string Generate(ValTraceMgr* vtm) const override;

	void Dump() const override;

private:
	ValPtr new_val;
	};

// Captures the notion of setting a record field.  If the replacement
// value is nil then it means delete the field.
class DeltaSetField : public ValDelta
	{
public:
	DeltaSetField(const ValTrace* _vt, int _field, ValPtr _new_val)
		: ValDelta(_vt), field(_field), new_val(std::move(_new_val)) {}

	std::string Generate(ValTraceMgr* vtm) const override;

	void Dump() const override;

private:
	int field;
	ValPtr new_val;
	};

// Captures the notion of adding an element to a set.  Use DeltaRemoveTableEntry to
// delete values.
class DeltaSetSetEntry : public ValDelta
	{
public:
	DeltaSetSetEntry(const ValTrace* _vt, ValPtr _index)
		: ValDelta(_vt), index(_index) {}

	std::string Generate(ValTraceMgr* vtm) const override;
	bool NeedsLHS() const override { return false; }

	void Dump() const override;

private:
	ValPtr index;
	};

// Captures the notion of setting a table entry (which includes both changing
// an existing one and adding a new one).  Use DeltaRemoveTableEntry to
// delete values.
class DeltaSetTableEntry : public ValDelta
	{
public:
	DeltaSetTableEntry(const ValTrace* _vt, ValPtr _index, ValPtr _new_val)
		: ValDelta(_vt), index(_index), new_val(std::move(_new_val)) {}

	std::string Generate(ValTraceMgr* vtm) const override;

	void Dump() const override;

private:
	ValPtr index;
	ValPtr new_val;
	};

// Captures the notion of removing a table/set entry.
class DeltaRemoveTableEntry : public ValDelta
	{
public:
	DeltaRemoveTableEntry(const ValTrace* _vt, ValPtr _index)
		: ValDelta(_vt), index(std::move(_index)) {}

	std::string Generate(ValTraceMgr* vtm) const override;
	bool NeedsLHS() const override { return false; }

	void Dump() const override;

private:
	ValPtr index;
	};

// Captures the notion of changing an element of a vector.
class DeltaVectorSet : public ValDelta
	{
public:
	DeltaVectorSet(const ValTrace* _vt, int _index, ValPtr _elem)
		 : ValDelta(_vt), index(_index), elem(std::move(_elem)) {}

	std::string Generate(ValTraceMgr* vtm) const override;

	void Dump() const override;

private:
	int index;
	ValPtr elem;
	};

// Captures the notion of adding an entry to the end of a vector.
class DeltaVectorAppend : public ValDelta
	{
public:
	DeltaVectorAppend(const ValTrace* _vt, int _index, ValPtr _elem)
		: ValDelta(_vt), index(_index), elem(std::move(_elem)) {}

	std::string Generate(ValTraceMgr* vtm) const override;

	void Dump() const override;

private:
	int index;
	ValPtr elem;
	};

// Captures the notion of replacing a vector wholesale.
class DeltaVectorCreate : public ValDelta
	{
public:
	DeltaVectorCreate(const ValTrace* _vt)
		: ValDelta(_vt) {}

	std::string Generate(ValTraceMgr* vtm) const override;

	void Dump() const override;

private:
	};

class ValTraceMgr
	{
public:
	void AddVal(ValPtr v);

	const std::string& ValName(const ValPtr& v);
	const std::string& ValName(const ValTrace* vt);

private:
	void NewVal(ValPtr v);

	void AssessChange(ValPtr v, const ValTrace* prev_vt);
	bool AssessChange(const ValTrace* vt, const ValTrace* prev_vt);

	void ProcessDelta(const ValDelta* d);

	void TrackValTrace(const ValTrace* vt);
	void CreateVal(const ValTrace* vt);

	std::unordered_map<const Val*, std::shared_ptr<ValTrace>> val_map;

	std::unordered_map<const Val*, std::string> val_names;
	std::unordered_map<const ValTrace*, std::string> vt_names;

	// Hang on to values we're tracking to make sure the pointers don't
	// go away.
	std::vector<ValPtr> vals;
	};

	} // namespace zeek::detail
