// See the file "COPYING" in the main distribution directory for copyright.

// Information needed for ZAM loop iterations.

#pragma once

#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/script_opt/ZAM/ZInst.h"

namespace zeek::detail {

class TableIterInfo {
public:
	// No constructor needed, as all of our member variables are
	// instead instantiated via BeginLoop().  This allows us to
	// reuse TableIterInfo objects to lower the overhead associated
	// with executing ZBody::DoExec for non-recursive functions.

	// We do, however, want to make sure that when we go out of scope,
	// if we have any pending iterators we clear them.
	~TableIterInfo()	{ Clear(); }

	void BeginLoop(const TableVal* _tv, ZInstAux* _aux)
		{
		tv = _tv;
		auto tvd = tv->AsTable();
		tbl_iter = tvd->begin();
		tbl_end = tvd->end();
		}

	// True if we're done iterating, false if not.
	bool IsDoneIterating() const
		{
		return *tbl_iter == *tbl_end;
		}

	// Indicates that the current iteration is finished.
	void IterFinished()
		{
		++*tbl_iter;
		}

	void NextIter(ZVal* frame)
		{
		auto ind_lv = tv->RecreateIndex(*(*tbl_iter)->GetHashKey());
		for ( int i = 0; i < ind_lv->Length(); ++i )
			{
			ValPtr ind_lv_p = ind_lv->Idx(i);
			auto& var = frame[aux->loop_vars[i]];
			auto& t = aux->loop_var_types[i];
			if ( ZVal::IsManagedType(t) )
				ZVal::DeleteManagedType(var);
			var = ZVal(ind_lv_p, t);
			}

		IterFinished();
		}

	ZVal IterValue()
		{
		auto tev = (*tbl_iter)->GetValue<TableEntryVal*>();
		return ZVal(tev->GetVal(), aux->value_var_type);
		}

	void EndIter()		{ Clear(); }

	void Clear()
		{
		tbl_iter = std::nullopt;
		tbl_end = std::nullopt;
		}

private:
	ZInstAux* aux;

	//// Dynamic information:

	// The table we're looping over.  If we want to allow for the table
	// going away before we're able to clear our iterators then we
	// could change this to non-const and use Ref/Unref.
	const TableVal* tv = nullptr;

	std::optional<DictIterator> tbl_iter;
	std::optional<DictIterator> tbl_end;
};

class StepIterInfo {
public:
	// We do some cycle-squeezing by not having a constructor to
	// initialize our member variables, since we impose a discipline
	// that any use of the object starts with InitLoop().  That lets
	// us use quasi-static objects for non-recursive functions.

	void InitLoop(const std::vector<std::optional<ZVal>>* _vv)
		{
		vv = _vv;
		n = vv->size();
		iter = 0;
		}

	void InitLoop(const String* _s)
		{
		s = _s;
		n = s->Len();
		iter = 0;
		}

	// True if we're done iterating, false if not.
	bool IsDoneIterating() const
		{
		return iter >= n;
		}

	// Indicates that the current iteration is finished.
	void IterFinished()
		{
		++iter;
		}

	// Counter of where we are in the iteration.
	bro_uint_t iter;	// initialized to 0 at start of loop
	bro_uint_t n;	// we loop from 0 ... n-1

	// The low-level value we're iterating over.
	const std::vector<std::optional<ZVal>>* vv;
	const String* s;
};

} // namespace zeek::detail
