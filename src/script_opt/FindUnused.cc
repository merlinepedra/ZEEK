// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/FindUnused.h"

namespace zeek::detail
	{

std::unordered_set<std::string> script_events;

void register_new_event(const IDPtr& id)
	{
	script_events.insert(id->Name());
	}

UsageAnalyzer::UsageAnalyzer(std::vector<FuncInfo>& funcs)
	{
	FuncSet all_funcs;

	FindEvents(all_funcs, reachables);
	FullyExpandReachables();

	for ( auto f : all_funcs )
		{
		if ( reachables.count(f) == 0 )
			printf("orphan %s (%d)\n", f->Name(), f->GetBodies().size());
		}
	}

void UsageAnalyzer::FindEvents(FuncSet& all_events, FuncSet& non_script_events)
	{
	for ( auto& gpair : global_scope()->Vars() )
		{
		auto& id = gpair.second;
		auto f = GetEventIfAny(id);

		if ( f )
			{
			all_events.insert(f);

			if ( script_events.count(f->Name()) == 0 ||
			     id->GetAttr(ATTR_IS_USED))
				non_script_events.insert(f);
			}
		}
	}

const Func* UsageAnalyzer::GetFuncIfAny(const ID* id) const
	{
	auto& t = id->GetType();
	if ( t->Tag() != TYPE_FUNC )
		return nullptr;

	auto fv = cast_intrusive<FuncVal>(id->GetVal());
	return fv ? fv->Get() : nullptr;
	}

const Func* UsageAnalyzer::GetEventIfAny(const ID* id) const
	{
	auto f = GetFuncIfAny(id);
	if ( f && id->GetType<FuncType>()->Flavor() == FUNC_FLAVOR_EVENT )
		return f;

	return nullptr;
	}

void UsageAnalyzer::FullyExpandReachables()
	{
	// We use the following structure to avoid having to copy
	// the initial set of reachables, which can be quite large.
	if ( ExpandReachables(reachables) )
		{
		auto r = new_reachables;
		reachables.insert(r.begin(), r.end());

		while ( ExpandReachables(r) )
			{
			r = new_reachables;
			reachables.insert(r.begin(), r.end());
			}
		}
	}

bool UsageAnalyzer::ExpandReachables(const FuncSet& curr_r)
	{
	new_reachables.clear();

	for ( auto r : curr_r )
		Expand(r);

	return ! new_reachables.empty();
	}

void UsageAnalyzer::Expand(const Func* f)
	{
	// printf("expanding %s\n", f->Name());
	f->Traverse(this);
	}

TraversalCode UsageAnalyzer::PreID(const ID* id)
	{
	auto f = GetFuncIfAny(id);

	// printf("found identifier %s (%d)\n", id->Name(), f ? reachables.count(f) : -1);

	if ( f && reachables.count(f) == 0 )
		new_reachables.insert(f);

	return TC_CONTINUE;
	}

	} // namespace zeek::detail
