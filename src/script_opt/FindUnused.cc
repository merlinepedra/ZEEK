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

	FindSeeds(all_funcs, reachables);
	FullyExpandReachables();

	for ( auto& gpair : global_scope()->Vars() )
		{
		auto& id = gpair.second;
		auto f = GetFuncIfAny(id.get());

		if ( f && reachables.count(f) == 0 && ! id->IsExport() )
			printf("orphan %s (%d, %s)\n", f->Name(), f->GetBodies().size(), id->ModuleName().c_str());
		}
	}

void UsageAnalyzer::FindSeeds(FuncSet& all_funcs, FuncSet& seeds) const
	{
	for ( auto& gpair : global_scope()->Vars() )
		{
		auto& id = gpair.second;
		auto f = GetFuncIfAny(id);

		if ( ! f )
			continue;

		all_funcs.insert(f);

		if ( id->GetAttr(ATTR_IS_USED) )
			{
			seeds.insert(f);
			continue;
			}

		auto fl = id->GetType<FuncType>()->Flavor();

		if ( fl == FUNC_FLAVOR_EVENT )
			{
			if ( script_events.count(f->Name()) == 0 )
				seeds.insert(f);
			}

		else
			{
			// A function or a hook.  If it's exported, or has
			// global scope, then assume it's meant to be called.
			if ( id->IsExport() || id->ModuleName() == "GLOBAL" )
				seeds.insert(f);
			}
		}
	}

const Func* UsageAnalyzer::GetFuncIfAny(const ID* id) const
	{
	auto& t = id->GetType();
	if ( t->Tag() != TYPE_FUNC )
		return nullptr;

	auto fv = cast_intrusive<FuncVal>(id->GetVal());
	if ( ! fv )
		return nullptr;

	auto func = fv->Get();
	return func->GetKind() == Func::SCRIPT_FUNC ? func : nullptr;
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

	if ( f && reachables.count(f) == 0 )
		new_reachables.insert(f);

	return TC_CONTINUE;
	}

	} // namespace zeek::detail
