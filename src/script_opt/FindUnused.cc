// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/script_opt/FindUnused.h"
#include "zeek/script_opt/IDOptInfo.h"

namespace zeek::detail
	{

std::unordered_set<std::string> script_events;

void register_new_event(const IDPtr& id)
	{
	script_events.insert(id->Name());
	}

UsageAnalyzer::UsageAnalyzer(std::vector<FuncInfo>& funcs)
	{
	current_scope = global_scope();

	FindSeeds(reachables);
	FullyExpandReachables();

	for ( auto& gpair : global_scope()->Vars() )
		{
		auto& id = gpair.second;
		auto f = GetFuncIfAny(id.get());

		if ( f && reachables.count(id.get()) == 0 && ! id->IsExport() )
			// printf("orphan %s (%d, %s):\n%s\n", f->Name(), f->GetBodies().size(), id->ModuleName().c_str(), obj_desc(id.get()).c_str());
			printf("orphan %s (%d, %s):\n", f->Name(), f->GetBodies().size(), id->ModuleName().c_str());
		}
	}

void UsageAnalyzer::FindSeeds(IDSet& seeds) const
	{
	for ( auto& gpair : global_scope()->Vars() )
		{
		auto& id = gpair.second;

		if ( id->GetAttr(ATTR_IS_USED) )
			{
			seeds.insert(id.get());
			continue;
			}

		auto f = GetFuncIfAny(id);

		if ( f && id->GetType<FuncType>()->Flavor() == FUNC_FLAVOR_EVENT )
			{
			if ( script_events.count(f->Name()) == 0 )
				seeds.insert(id.get());
			continue;
			}

		// If the global is exported, or has global scope, we assume
		// it's meant to be used, even if the current scripts don't
		// use it.
		if ( id->IsExport() || id->ModuleName() == "GLOBAL" )
			seeds.insert(id.get());
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

bool UsageAnalyzer::ExpandReachables(const IDSet& curr_r)
	{
	new_reachables.clear();

	for ( auto r : curr_r )
		Expand(r);

	return ! new_reachables.empty();
	}

void UsageAnalyzer::Expand(const ID* id)
	{
	// printf("expanding %s\n", id->Name());
	id->Traverse(this);
	}

TraversalCode UsageAnalyzer::PreID(const ID* id)
	{
	auto f = GetFuncIfAny(id);

	if ( f && reachables.count(id) == 0 )
		new_reachables.insert(id);

	id->GetType()->Traverse(this);

	auto& attrs = id->GetAttrs();
	if ( attrs )
		attrs->Traverse(this);

	for ( auto& ie : id->GetOptInfo()->GetInitExprs() )
		if ( ie )
			ie->Traverse(this);

	return TC_CONTINUE;
	}

TraversalCode UsageAnalyzer::PreType(const Type* t)
	{
	if ( analyzed_types.count(t) > 0 )
		return TC_ABORTSTMT;

	analyzed_types.insert(t);
	return TC_CONTINUE;
	}

	} // namespace zeek::detail
