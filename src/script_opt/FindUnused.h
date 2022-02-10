// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Traverse.h"
#include "zeek/script_opt/ScriptOpt.h"

namespace zeek::detail
	{

class UsageAnalyzer : public TraversalCallback
	{
public:
	UsageAnalyzer(std::vector<FuncInfo>& funcs);

private:
	using FuncSet = std::unordered_set<const Func*>;

	void FindSeeds(FuncSet& all_funcs, FuncSet& seeds) const;

	const Func* GetFuncIfAny(const ID* id) const;
	const Func* GetFuncIfAny(const IDPtr& id) const { return GetFuncIfAny(id.get()); }

	void FullyExpandReachables();
	bool ExpandReachables(const FuncSet& curr_r);
	void Expand(const Func* f);

	TraversalCode PreID(const ID* id) override;

	FuncSet reachables;
	FuncSet new_reachables;
	};

// Marks a given identifier as referring to a script-level event (one
// not known to the event engine).
extern void register_new_event(const IDPtr& id);

	} // namespace zeek::detail
