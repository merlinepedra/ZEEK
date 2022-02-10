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
	using IDSet = std::unordered_set<const ID*>;

	void FindSeeds(IDSet& seeds) const;

	const Func* GetFuncIfAny(const ID* id) const;
	const Func* GetFuncIfAny(const IDPtr& id) const { return GetFuncIfAny(id.get()); }

	void FullyExpandReachables();
	bool ExpandReachables(const IDSet& curr_r);
	void Expand(const ID* f);

	TraversalCode PreID(const ID* id) override;
	TraversalCode PreType(const Type* t) override;

	IDSet reachables;
	IDSet new_reachables;

	std::unordered_set<const ID*> analyzed_IDs;
	std::unordered_set<const Type*> analyzed_types;
	};

// Marks a given identifier as referring to a script-level event (one
// not known to the event engine).
extern void register_new_event(const IDPtr& id);

	} // namespace zeek::detail
