// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "DefItem.h"
#include "DefPoint.h"
#include "ReachingDefs.h"


namespace zeek::detail {


//


class DefSetsMgr {
public:
	DefSetsMgr();

	RDPtr& GetPreMinRDs(const Obj* o) const
		{ return GetRDs(pre_min_defs, o); }
	RDPtr& GetPreMaxRDs(const Obj* o) const
		{ return GetRDs(pre_max_defs, o); }

	RDPtr& GetPostMinRDs(const Obj* o) const
		{
		if ( HasPostMinRDs(o) )
			return GetRDs(post_min_defs, o);
		else
			return GetPreMinRDs(o);
		}
	RDPtr& GetPostMaxRDs(const Obj* o) const
		{
		if ( HasPostMaxRDs(o) )
			return GetRDs(post_max_defs, o);
		else
			return GetPreMaxRDs(o);
		}

	void SetPostRDs(const Obj* o, RDPtr& min_rd, RDPtr& max_rd)
		{
		SetPostMinRDs(o, min_rd);
		SetPostMaxRDs(o, max_rd);
		}

	void SetEmptyPre(const Obj* o)
		{
		auto empty_rds = make_intrusive<ReachingDefs>();
		SetPreMinRDs(o, empty_rds);
		SetPreMaxRDs(o, empty_rds);
		empty_rds.release();
		}

	void SetPreFromPre(const Obj* target, const Obj* source)
		{
		SetPreMinRDs(target, GetPreMinRDs(source));
		SetPreMaxRDs(target, GetPreMaxRDs(source));
		}

	void SetPreFromPost(const Obj* target, const Obj* source)
		{
		SetPreMinRDs(target, GetPostMinRDs(source));
		SetPreMaxRDs(target, GetPostMaxRDs(source));
		}

	void SetPostFromPre(const Obj* o)
		{
		SetPostMinRDs(o, GetPreMinRDs(o));
		SetPostMaxRDs(o, GetPreMaxRDs(o));
		}

	void SetPostFromPre(const Obj* target, const Obj* source)
		{
		SetPostMinRDs(target, GetPreMinRDs(source));
		SetPostMaxRDs(target, GetPreMaxRDs(source));
		}

	void SetPostFromPost(const Obj* target, const Obj* source)
		{
		SetPostMinRDs(target, GetPostMinRDs(source));
		SetPostMaxRDs(target, GetPostMaxRDs(source));
		}

	// Fine-grained control for setting RDs.
	void SetPreMinRDs(const Obj* o, RDPtr& rd)
		{ pre_min_defs->SetRDs(o, rd); }
	void SetPreMaxRDs(const Obj* o, RDPtr& rd)
		{ pre_max_defs->SetRDs(o, rd); }

	void SetPostMinRDs(const Obj* o, RDPtr& rd)
		{ post_min_defs->SetRDs(o, rd); }
	void SetPostMaxRDs(const Obj* o, RDPtr& rd)
		{ post_max_defs->SetRDs(o, rd); }

	// The following only apply to max RDs.
	void MergeIntoPre(const Obj* o, const RDPtr& rds)
		{
		// Don't use SetRDs as that overwrites.  We instead
		// want to merge.
		pre_max_defs->AddRDs(o, rds);
		}

	void MergeIntoPost(const Obj* o, const RDPtr& rds)
		{
		// Don't use SetRDs as that overwrites.  We instead
		// want to merge.
		post_max_defs->AddRDs(o, rds);
		}

	void MergePostIntoPre(const Obj* o)
		{ MergeIntoPre(o, GetPostMaxRDs(o)); }


	bool HasPreMinRDs(const Obj* o) const
		{ return pre_min_defs && pre_min_defs->HasRDs(o); }
	bool HasPreMaxRDs(const Obj* o) const
		{ return pre_max_defs && pre_max_defs->HasRDs(o); }

	bool HasPreMinRD(const Obj* o, const ID* id) const
		{ return pre_min_defs && pre_min_defs->HasRD(o, id); }

	// True if at the given object, there's a single unambiguous
	// pre RD for the given identifier.
	bool HasSinglePreMinRD(const Obj* o, const ID* id) const
		{
		return pre_min_defs && pre_min_defs->HasSingleRD(o, id);
		}

	bool HasPostMinRDs(const Obj* o) const
		{ return post_min_defs && post_min_defs->HasRDs(o); }
	bool HasPostMaxRDs(const Obj* o) const
		{ return post_max_defs && post_max_defs->HasRDs(o); }

	void CreatePreDef(DefinitionItem* di, DefinitionPoint dp, bool min_only)
		{ CreateDef(di, dp, true, min_only); }
	void CreatePostDef(const ID* id, DefinitionPoint dp, bool min_only);
	void CreatePostDef(DefinitionItem* di, DefinitionPoint dp, bool min_only);

	void CreatePostRDsFromPre(const Stmt* s)
		{
		SetPostMinRDs(s, GetPreMinRDs(s));
		SetPostMaxRDs(s, GetPreMaxRDs(s));
		}
	void CreatePostRDsFromPost(const Stmt* target, const Obj* source)
		{
		SetPostMinRDs(target, GetPostMinRDs(source));
		SetPostMaxRDs(target, GetPostMaxRDs(source));
		}

	void CreatePostRDs(const Stmt* target, RDPtr& min_rds, RDPtr& max_rds)
		{
		SetPostMinRDs(target, min_rds);
		SetPostMaxRDs(target, max_rds);
		}

	void CreateDef(DefinitionItem* di, DefinitionPoint dp,
			bool is_pre, bool min_only);

	DefinitionItem* GetExprDI(const Expr* e)
		{ return item_map.GetExprDI(e); }
	DefinitionItem* GetID_DI(const ID* id)
		{ return item_map.GetID_DI(id); }
	const DefinitionItem* GetConstID_DI(const ID* id) const
		{ return item_map.GetConstID_DI(id); }
        const DefinitionItem* GetConstID_DI(const DefinitionItem* di,
						const char* field_name) const
		{ return item_map.GetConstID_DI(di, field_name); }

protected:
	RDPtr& GetRDs(const RDSetPtr& defs, const Obj* o) const
		{
		return defs->FindRDs(o);
		}

	// Mappings of minimal reaching defs pre- and post- execution
	// of the given object.
	RDSetPtr pre_min_defs;
	RDSetPtr post_min_defs;

	// Mappings of maximal reaching defs pre- and post- execution
	// of the given object.
	RDSetPtr pre_max_defs;
	RDSetPtr post_max_defs;

	DefItemMap item_map;
};


} // zeek::detail
