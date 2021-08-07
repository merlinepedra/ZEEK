// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Stmt.h"
#include "zeek/Expr.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/StmtOptInfo.h"


namespace zeek::detail {

IDDefRegion::IDDefRegion(const Stmt* s,
                         bool maybe, bool definitely, int single_def)
	{
	start_stmt = s->GetOptInfo()->stmt_num;
	block_level = s->GetOptInfo()->block_level;

	Init(maybe, definitely, single_def);
	}

IDDefRegion::IDDefRegion(int stmt_num, int level,
                         bool maybe, bool definitely, int single_def)
	{
	start_stmt = stmt_num;
	block_level = level;

	Init(maybe, definitely, single_def);
	}


void IDOptInfo::Clear()
	{
	init_exprs.clear();
	usage_regions.clear();
	pending_confluences.clear();
	confluence_stmts.clear();
	}

void IDOptInfo::DefinedAt(const Stmt* s)
	{
	if ( s )
		{
		auto s_oi = s->GetOptInfo();
		auto stmt_num = s_oi->stmt_num;

		EndRegionAt(stmt_num - 1, s_oi->block_level);

		// Create new region corresponding to this definition.
		usage_regions.emplace_back(s, false, true, stmt_num);
		}

	else
		{ // This is a definition-upon-entry
		ASSERT(usage_regions.size() == 0);
		usage_regions.emplace_back(0, 0, true, true, 0);
		}
	}

void IDOptInfo::ReturnAt(const Stmt* s)
	{
	auto s_oi = s->GetOptInfo();
	EndRegionAt(s_oi->stmt_num, s_oi->block_level);
	}

void IDOptInfo::BranchBackTo(const Stmt* to)
	{
	// The key notion we need to update is whether the regions
	// between from_reg and to_reg still have unique definitions.
	// Confluence due to the branch can only take that away, it
	// can't instill it.  (OTOH, in principle it could update
	// "maybe defined", but not in a way we care about, since we
	// only draw upon that for diagnosing usage errors, and for
	// those the error has already occurred on entry into the
	// loop.)
	auto& from_reg = ActiveRegion();
	auto t_oi = to->GetOptInfo();
	auto t_r_ind = FindRegionIndex(t_oi->stmt_num);
	auto& t_r = usage_regions[t_r_ind];

	if ( from_reg.single_definition != t_r.single_definition )
		{
		// They disagree on the unique definition, if any.
		// Invalidate any unique definitions in the regions
		// subsequent to t_r.
		for ( auto i = t_r_ind; i < usage_regions.size(); ++i )
			usage_regions[i].single_definition = NO_DEF;
		}
	}

void IDOptInfo::BranchBeyond(const Stmt* block)
	{
	pending_confluences[block].insert(&ActiveRegion());
	}

void IDOptInfo::StartConfluenceBlock(const Stmt* s)
	{
	ConfluenceSet empty_set;
	pending_confluences[s] = empty_set;
	confluence_stmts.push_back(s);
	}

void IDOptInfo::ConfluenceBlockEndsAt(const Stmt* s, bool no_orig_flow)
	{
	auto s_oi = s->GetOptInfo();

	auto cs = confluence_stmts.back();
	auto& pc = pending_confluences[cs];

	// End any active regions.

	bool maybe = false;
	bool definitely = true;

	bool did_single_def = false;
	int single_def = 0;	// 0 just to keep linter from griping
	bool have_multi_defs = false;

	int num_regions = 0;

	for ( auto& ur : usage_regions )
		{
		if ( ur.end_stmt == NO_DEF )
			{
			// End this region.
			ur.end_stmt = s_oi->stmt_num;

			if ( ur.start_stmt < s_oi->stmt_num && no_orig_flow )
				// Don't include this region in our assessment.
				continue;
			}

		else
			{
			ASSERT(ur.end_stmt < s_oi->stmt_num);

			// This region isn't active, but could still be
			// germane if we're tracking it for confluence.
			if ( pc.count(&ur) == 0 )
				// No, we're not tracking it.
				continue;
			}

		++num_regions;

		maybe = maybe || ur.maybe_defined;

		if ( ! ur.definitely_defined )
			definitely = false;

		if ( have_multi_defs || ! definitely ||
		     ur.single_definition < 0 )
			{
			// No need to assess single-definition any further.
			have_multi_defs = true;
			continue;
			}

		if ( did_single_def )
			{
			if ( single_def != ur.single_definition )
				have_multi_defs = true;
			}
		else
			{
			single_def = ur.single_definition;
			did_single_def = true;
			}
		}

	if ( num_regions == 0 )
		{ // Nothing survives.
		ASSERT(maybe == false);
		definitely = false;
		}

	if ( have_multi_defs || ! did_single_def )
		single_def = NO_DEF;

	// Adjust for the new region coming just after 's'.
	int stmt_num = s_oi->stmt_num + 1;
	int level = s_oi->block_level - 1;

	usage_regions.emplace_back(stmt_num, level, maybe, definitely,
	                           single_def);

	confluence_stmts.pop_back();
	}

void IDOptInfo::EndRegionAt(int stmt_num, int level)
	{
	auto& r = ActiveRegion();

	if ( r.block_level == level )
		// Previous region ends here.
		r.end_stmt = stmt_num;
	}

int IDOptInfo::FindRegionIndex(int stmt_num)
	{
	int i;
	for ( i = 0; i < usage_regions.size(); ++i )
		{
		ASSERT(usage_regions[i].start_stmt < stmt_num);

		if ( usage_regions[i].end_stmt < 0 )
			break;
		if ( usage_regions[i].end_stmt >= stmt_num )
			break;
		}

	ASSERT(i < usage_regions.size());
	return i;
	}

int IDOptInfo::ActiveRegionIndex()
	{
	int i;
	for ( i = usage_regions.size() - 1; i >= 0; --i )
		if ( usage_regions[i].end_stmt < 0 )
			break;

	ASSERT(i >= 0);
	return i;
	}


} // zeek::detail
