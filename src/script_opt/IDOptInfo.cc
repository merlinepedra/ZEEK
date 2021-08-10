// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Stmt.h"
#include "zeek/Expr.h"
#include "zeek/Desc.h"
#include "zeek/script_opt/IDOptInfo.h"
#include "zeek/script_opt/StmtOptInfo.h"


namespace zeek::detail {

const char* trace_ID = nullptr;

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

void IDDefRegion::Dump() const
	{
	printf("\t%d->%d (%d), %d/%d/%d\n", start_stmt, end_stmt,
	       block_level, maybe_defined, definitely_defined,
	       single_definition);
	}


void IDOptInfo::Clear()
	{
	static bool did_init = false;

	if ( ! did_init )
		{
		trace_ID = getenv("ZEEK_TRACE_ID");
		did_init = true;
		}

	init_exprs.clear();
	usage_regions.clear();
	pending_confluences.clear();
	confluence_stmts.clear();
	}

void IDOptInfo::DefinedAt(const Stmt* s,
                          const std::vector<const Stmt*>& conf_blocks,
                          int conf_start)
	{
	if ( trace_ID && util::streq(trace_ID, my_id->Name()) )
		printf("ID %s defined at %d: %s\n", trace_ID, s ? s->GetOptInfo()->stmt_num : NO_DEF, s ? obj_desc(s).c_str() : "<entry>");

	if ( ! s )
		{ // This is a definition-upon-entry
		ASSERT(usage_regions.size() == 0);
		usage_regions.emplace_back(0, 0, true, true, 0);
		DumpBlocks();
		return;
		}

	auto s_oi = s->GetOptInfo();
	auto stmt_num = s_oi->stmt_num;

	if ( usage_regions.size() == 0 )
		{
		ASSERT(confluence_stmts.size() == 0);

		// We're seeing this identifier for the first time,
		// so we don't have any context or confluence
		// information for it.  Create its "backstory" region.
		usage_regions.emplace_back(0, 0, false, false, NO_DEF);
		}

	EndRegionAt(stmt_num - 1, s_oi->block_level);

	// Create new region corresponding to this definition.
	usage_regions.emplace_back(s, true, true, stmt_num);

	// Fill in any missing confluence blocks.
	int b = 0;	// index into our own blocks
	int n = confluence_stmts.size();

	while ( b < n && conf_start < conf_blocks.size() )
		{
		auto outer_block = conf_blocks[conf_start];

		// See if we can find that block.
		for ( ; b < n; ++b )
			if ( confluence_stmts[b] == outer_block )
				break;

		if ( b < n )
			{ // We found it, look for the next one.
			++conf_start;
			++b;
			}
		}

	// Add in the remainder.
	for ( ; conf_start < conf_blocks.size(); ++conf_start )
		StartConfluenceBlock(conf_blocks[conf_start]);

	DumpBlocks();
	}

void IDOptInfo::ReturnAt(const Stmt* s)
	{
	if ( trace_ID && util::streq(trace_ID, my_id->Name()) )
		printf("ID %s subject to return %d: %s\n", trace_ID, s->GetOptInfo()->stmt_num, obj_desc(s).c_str());

	// Look for a catch-return that this would branch to.
	for ( int i = confluence_stmts.size() - 1; i >= 0; --i )
		if ( confluence_stmts[i]->Tag() == STMT_CATCH_RETURN )
			{
			BranchBeyond(s, confluence_stmts[i]);
			DumpBlocks();
			return;
			}

	auto s_oi = s->GetOptInfo();
	EndRegionAt(s_oi->stmt_num, s_oi->block_level);

	DumpBlocks();
	}

void IDOptInfo::BranchBackTo(const Stmt* from, const Stmt* to)
	{
	if ( trace_ID && util::streq(trace_ID, my_id->Name()) )
		printf("ID %s branching back from %d: %s\n", trace_ID, from->GetOptInfo()->stmt_num, obj_desc(from).c_str());

	// The key notion we need to update is whether the regions
	// between from_reg and to_reg still have unique definitions.
	// Confluence due to the branch can only take that away, it
	// can't instill it.  (OTOH, in principle it could update
	// "maybe defined", but not in a way we care about, since we
	// only draw upon that for diagnosing usage errors, and for
	// those the error has already occurred on entry into the loop.)
	auto from_reg = ActiveRegion();
	auto t_oi = to->GetOptInfo();
	auto t_r_ind = FindRegionIndex(t_oi->stmt_num);
	auto& t_r = usage_regions[t_r_ind];

	if ( from_reg && from_reg->single_definition != t_r.single_definition )
		{
		// They disagree on the unique definition, if any.
		// Invalidate any unique definitions in the regions
		// subsequent to t_r.
		for ( auto i = t_r_ind; i < usage_regions.size(); ++i )
			usage_regions[i].single_definition = NO_DEF;
		}

	EndRegionAt(from);

	DumpBlocks();
	}

void IDOptInfo::BranchBeyond(const Stmt* end_s, const Stmt* block)
	{
	if ( trace_ID && util::streq(trace_ID, my_id->Name()) )
		printf("ID %s branching forward from %d: %s\n", trace_ID, end_s->GetOptInfo()->stmt_num, obj_desc(end_s).c_str());

	ASSERT(pending_confluences.count(block) > 0);

	auto ar = ActiveRegion();
	if ( ar )
		{
		pending_confluences[block].insert(ar);
		EndRegionAt(end_s);
		}

	DumpBlocks();
	}

void IDOptInfo::StartConfluenceBlock(const Stmt* s)
	{
	if ( trace_ID && util::streq(trace_ID, my_id->Name()) )
		printf("ID %s starting confluence block at %d: %s\n", trace_ID, s->GetOptInfo()->stmt_num, obj_desc(s).c_str());

	auto s_oi = s->GetOptInfo();
	int block_level = s_oi->block_level;

	for ( auto cs : confluence_stmts )
		{
		ASSERT(cs != s);

		auto cs_level = cs->GetOptInfo()->block_level;

		if ( cs_level >= block_level )
			{
			ASSERT(cs_level == block_level);
			ASSERT(cs == confluence_stmts.back());
			EndRegionAt(s_oi->stmt_num - 1, block_level);
			break;	// iterator is invalid
			}
		}

	ConfluenceSet empty_set;
	pending_confluences[s] = empty_set;
	confluence_stmts.push_back(s);

	DumpBlocks();
	}

void IDOptInfo::ConfluenceBlockEndsAt(const Stmt* s, bool no_orig_flow)
	{
	if ( trace_ID && util::streq(trace_ID, my_id->Name()) )
		printf("ID %s ending (%d) confluence block at %d: %s\n", trace_ID, no_orig_flow, s->GetOptInfo()->stmt_num, obj_desc(s).c_str());

	auto stmt_num = s->GetOptInfo()->stmt_num;

	ASSERT(confluence_stmts.size() > 0);
	auto cs = confluence_stmts.back();
	auto& pc = pending_confluences[cs];

	// End any active regions.  Those will all have a level >= that
	// of cs, since we're now returning to cs's level.
	int cs_stmt_num = cs->GetOptInfo()->stmt_num;
	int cs_level = cs->GetOptInfo()->block_level;

	bool maybe = false;
	bool definitely = true;

	bool did_single_def = false;
	int single_def = 0;	// 0 just to keep linter from griping
	bool have_multi_defs = false;

	int num_regions = 0;

	for ( auto& ur : usage_regions )
		{
		if ( ur.block_level < cs_level )
			// It's not applicable.
			continue;

		if ( ur.end_stmt == NO_DEF )
			{
			// End this region.
			ur.end_stmt = stmt_num;

			if ( ur.start_stmt <= cs_stmt_num && no_orig_flow &&
			     pc.count(&ur) == 0 )
				// Don't include this region in our assessment.
				continue;
			}

		else if ( ur.end_stmt < cs_stmt_num )
			// Irrelevant, didn't extend into confluence region.
			continue;

		else
			{
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

	// Adjust for the new region coming just after stmt_num.
	int level = cs->GetOptInfo()->block_level;

	usage_regions.emplace_back(stmt_num + 1, level, maybe, definitely,
	                           single_def);

	confluence_stmts.pop_back();
	pending_confluences.erase(cs);

	DumpBlocks();
	}

bool IDOptInfo::IsPossiblyDefinedAt(const Stmt* s)
	{
	if ( usage_regions.size() == 0 )
		return false;

	return FindRegion(s->GetOptInfo()->stmt_num).maybe_defined;
	}

bool IDOptInfo::IsDefinitelyDefinedAt(const Stmt* s)
	{
	if ( usage_regions.size() == 0 )
		return false;

	return FindRegion(s->GetOptInfo()->stmt_num).definitely_defined;
	}

bool IDOptInfo::IsUniquelyDefinedAt(const Stmt* s)
	{
	if ( usage_regions.size() == 0 )
		return false;

	return FindRegion(s->GetOptInfo()->stmt_num).single_definition != NO_DEF;
	}

void IDOptInfo::EndRegionAt(const Stmt* s)
	{
	auto s_oi = s->GetOptInfo();
	EndRegionAt(s_oi->stmt_num, s_oi->block_level);
	}

void IDOptInfo::EndRegionAt(int stmt_num, int level)
	{
	auto r = ActiveRegion();

	if ( r && r->block_level == level )
		// Previous region ends here.
		r->end_stmt = stmt_num;
	}

int IDOptInfo::FindRegionIndex(int stmt_num)
	{
	int region_ind = NO_DEF;
	for ( auto i = 0; i < usage_regions.size(); ++i )
		{
		if ( usage_regions[i].start_stmt > stmt_num )
			break;

		if ( usage_regions[i].end_stmt < 0 )
			region_ind = i;
		if ( usage_regions[i].end_stmt >= stmt_num )
			region_ind = i;
		}

	ASSERT(region_ind != NO_DEF);
	return region_ind;
	}

int IDOptInfo::ActiveRegionIndex()
	{
	int i;
	for ( i = usage_regions.size() - 1; i >= 0; --i )
		if ( usage_regions[i].end_stmt < 0 )
			break;

	return i;
	}

void IDOptInfo::DumpBlocks() const
	{
	if ( ! trace_ID || ! util::streq(trace_ID, my_id->Name()) )
		return;

	for ( auto i = 0; i < usage_regions.size(); ++i )
		usage_regions[i].Dump();

	printf("<end>\n");
	}


} // zeek::detail
