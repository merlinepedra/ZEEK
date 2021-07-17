// See the file "COPYING" in the main distribution directory for copyright.

// This file includes the ZAM methods associated with generating an
// initial, complete intermediary ZAM body for a given function.
// Optimization of that ZAM body, leading to ultimate code generation,
// is factored out into Opt.cc.

#include "zeek/CompHash.h"
#include "zeek/RE.h"
#include "zeek/Frame.h"
#include "zeek/module_util.h"
#include "zeek/Scope.h"
#include "zeek/Reporter.h"
#include "zeek/script_opt/ScriptOpt.h"
#include "zeek/script_opt/Reduce.h"
#include "zeek/script_opt/ProfileFunc.h"
#include "zeek/script_opt/ZAM/Compile.h"


namespace zeek::detail {

class OpaqueVals {
public:
	OpaqueVals(ZInstAux* _aux)	{ aux = _aux; }

	ZInstAux* aux;
};


ZAMCompiler::ZAMCompiler(ScriptFunc* f, std::shared_ptr<ProfileFunc> _pf,
                         ScopePtr _scope, StmtPtr _body,
                         std::shared_ptr<UseDefs> _ud,
                         std::shared_ptr<Reducer> _rd)
	{
	func = f;
	pf = std::move(_pf);
	scope = std::move(_scope);
	body = std::move(_body);
	ud = std::move(_ud);
	reducer = std::move(_rd);
	frame_sizeI = 0;

	Init();
	}

StmtPtr ZAMCompiler::CompileBody()
	{
	curr_stmt = nullptr;

	if ( func->Flavor() == FUNC_FLAVOR_HOOK )
		PushBreaks();

	(void) CompileStmt(body);

	if ( reporter->Errors() > 0 )
		return nullptr;

	if ( LastStmt(body.get())->Tag() != STMT_RETURN )
		SyncGlobals();

	if ( breaks.size() > 0 )
		{
		ASSERT(breaks.size() == 1);

		if ( func->Flavor() == FUNC_FLAVOR_HOOK )
			{
			// Rewrite the breaks.
			for ( auto& b : breaks[0] )
				{
				auto& i = insts1[b.stmt_num];
				delete i;
				i = new ZInstI(OP_HOOK_BREAK_X);
				}
			}

		else
			reporter->Error("\"break\" used without an enclosing \"for\" or \"switch\"");
		}

	if ( nexts.size() > 0 )
		reporter->Error("\"next\" used without an enclosing \"for\"");

	if ( fallthroughs.size() > 0 )
		reporter->Error("\"fallthrough\" used without an enclosing \"switch\"");

	if ( catches.size() > 0 )
		reporter->InternalError("untargeted inline return");

	// Make sure we have a (pseudo-)instruction at the end so we
	// can use it as a branch label.
	if ( ! pending_inst )
		pending_inst = new ZInstI();

	// Concretize instruction numbers in inst1 so we can
	// easily move through the code.
	for ( auto i = 0U; i < insts1.size(); ++i )
		insts1[i]->inst_num = i;

	// Compute which instructions are inside loops.
	for ( auto i = 0; i < int(insts1.size()); ++i )
		{
		auto inst = insts1[i];

		auto t = inst->target;
		if ( ! t || t == pending_inst )
			continue;

		if ( t->inst_num < i )
			{
			auto j = t->inst_num;

			if ( ! t->loop_start )
				{
				// Loop is newly discovered.
				t->loop_start = true;
				}
			else
				{
				// We're extending an existing loop.  Find
				// its current end.
				auto depth = t->loop_depth;
				while ( j < i &&
				        insts1[j]->loop_depth == depth )
					++j;

				ASSERT(insts1[j]->loop_depth == depth - 1);
				}

			// Run from j's current position to i, bumping
			// the loop depth.
			while ( j <= i )
				{
				++insts1[j]->loop_depth;
				++j;
				}
			}

		ASSERT(! inst->target2 || inst->target2->inst_num > i);
		}

	if ( ! analysis_options.no_ZAM_opt )
		OptimizeInsts();

	// Move branches to dead code forward to their successor live code.
	for ( auto i = 0U; i < insts1.size(); ++i )
		{
		auto inst = insts1[i];
		if ( ! inst->live )
			continue;

		auto t = inst->target;

		if ( ! t )
			continue;

		inst->target = FindLiveTarget(t);

		if ( inst->target2 )
			inst->target2 = FindLiveTarget(inst->target2);
		}

	// Construct the final program with the dead code eliminated
	// and branches resolved.

	// Make sure we don't include the empty pending-instruction, if any.
	if ( pending_inst )
		pending_inst->live = false;

	// Maps inst1 instructions to where they are in inst2.
	// Dead instructions map to -1.
	std::vector<int> inst1_to_inst2;

	for ( auto i = 0U; i < insts1.size(); ++i )
		{
		if ( insts1[i]->live )
			{
			inst1_to_inst2.push_back(insts2.size());
			insts2.push_back(insts1[i]);
			}
		else
			inst1_to_inst2.push_back(-1);
		}

	// Re-concretize instruction numbers, and concretize GoTo's.
	for ( auto i = 0U; i < insts2.size(); ++i )
		insts2[i]->inst_num = i;

	for ( auto i = 0U; i < insts2.size(); ++i )
		{
		auto inst = insts2[i];

		if ( inst->target )
			{
			RetargetBranch(inst, inst->target, inst->target_slot);

			if ( inst->target2 )
				RetargetBranch(inst, inst->target2,
				               inst->target2_slot);
			}
		}

	// If we have remapped frame denizens, update them.  If not,
	// create them.
	if ( shared_frame_denizens.size() > 0 )
		{ // update
		for ( auto i = 0U; i < shared_frame_denizens.size(); ++i )
			{
			auto& info = shared_frame_denizens[i];

			for ( auto& start : info.id_start )
				{
				// It can happen that the identifier's
				// origination instruction was optimized
				// away, if due to slot sharing it's of
				// the form "slotX = slotX".  In that
				// case, look forward for the next viable
				// instruction.
				while ( start < int(insts1.size()) &&
				        inst1_to_inst2[start] == -1 )
					++start;

				ASSERT(start < insts1.size());
				start = inst1_to_inst2[start];
				}

			shared_frame_denizens_final.push_back(info);
			}
		}

	else
		{ // create
		for ( auto i = 0U; i < frame_denizens.size(); ++i )
			{
			FrameSharingInfo info;
			info.ids.push_back(frame_denizens[i]);
			info.id_start.push_back(0);
			info.scope_end = insts2.size();

			// The following doesn't matter since the value
			// is only used during compiling, not during
			// execution.
			info.is_managed = false;

			shared_frame_denizens_final.push_back(info);
			}
		}

	delete pending_inst;

	// Create concretized versions of any case tables.
	ZBody::CaseMaps<bro_int_t> int_cases;
	ZBody::CaseMaps<bro_uint_t> uint_cases;
	ZBody::CaseMaps<double> double_cases;
	ZBody::CaseMaps<std::string> str_cases;

#define CONCRETIZE_SWITCH_TABLES(T, switchesI, switches) \
	for ( auto& targs : switchesI ) \
		{ \
		ZBody::CaseMap<T> cm; \
		for ( auto& targ : targs ) \
			cm[targ.first] = targ.second->inst_num; \
		switches.push_back(cm); \
		}

	CONCRETIZE_SWITCH_TABLES(bro_int_t, int_casesI, int_cases);
	CONCRETIZE_SWITCH_TABLES(bro_uint_t, uint_casesI, uint_cases);
	CONCRETIZE_SWITCH_TABLES(double, double_casesI, double_cases);
	CONCRETIZE_SWITCH_TABLES(std::string, str_casesI, str_cases);

	// Could erase insts1 here to recover memory, but it's handy
	// for debugging.

#if 0
	if ( non_recursive )
		func->UseStaticFrame();
#endif

	auto zb = make_intrusive<ZBody>(func->Name(),
	                    shared_frame_denizens_final, managed_slotsI,
	                    globalsI, num_iters, non_recursive,
			    int_cases, uint_cases, double_cases, str_cases);
	zb->SetInsts(insts2);

	return zb;
	}

void ZAMCompiler::Init()
	{
	auto uds = ud->HasUsage(body.get()) ? ud->GetUsage(body.get()) : nullptr;
	auto args = scope->OrderedVars();
	int nparam = func->GetType()->Params()->NumFields();

	for ( auto g : pf->Globals() )
		{
		auto non_const_g = const_cast<ID*>(g);

		GlobalInfo info;
		info.id = {NewRef{}, non_const_g};
		info.slot = AddToFrame(non_const_g);
		global_id_to_info[non_const_g] = globalsI.size();
		globalsI.push_back(info);
		}

	push_existing_scope(scope);

	for ( auto a : args )
		{
		if ( --nparam < 0 )
			break;

		auto arg_id = a.get();
		if ( uds && uds->HasID(arg_id) )
			LoadParam(arg_id);
		else
			{
			// printf("param %s unused\n", obj_desc(arg_id.get()));
			}
		}

	pop_scope();

	// Assign slots for locals (which includes temporaries).
	for ( auto l : pf->Locals() )
		{
		auto non_const_l = const_cast<ID*>(l);
		// ### should check for unused variables.
		// Don't add locals that were already added because they're
		// parameters.
		if ( ! HasFrameSlot(non_const_l) )
			(void) AddToFrame(non_const_l);
		}

#if 0
	// Complain about unused aggregates ... but not if we're inlining,
	// as that can lead to optimizations where they wind up being unused
	// but the original logic for using them was sound.
	if ( ! analysis_options.inliner )
		for ( auto a : pf->Inits() )
			{
			if ( pf->Locals().find(a) == pf->Locals().end() )
				reporter->Warning("%s unused", a->Name());
			}
#endif

	for ( auto& slot : frame_layout1 )
		{
		// Look for locals with values of types for which
		// we do explicit memory management on (re)assignment.
		auto t = slot.first->GetType();
		if ( ZVal::IsManagedType(t) )
			managed_slotsI.push_back(slot.second);
		}

	non_recursive = non_recursive_funcs.count(func) > 0;
	}


#include "ZAM-MethodDefs.h"


const ZAMStmt ZAMCompiler::StartingBlock()
	{
	return ZAMStmt(insts1.size());
	}

const ZAMStmt ZAMCompiler::FinishBlock(const ZAMStmt /* start */)
	{
	return ZAMStmt(insts1.size() - 1);
	}

bool ZAMCompiler::NullStmtOK() const
	{
	// They're okay iff they're the entire statement body.
	return insts1.size() == 0;
	}

const ZAMStmt ZAMCompiler::EmptyStmt()
	{
	return ZAMStmt(insts1.size() - 1);
	}

const ZAMStmt ZAMCompiler::LastInst()
	{
	return ZAMStmt(insts1.size() - 1);
	}

const ZAMStmt ZAMCompiler::ErrorStmt()
	{
	return ZAMStmt(0);
	}

bool ZAMCompiler::IsUnused(const IDPtr& id, const Stmt* where) const
	{
	if ( ! ud->HasUsage(where) )
		return true;

	auto usage = ud->GetUsage(where);
	// usage can be nil if due to constant propagation we've prune
	// all of the uses of the given identifier.

	return ! usage || ! usage->HasID(id.get());
	}

OpaqueVals* ZAMCompiler::BuildVals(const ListExprPtr& l)
	{
	return new OpaqueVals(InternalBuildVals(l.get()));
	}

ZInstAux* ZAMCompiler::InternalBuildVals(const ListExpr* l, int stride)
	{
	auto exprs = l->Exprs();
	int n = exprs.length();

	auto aux = new ZInstAux(n * stride);

	int offset = 0;	// offset into aux info
	for ( int i = 0; i < n; ++i )
		{
		auto& e = exprs[i];
		int num_vals = InternalAddVal(aux, offset, e);
		ASSERT(num_vals == stride);
		offset += num_vals;
		}

	return aux;
	}

int ZAMCompiler::InternalAddVal(ZInstAux* zi, int i, Expr* e)
	{
	if ( e->Tag() == EXPR_ASSIGN )
		{ // We're building up a table constructor
		auto& indices = e->GetOp1()->AsListExpr()->Exprs();
		auto val = e->GetOp2();
		int width = indices.length();

		for ( int j = 0; j < width; ++j )
			ASSERT(InternalAddVal(zi, i + j, indices[j]) == 1);

		ASSERT(InternalAddVal(zi, i + width, val.get()) == 1);

		return width + 1;
		}

	if ( e->Tag() == EXPR_LIST )
		{ // We're building up a set constructor
		auto& indices = e->AsListExpr()->Exprs();
		int width = indices.length();

		for ( int j = 0; j < width; ++j )
			ASSERT(InternalAddVal(zi, i + j, indices[j]) == 1);

		return width;
		}

	if ( e->Tag() == EXPR_FIELD_ASSIGN )
		{
		// These can appear when we're processing the
		// expression list for a record constructor.
		auto fa = e->AsFieldAssignExpr();
		e = fa->GetOp1().get();

		if ( e->GetType()->Tag() == TYPE_TYPE )
			{
			// Ugh - we actually need a "type" constant.
			auto v = e->Eval(nullptr);
			ASSERT(v);
			zi->Add(i, v);
			return 1;
			}

		// Now that we've adjusted, fall through.
		}

	if ( e->Tag() == EXPR_NAME )
		zi->Add(i, FrameSlot(e->AsNameExpr()), e->GetType());

	else
		zi->Add(i, e->AsConstExpr()->ValuePtr());

	return 1;
	}

const ZAMStmt ZAMCompiler::AddInst(const ZInstI& inst)
	{
	ZInstI* i;

	if ( pending_inst )
		{
		i = pending_inst;
		pending_inst = nullptr;
		}
	else
		i = new ZInstI();

	*i = inst;

	insts1.push_back(i);

	top_main_inst = insts1.size() - 1;

	if ( mark_dirty < 0 )
		return ZAMStmt(top_main_inst);

	auto dirty_global_slot = mark_dirty;
	mark_dirty = -1;

	auto dirty_inst = ZInstI(OP_DIRTY_GLOBAL_V, dirty_global_slot);
	dirty_inst.op_type = OP_V_I1;

	return AddInst(dirty_inst);
	}

const Stmt* ZAMCompiler::LastStmt(const Stmt* s) const
	{
	if ( s->Tag() == STMT_LIST )
		{
		auto sl = s->AsStmtList()->Stmts();
		return sl[sl.length() - 1];
		}

	else
		return s;
	}

void ZAMCompiler::LoadParam(ID* id)
	{
	if ( id->IsType() )
		reporter->InternalError("don't know how to compile local variable that's a type not a value");

	bool is_any = IsAny(id->GetType());

	ZOp op;

	op = AssignmentFlavor(OP_LOAD_VAL_VV, id->GetType()->Tag());

	int slot = AddToFrame(id);

	ZInstI z(op, slot, id->Offset());
	z.SetType(id->GetType());
	z.op_type = OP_VV_FRAME;

	(void) AddInst(z);
	}

const ZAMStmt ZAMCompiler::LoadGlobal(ID* id)
	{
	ZOp op;

	if ( id->IsType() )
		// Need a special load for these, as they don't fit
		// with the usual template.
		op = OP_LOAD_GLOBAL_TYPE_VV;
	else
		op = AssignmentFlavor(OP_LOAD_GLOBAL_VV, id->GetType()->Tag());

	auto slot = RawSlot(id);

	ZInstI z(op, slot, global_id_to_info[id]);
	z.SetType(id->GetType());
	z.op_type = OP_VV_I2;

	z.aux = new ZInstAux(0);
	z.aux->id_val = id;

	did_global_load = true;

	return AddInst(z);
	}

int ZAMCompiler::AddToFrame(ID* id)
	{
	frame_layout1[id] = frame_sizeI;
	frame_denizens.push_back(id);
	return frame_sizeI++;
	}

void ZAMCompiler::Dump()
	{
	bool remapped_frame = ! analysis_options.no_ZAM_opt;

	if ( remapped_frame )
		printf("Original frame:\n");

	for ( auto frame_elem : frame_layout1 )
		printf("frame[%d] = %s\n", frame_elem.second, frame_elem.first->Name());

	if ( remapped_frame )
		{
		printf("Final frame:\n");

		for ( auto i = 0U; i < shared_frame_denizens.size(); ++i )
			{
			printf("frame2[%d] =", i);
			for ( auto& id : shared_frame_denizens[i].ids )
				printf(" %s", id->Name());
			printf("\n");
			}
		}

	if ( insts2.size() > 0 )
		printf("Pre-removal of dead code:\n");

	auto remappings = remapped_frame ? &shared_frame_denizens : nullptr;

	for ( auto i = 0U; i < insts1.size(); ++i )
		{
		auto& inst = insts1[i];
		auto depth = inst->loop_depth;
		printf("%d%s%s: ", i, inst->live ? "" : " (dead)",
		       depth ? util::fmt(" (loop %d)", depth) : "");
		inst->Dump(&frame_denizens, remappings);
		}

	if ( insts2.size() > 0 )
		printf("Final intermediary code:\n");

	remappings = remapped_frame ? &shared_frame_denizens_final : nullptr;

	for ( auto i = 0U; i < insts2.size(); ++i )
		{
		auto& inst = insts2[i];
		auto depth = inst->loop_depth;
		printf("%d%s%s: ", i, inst->live ? "" : " (dead)",
		       depth ? util::fmt(" (loop %d)", depth) : "");
		inst->Dump(&frame_denizens, remappings);
		}

	if ( insts2.size() > 0 )
		printf("Final code:\n");

	for ( auto i = 0U; i < insts2.size(); ++i )
		{
		auto& inst = insts2[i];
		printf("%d: ", i);
		inst->Dump(&frame_denizens, remappings);
		}

	for ( auto i = 0U; i < int_casesI.size(); ++i )
		DumpIntCases(i);
	for ( auto i = 0U; i < uint_casesI.size(); ++i )
		DumpUIntCases(i);
	for ( auto i = 0U; i < double_casesI.size(); ++i )
		DumpDoubleCases(i);
	for ( auto i = 0U; i < str_casesI.size(); ++i )
		DumpStrCases(i);
	}

void ZAMCompiler::DumpIntCases(int i) const
	{
	printf("int switch table #%d:", i);
	for ( auto& m : int_casesI[i] )
		printf(" %lld->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAMCompiler::DumpUIntCases(int i) const
	{
	printf("uint switch table #%d:", i);
	for ( auto& m : uint_casesI[i] )
		printf(" %llu->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAMCompiler::DumpDoubleCases(int i) const
	{
	printf("double switch table #%d:", i);
	for ( auto& m : double_casesI[i] )
		printf(" %lf->%d", m.first, m.second->inst_num);
	printf("\n");
	}

void ZAMCompiler::DumpStrCases(int i) const
	{
	printf("str switch table #%d:", i);
	for ( auto& m : str_casesI[i] )
		printf(" %s->%d", m.first.c_str(), m.second->inst_num);
	printf("\n");
	}

void ZAMCompiler::SyncGlobals(const Stmt* s)
	{
	SyncGlobals(pf->Globals(), s);
	}

void ZAMCompiler::SyncGlobals(const std::unordered_set<const ID*>& globals,
                              const Stmt* s)
	{
	// We're at a point where we need to ensure that any cached
	// value we have of a global is synchronized with external uses
	// (such as by the interpreter).
	//
	// We need to check for two situations.  (1) A modification to
	// a global makes it to this point, so we need to synchronize
	// globals in order to flush that modification.  (2) A global
	// whose value we've used (not necessarily modified) previously
	// will also be used after this point, and thus we should
	// synchronize in order to return it to the "unloaded" state
	// in case it's modified by whatever is leading us to decide
	// to synchronize globals here.  (Note that if this call is
	// happening due to finishing a function's execution, then there
	// won't be any subsequent use, and we won't bother flushing
	// unless we have a modified global.)
	//
	// We can determine the first case using reaching-defs: is
	// there a modification to a global that reaches this point?
	//
	// The second case is harder to do with full precision.  Ideally
	// we'd like to know whether there's a reference to a global
	// between this point and all previous possible global synchronization
	// points (including function entry), and then for that global
	// seeing whether there's a UseDef for it at this point, indicating
	// it'll be used subsequently.  We don't have the data structures
	// built up to do this.  However, can approximate the notion by
	// (1) tracking whether *any* LoadGlobal has happened so far,
	// and (2) seeing whether *any* global has a UseDef at this point.

	bool need_sync = false;

	// First case: look for modifications that reach this point.
	auto mgr = reducer->GetDefSetsMgr();
	auto curr_rds = s ? mgr->GetPreMaxRDs(s) :
	                    mgr->GetPostMaxRDs(LastStmt(body.get()));

	// Note that curr_rds might be nil, for functions that only access
	// (but don't modify) globals, and have no modified locals, at the
	// point of interest.

	if ( curr_rds )
		{
		auto entry_rds = mgr->GetPreMaxRDs(body.get());

		for ( auto g : globals )
			{
			auto g_di = mgr->GetConstID_DI(g);
			auto entry_dps = entry_rds->GetDefPoints(g_di);
			auto curr_dps = curr_rds->GetDefPoints(g_di);

			if ( ! entry_rds->SameDefPoints(entry_dps, curr_dps) )
				{
				modified_globals.insert(g);
				need_sync = true;
				}
			}
		}

	// Second case: we've already loaded some globals, and there are
	// globals used after this point.
	if ( did_global_load && s )
		{
		auto uds = ud->GetUsage(s);

		if ( uds )
			for ( auto g : globals )
				if ( uds->HasID(g) )
					{
					need_sync = true;
					break;
					}
		}

	if ( need_sync )
		(void) AddInst(ZInstI(OP_SYNC_GLOBALS_X));
	}

void ZAMCompiler::PushGoTos(GoToSets& gotos)
	{
	std::vector<ZAMStmt> vi;
	gotos.push_back(vi);
	}

void ZAMCompiler::ResolveGoTos(GoToSets& gotos, const InstLabel l)
	{
	auto& g = gotos.back();

	for ( auto i = 0U; i < g.size(); ++i )
		SetGoTo(g[i], l);

	gotos.pop_back();
	}

ZAMStmt ZAMCompiler::GenGoTo(GoToSet& v)
	{
	auto g = GoToStub();
	v.push_back(g.stmt_num);

	return g;
	}

ZAMStmt ZAMCompiler::GoToStub()
	{
	ZInstI z(OP_GOTO_V, 0);
	z.op_type = OP_V_I1;
	return AddInst(z);
	}

ZAMStmt ZAMCompiler::GoTo(const InstLabel l)
	{
	ZInstI inst(OP_GOTO_V, 0);
	inst.target = l;
	inst.target_slot = 1;
	inst.op_type = OP_V_I1;
	return AddInst(inst);
	}

InstLabel ZAMCompiler::GoToTarget(const ZAMStmt s)
	{
	return insts1[s.stmt_num];
	}

InstLabel ZAMCompiler::GoToTargetBeyond(const ZAMStmt s)
	{
	int n = s.stmt_num;

	if ( n == int(insts1.size()) - 1 )
		{
		if ( ! pending_inst )
			pending_inst = new ZInstI();

		return pending_inst;
		}

	return insts1[n+1];
	}

ZAMStmt ZAMCompiler::PrevStmt(const ZAMStmt s)
	{
	return ZAMStmt(s.stmt_num - 1);
	}

void ZAMCompiler::SetTarget(ZInstI* inst, const InstLabel l, int slot)
	{
	if ( inst->target )
		{
		ASSERT(! inst->target2);
		inst->target2 = l;
		inst->target2_slot = slot;
		}
	else
		{
		inst->target = l;
		inst->target_slot = slot;
		}
	}

void ZAMCompiler::SetV1(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 1);
	ASSERT(inst->op_type == OP_V || inst->op_type == OP_V_I1);
	inst->op_type = OP_V_I1;
	}

void ZAMCompiler::SetV2(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 2);

	auto& ot = inst->op_type;

	if ( ot == OP_VV )
		ot = OP_VV_I2;

	else if ( ot == OP_VC || ot == OP_VVC )
		ot = OP_VVC_I2;

	else
		ASSERT(ot == OP_VV_I2 || ot == OP_VVC_I2);
	}

void ZAMCompiler::SetV3(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 3);

	auto ot = inst->op_type;

	if ( ot == OP_VVV_I2_I3 || ot == OP_VVVC_I3 )
		return;

	ASSERT(ot == OP_VV || ot == OP_VVV || ot == OP_VVV_I3);
	inst->op_type = OP_VVV_I3;
	}

void ZAMCompiler::SetV4(ZAMStmt s, const InstLabel l)
	{
	auto inst = insts1[s.stmt_num];
	SetTarget(inst, l, 4);

	auto ot = inst->op_type;

	ASSERT(ot == OP_VVVV || ot == OP_VVVV_I4);
	if ( ot != OP_VVVV_I4 )
		inst->op_type = OP_VVVV_I4;
	}


int ZAMCompiler::FrameSlot(const ID* id)
	{
	auto slot = RawSlot(id);

	if ( id->IsGlobal() )
		(void) LoadGlobal(frame_denizens[slot]);

	return slot;
	}

int ZAMCompiler::Frame1Slot(const ID* id, ZAMOp1Flavor fl)
	{
	auto slot = RawSlot(id);

	switch ( fl ) {
	case OP1_READ:
		if ( id->IsGlobal() )
			(void) LoadGlobal(frame_denizens[slot]);
		break;

	case OP1_WRITE:
		if ( id->IsGlobal() )
			mark_dirty = global_id_to_info[id];
		break;

        case OP1_READ_WRITE:
		if ( id->IsGlobal() )
			{
			(void) LoadGlobal(frame_denizens[slot]);
			mark_dirty = global_id_to_info[id];
			}
		break;

	case OP1_INTERNAL:
		break;
	}

	return slot;
	}

int ZAMCompiler::RawSlot(const ID* id)
	{
	auto id_slot = frame_layout1.find(id);

	if ( id_slot == frame_layout1.end() )
		reporter->InternalError("ID %s missing from frame layout", id->Name());

	return id_slot->second;
	}

bool ZAMCompiler::HasFrameSlot(const ID* id) const
	{
	return frame_layout1.find(id) != frame_layout1.end();
	}

int ZAMCompiler::NewSlot(bool is_managed)
	{
	char buf[8192];
	snprintf(buf, sizeof buf, "#internal-%d#", frame_sizeI);

	// In the following, all that matters is that for managed
	// types we pick a tag that will be viewed as managed, and
	// vice versa.
	auto tag = is_managed ? TYPE_TABLE : TYPE_VOID;

	auto internal_reg = new ID(buf, SCOPE_FUNCTION, false);
	internal_reg->SetType(base_type(tag));

	return AddToFrame(internal_reg);
	}

int ZAMCompiler::TempForConst(const ConstExpr* c)
	{
	auto slot = NewSlot(c->GetType());
	auto z = ZInstI(OP_ASSIGN_CONST_VC, slot, c);
	z.CheckIfManaged(c->GetType());
	(void) AddInst(z);

	return slot;
	}

ZInstI* ZAMCompiler::FindLiveTarget(ZInstI* goto_target)
	{
	if ( goto_target == pending_inst )
		return goto_target;

	int idx = goto_target->inst_num;
	ASSERT(idx >= 0 && idx <= insts1.size());

	while ( idx < int(insts1.size()) && ! insts1[idx]->live )
		++idx;

	if ( idx == int(insts1.size()) )
		return pending_inst;
	else
		return insts1[idx];
	}

void ZAMCompiler::RetargetBranch(ZInstI* inst, ZInstI* target, int target_slot)
	{
	int t;	// instruction number of target

	if ( target == pending_inst )
		t = insts2.size();
	else
		t = target->inst_num;

	switch ( target_slot ) {
	case 1:	inst->v1 = t; break;
	case 2:	inst->v2 = t; break;
	case 3:	inst->v3 = t; break;
	case 4:	inst->v4 = t; break;

	default:
		reporter->InternalError("bad GoTo target");
	}
	}

} // zeek::detail
