// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include "zeek/script_opt/CPPCompile.h"
#include "zeek/script_opt/ProfileFunc.h"


namespace zeek::detail {

void CPPCompile::GenInitExpr(const ExprPtr& e)
	{
	NL();

	const auto& t = e->GetType();
	auto ename = InitExprName(e);

	// First, create a CPPFunc that we can compile to compute 'e'.
	auto name = std::string("wrapper_") + ename;

	// Forward declaration of the function that computes 'e'.
	Emit("static %s %s(Frame* f__CPP);", FullTypeName(t), name);

	// Create the Func subclass that can be used in a CallExpr to
	// evaluate 'e'.
	Emit("class %s_cl : public CPPFunc", name);
	StartBlock();

	Emit("public:");
	Emit("%s_cl() : CPPFunc(\"%s\", %s)", name, name, e->IsPure() ? "true" : "false");

	StartBlock();
	Emit("type = make_intrusive<FuncType>(make_intrusive<RecordType>(new type_decl_list()), %s, FUNC_FLAVOR_FUNCTION);", GenTypeName(t));

	NoteInitDependency(e, TypeRep(t));
	EndBlock();

	Emit("ValPtr Invoke(zeek::Args* args, Frame* parent) const override final");
	StartBlock();

	if ( IsNativeType(t) )
		GenInvokeBody(name, t, "parent");
	else
		Emit("return %s(parent);", name);

	EndBlock();
	EndBlock(true);

	// Now the implementation of computing 'e'.
	Emit("static %s %s(Frame* f__CPP)", FullTypeName(t), name);
	StartBlock();

	Emit("return %s;", GenExpr(e, GEN_NATIVE));
	EndBlock();

	Emit("CallExprPtr %s;", ename);

	NoteInitDependency(e, TypeRep(t));
	AddInit(e, ename, std::string("make_intrusive<CallExpr>(make_intrusive<ConstExpr>(make_intrusive<FuncVal>(make_intrusive<") +
		name + "_cl>())), make_intrusive<ListExpr>(), false)");
	}

bool CPPCompile::IsSimpleInitExpr(const ExprPtr& e) const
	{
	switch ( e->Tag() ) {
	case EXPR_CONST:
	case EXPR_NAME:
		return true;

	case EXPR_RECORD_COERCE:
		{ // look for coercion of empty record
		auto op = e->GetOp1();

		if ( op->Tag() != EXPR_RECORD_CONSTRUCTOR )
			return false;

		auto rc = static_cast<const RecordConstructorExpr*>(op.get());
		const auto& exprs = rc->Op()->AsListExpr()->Exprs();

		return exprs.length() == 0;
		}

	default:
		return false;
	}
	}

std::string CPPCompile::InitExprName(const ExprPtr& e)
	{
	return init_exprs.KeyName(e);
	}

void CPPCompile::GenGlobalInit(const ID* g, std::string& gl, const ValPtr& v)
	{
	if ( v->GetType()->Tag() == TYPE_FUNC )
		return;

	AddInit(g, std::string("if ( ! ") + gl + "->HasVal() )");
	AddInit(g, std::string("\t") + gl + "->SetVal(" + BuildConstant(g, v) + ");");
	}

void CPPCompile::GenFuncVarInits()
	{
	for ( const auto& fv_init : func_vars )
		{
		auto& fv = fv_init.first;
		auto f = fv->AsFunc();
		auto& const_name = fv_init.second;

		const auto& bodies = f->GetBodies();
		ASSERT(bodies.size() == 1);

		const auto body = bodies[0].stmts.get();
		ASSERT(body_names.count(body) > 0);

		auto& body_name = body_names[body];
		ASSERT(body_hashes.count(body_name) > 0);

		NoteInitDependency(fv, body);

		const auto& h = body_hashes[body_name];
		const auto& fn = f->Name();

		const auto& ft = f->GetType();
		auto ftr = TypeRep(ft);
		NoteInitDependency(fv, ftr);

		auto init = std::string("lookup_func__CPP(\"") + fn + "\", " +
		            Fmt(h) + ", " + GenTypeName(ft) + ")";

		ValPtr fvp{NewRef{}, fv};
		AddInit(fvp, const_name, init);
		}
	}

void CPPCompile::GenPreInit(const Type* t)
	{
	std::string pre_init;

	switch ( t->Tag() ) {
	case TYPE_ADDR:
	case TYPE_ANY:
	case TYPE_BOOL:
	case TYPE_COUNT:
	case TYPE_DOUBLE:
	case TYPE_ERROR:
	case TYPE_INT:
	case TYPE_INTERVAL:
	case TYPE_PATTERN:
	case TYPE_PORT:
	case TYPE_STRING:
	case TYPE_TIME:
	case TYPE_TIMER:
	case TYPE_VOID:
		pre_init = std::string("base_type(") + TypeTagName(t->Tag()) + ")";
		break;

	case TYPE_ENUM:
		pre_init = std::string("get_enum_type__CPP(\"") +
		           t->GetName() + "\")";
		break;

	case TYPE_SUBNET:
		pre_init = std::string("make_intrusive<SubNetType>()");
		break;

	case TYPE_FILE:
		pre_init = std::string("make_intrusive<FileType>(") +
		           GenTypeName(t->AsFileType()->Yield()) + ")";
		break;

	case TYPE_OPAQUE:
		pre_init = std::string("make_intrusive<OpaqueType>(\"") +
		           t->AsOpaqueType()->Name() + "\")";
		break;

	case TYPE_RECORD:
		{
		std::string name;

		if ( t->GetName() != "" )
			name = std::string("\"") + t->GetName() + std::string("\"");
		else
			name = "nullptr";

		pre_init = std::string("get_record_type__CPP(") + name + ")";
		}
		break;

	case TYPE_LIST:
		pre_init = std::string("make_intrusive<TypeList>()");
		break;

	case TYPE_TYPE:
	case TYPE_VECTOR:
	case TYPE_TABLE:
	case TYPE_FUNC:
		// Nothing to do for these, pre-initialization-wise.
		return;

	default:
		reporter->InternalError("bad type in CPPCompile::GenType");
	}

	pre_inits.emplace_back(GenTypeName(t) + " = " + pre_init + ";");
	}

void CPPCompile::AddInit(const Obj* o, const std::string& init)
	{
	obj_inits[o].emplace_back(init);
	}

void CPPCompile::AddInit(const Obj* o)
	{
	if ( obj_inits.count(o) == 0 )
		{
		std::vector<std::string> empty;
		obj_inits[o] = empty;
		}
	}

void CPPCompile::NoteInitDependency(const Obj* o1, const Obj* o2)
	{
	obj_deps[o1].emplace(o2);
	}

} // zeek::detail
