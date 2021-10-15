// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/File.h"
#include "zeek/RE.h"
#include "zeek/script_opt/CPP/Compile.h"

using namespace std;

namespace zeek::detail
	{

string CPPCompile::BuildConstant(const Obj* parent, const ValPtr& vp)
	{
	if ( ! vp )
		return "nullptr";

	if ( AddConstant(vp) )
		{
		auto v = vp.get();
		AddInit(parent);
		NoteInitDependency(parent, v);

		// Make sure the value pointer, which might be transient
		// in construction, sticks around so we can track its
		// value.
		cv_indices.push_back(vp);

		return const_vals[v];
		}
	else
		return NativeToGT(GenVal(vp), vp->GetType(), GEN_VAL_PTR);
	}

void CPPCompile::AddConstant(const ConstExpr* c)
	{
	auto v = c->ValuePtr();

	if ( AddConstant(v) )
		{
		AddInit(c);
		NoteInitDependency(c, v.get());
		}
	}

bool CPPCompile::AddConstant(const ValPtr& vp)
	{
	auto v = vp.get();

	if ( IsNativeType(v->GetType()) )
		// These we instantiate directly.
		return false;

	if ( const_vals.count(v) > 0 )
		// Already did this one.
		return true;

	// Formulate a key that's unique per distinct constant.

	const auto& t = v->GetType();
	string c_desc;

	if ( t->Tag() == TYPE_STRING )
		{
		// We can't rely on these to render with consistent
		// escaping, sigh.  Just use the raw string.
		auto s = v->AsString();
		auto b = (const char*)(s->Bytes());
		c_desc = string(b, s->Len()) + "string";
		}
	else
		{
		ODesc d;
		v->Describe(&d);

		// Don't confuse constants of different types that happen to
		// render the same.
		t->Describe(&d);

		c_desc = d.Description();
		}

	if ( constants.count(c_desc) > 0 )
		{
		const_vals[v] = constants[c_desc];

		auto orig_v = constants_to_vals[c_desc];
		ASSERT(v != orig_v);
		AddInit(v);
		NoteInitDependency(v, orig_v);

		return true;
		}

	auto tag = t->Tag();
	auto const_name = const_info[tag]->NextName();
	std::shared_ptr<CPP_GlobalInfo> gi;

	switch ( tag )
		{
                case TYPE_BOOL:
			gi = make_shared<BoolConstantInfo>(vp);
			break;

                case TYPE_INT:
			gi = make_shared<IntConstantInfo>(vp);
			break;

                case TYPE_COUNT:
			gi = make_shared<CountConstantInfo>(vp);
			break;

                case TYPE_ENUM:
			gi = make_shared<EnumConstantInfo>(this, vp);
			break;

                case TYPE_DOUBLE:
			gi = make_shared<DoubleConstantInfo>(vp);
			break;

                case TYPE_TIME:
			gi = make_shared<TimeConstantInfo>(vp);
			break;

                case TYPE_INTERVAL:
			gi = make_shared<IntervalConstantInfo>(vp);
			break;

                case TYPE_STRING:
			gi = make_shared<StringConstantInfo>(vp);
			break;

                case TYPE_PATTERN:
			gi = make_shared<PatternConstantInfo>(vp);
			break;

                case TYPE_ADDR:
			gi = make_shared<DescConstantInfo>(vp);
			break;

                case TYPE_SUBNET:
			gi = make_shared<DescConstantInfo>(vp);
			break;

                case TYPE_PORT:
			gi = make_shared<PortConstantInfo>(vp);
			break;

                case TYPE_LIST:
			gi = make_shared<ListConstantInfo>(this, vp);
			break;

                case TYPE_VECTOR:
			gi = make_shared<VectorConstantInfo>(this, vp);
			break;

                case TYPE_RECORD:
			gi = make_shared<RecordConstantInfo>(this, vp);
			break;

                case TYPE_TABLE:
			gi = make_shared<TableConstantInfo>(this, vp);
			break;

                case TYPE_FILE:
			gi = make_shared<FileConstantInfo>(this, vp);
			break;

                case TYPE_FUNC:
			gi = make_shared<FuncConstantInfo>(this, vp);

			// We can't generate the initialization now because it
			// depends on first having compiled the associated body,
			// so we know its hash.  So for now we just note it
			// to deal with later.
			func_vars[v->AsFuncVal()] = const_name;

			break;

		default:
			reporter->InternalError("bad constant type in CPPCompile::AddConstant");
			break;
		}

	const_name = const_info[tag]->NextName();
	const_info[tag]->AddInstance(gi);

#if 0
		case TYPE_RECORD:
			AddRecordConstant(vp, const_name);
			break;

		case TYPE_TABLE:
			AddTableConstant(vp, const_name);
			break;

		case TYPE_VECTOR:
			AddVectorConstant(vp, const_name);
			break;

		case TYPE_FUNC:
			Emit("FuncValPtr %s;", const_name);

			// We can't generate the initialization now because it
			// depends on first having compiled the associated body,
			// so we know its hash.  So for now we just note it
			// to deal with later.
			func_vars[v->AsFuncVal()] = const_name;
			break;

		case TYPE_FILE:
				{
				Emit("FileValPtr %s;", const_name);

				auto f = cast_intrusive<FileVal>(vp)->Get();

				AddInit(v, const_name,
				        string("make_intrusive<FileVal>(") + "make_intrusive<File>(\"" + f->Name() +
				            "\", \"w\"))");
				}
			break;

		default:
			reporter->InternalError("bad constant type in CPPCompile::AddConstant");
		}
#endif

	const_vals[v] = constants[c_desc] = const_name;
	constants_to_vals[c_desc] = v;

#if 0
	switch ( tag )
		{
                case TYPE_BOOL:
                        return string("val_mgr->Bool(") + expr + ")";

                case TYPE_INT:
                        return string("val_mgr->Int(") + expr + ")";

                case TYPE_COUNT:
                        return string("val_mgr->Count(") + expr + ")";

                case TYPE_PORT:
                        return string("val_mgr->Port(") + expr + ")";

                case TYPE_ENUM:

		case TYPE_STRING:
		case TYPE_PATTERN:
		case TYPE_ADDR:
		case TYPE_SUBNET:
		case TYPE_LIST:
			AddInit(vp);
			break;

		case TYPE_RECORD:
			AddRecordConstant(vp, const_name);
			break;

		case TYPE_TABLE:
			AddTableConstant(vp, const_name);
			break;

		case TYPE_VECTOR:
			AddVectorConstant(vp, const_name);
			break;

		case TYPE_FUNC:
			Emit("FuncValPtr %s;", const_name);

			// We can't generate the initialization now because it
			// depends on first having compiled the associated body,
			// so we know its hash.  So for now we just note it
			// to deal with later.
			func_vars[v->AsFuncVal()] = const_name;
			break;

		case TYPE_FILE:
				{
				Emit("FileValPtr %s;", const_name);

				auto f = cast_intrusive<FileVal>(vp)->Get();

				AddInit(v, const_name,
				        string("make_intrusive<FileVal>(") + "make_intrusive<File>(\"" + f->Name() +
				            "\", \"w\"))");
				}
			break;

		default:
			reporter->InternalError("bad constant type in CPPCompile::AddConstant");
		}
#endif

	return true;
	}

void CPPCompile::AddListConstant(const ValPtr& v, string& const_name)
	{
	Emit("ListValPtr %s;", const_name);

	// No initialization dependency on the main type since we don't
	// use the underlying TypeList.  However, we *do* use the types of
	// the elements.

	AddInit(v, const_name, string("make_intrusive<ListVal>(TYPE_ANY)"));

	auto lv = cast_intrusive<ListVal>(v);
	auto n = lv->Length();

	for ( auto i = 0; i < n; ++i )
		{
		const auto& l_i = lv->Idx(i);
		auto l_i_c = BuildConstant(v, l_i);
		AddInit(v, const_name + "->Append(" + l_i_c + ");");
		NoteInitDependency(v, TypeRep(l_i->GetType()));
		}
	}

void CPPCompile::AddRecordConstant(const ValPtr& v, string& const_name)
	{
	const auto& t = v->GetType();

	Emit("RecordValPtr %s;", const_name);

	NoteInitDependency(v, TypeRep(t));

	AddInit(v, const_name,
	        string("make_intrusive<RecordVal>(") + "cast_intrusive<RecordType>(" + GenTypeName(t) +
	            "))");

	auto r = cast_intrusive<RecordVal>(v);
	auto n = r->NumFields();

	for ( auto i = 0u; i < n; ++i )
		{
		const auto& r_i = r->GetField(i);

		if ( r_i )
			{
			auto r_i_c = BuildConstant(v, r_i);
			AddInit(v, const_name + "->Assign(" + Fmt(static_cast<int>(i)) + ", " + r_i_c + ");");
			}
		}
	}

void CPPCompile::AddTableConstant(const ValPtr& v, string& const_name)
	{
	const auto& t = v->GetType();

	Emit("TableValPtr %s;", const_name);

	NoteInitDependency(v, TypeRep(t));

	AddInit(v, const_name,
	        string("make_intrusive<TableVal>(") + "cast_intrusive<TableType>(" + GenTypeName(t) +
	            "))");

	auto tv = cast_intrusive<TableVal>(v);
	auto tv_map = tv->ToMap();

	for ( auto& tv_i : tv_map )
		{
		auto ind = BuildConstant(v, tv_i.first);
		auto val = BuildConstant(v, tv_i.second);
		AddInit(v, const_name + "->Assign(" + ind + ", " + val + ");");
		}
	}

void CPPCompile::AddVectorConstant(const ValPtr& v, string& const_name)
	{
	const auto& t = v->GetType();

	Emit("VectorValPtr %s;", const_name);

	NoteInitDependency(v, TypeRep(t));

	AddInit(v, const_name,
	        string("make_intrusive<VectorVal>(") + "cast_intrusive<VectorType>(" + GenTypeName(t) +
	            "))");

	auto vv = cast_intrusive<VectorVal>(v);
	auto n = vv->Size();

	for ( auto i = 0u; i < n; ++i )
		{
		const auto& v_i = vv->ValAt(i);
		auto v_i_c = BuildConstant(v, v_i);
		AddInit(v, const_name + "->Append(" + v_i_c + ");");
		}
	}

	} // zeek::detail
