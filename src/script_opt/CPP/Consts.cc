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

	string const_name;

	auto tag = t->Tag();

	if ( tag == TYPE_STRING )
		{
		const_name = str_constants->NextName();
		str_constants->AddInstance(make_shared<StringConstantInfo>(vp));
		}
	else if ( tag == TYPE_PATTERN )
		{
		const_name = re_constants->NextName();
		re_constants->AddInstance(make_shared<PatternConstantInfo>(vp));
		}
	else if ( tag == TYPE_ADDR )
		{
		const_name = addr_constants->NextName();
		addr_constants->AddInstance(make_shared<DescConstantInfo>(vp));
		}
	else if ( tag == TYPE_SUBNET )
		{
		const_name = subnet_constants->NextName();
		subnet_constants->AddInstance(make_shared<DescConstantInfo>(vp));
		}
	else if ( tag == TYPE_LIST )
		{
		const_name = list_constants->NextName();
		list_constants->AddInstance(make_shared<ListConstantInfo>(this, vp));
		}
	else
		// Need a C++ global for this constant.
		const_name = string("CPP__const__") + Fmt(int(constants.size()));

	const_vals[v] = constants[c_desc] = const_name;
	constants_to_vals[c_desc] = v;

	switch ( tag )
		{
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
