// Class for tracking items of a given type that we need to
// (1) save in a readable form, and (2) maintain a mapping so
// that we can refer to the items when saving instructions.
//
// The basic idea is we make one pass through the instructions
// accumulating items (and constructing string representations,
// which are provided by template specializations), and a second
// pass then saving instructions using the representations.
//
// Note that items are deemed equivalent if they have the same
// string representation.  This both makes the save representation
// more compact and quicker to load, and also addresses the problem
// of items that are transient, such as Val's constructed using
// ZVal::ToVal, which will have a different pointer value
// every time we instantiate them.

// Constant used to represent a missing value.
const auto NA = "*";
const auto SP_NA = " *";	// same but with a leading space

// Type used to hold the representation of an item.
using RepType = std::string;

template<typename T>
class ItemTracker {
public:
	ItemTracker()	{ }

	virtual void AddItem(T item)
		{
		if ( ! item )
			return;

		auto rep = ItemRep(item);

		if ( item_map.count(rep) == 0 )
			{
			item_map[rep] = items.size();	// 0-based
			items.push_back(rep);
			}
		}

	int FindItem(const T item) const
		{
		auto rep = ItemRep(item);

		auto el = item_map.find(rep);
		if ( el == item_map.end() )
			return -1;
		else
			return el->second;
		}

	// Writes the items to the given file, using the given tag.  Does
	// nothing if there are no items.
	void Render(FILE* f, const char* tag) const
		{
		if ( items.size() == 0 )
			return;

		fprintf(f, "<%s> {\n", tag);
		for ( auto i : items )
			fprintf(f, " %s,\n", i.c_str());
		fprintf(f, "}\n");
		}

protected:
	// This is specialized per type T.
	virtual RepType ItemRep(const T item) const = 0;

	vector<RepType> items;
	std::unordered_map<RepType, int> item_map;	// inverse
};


class ValTracker : public ItemTracker<const Val*> {
protected:
	RepType ItemRep(const Val* item) const override
		{
		ODesc d(DESC_PARSEABLE);

		// Special case for integers: we need these to be
		// parsed as such, and not as counts.
		auto t = item->GetType();
		if ( t->Tag() == TYPE_INT && item->AsInt() >= 0 )
			d.Add("+");

		// Special case for doubles that aren't representable
		// directly as Zeek constants.  (Note, strictly speaking
		// these could occur for "time" and "interval" types,
		// but at present we don't support those.)
		if ( t->Tag() == TYPE_DOUBLE )
			{
			auto infinity = RepType("1e9999");
			double d = item->AsDouble();

			if ( fpclassify(d) == FP_ZERO && signbit(d) )
				return RepType("-0.0");

			if ( isinf(d) )
				{
				if ( d < 0 )
					return RepType("-") + infinity;
				else
					return infinity;
				}

			if ( isnan(d) )
				return infinity + "/" + infinity;
			}

		item->Describe(&d);
		return RepType(d.Description());
		}
};


class AttrTracker : public ItemTracker<const Attributes*> {
protected:
	RepType ItemRep(const Attributes* item) const override
		{
		ODesc d(DESC_PARSEABLE);
		item->Describe(&d);
		// We need a delimiter to mark the end of the list,
		// to allow representing multiple lists unambiguously.
		d.Add(";");
		return RepType(d.Description());
		}
};

class LocFileTracker : public ItemTracker<const char*> {
protected:
	RepType ItemRep(const char* item) const override
		{
		ODesc d(DESC_PARSEABLE);
		d.Add("\"");
		d.Add(item);
		d.Add("\"");
		return RepType(d.Description());
		}
};

class LocTracker : public ItemTracker<const Location*> {
public:
	LocTracker(LocFileTracker& _lf) : lf(_lf)	{ }

	// A refinement to AddItem that knows how to populate the
	// LocFileTracker.
	void AddItem(const Location* item) override
		{
		if ( ! item )
			return;
		
		lf.AddItem(item->filename);
		ItemTracker::AddItem(item);
		}

protected:
	RepType ItemRep(const Location* item) const override
		{
		ODesc d(DESC_PARSEABLE);
		d.Add(lf.FindItem(item->filename));
		d.AddSP(",");
		d.Add(item->first_line);
		d.AddSP(",");
		d.Add(item->last_line);
		return RepType(d.Description());
		}

	LocFileTracker& lf;
};


class TypeTracker : public ItemTracker<const Type*> {
protected:
	RepType ItemRep(const Type* item) const override
		{
		ODesc d(DESC_PARSEABLE);
		DescribeType(item, &d, true);
		return RepType(d.Description());
		}

	// Describes the given type in a form that is parse-able (which
	// is more detailed than what we get just using Type::Describe()).
	//
	// top_level is true if we're describing the type stand-alone
	// (not as a component of another type).
	void DescribeType(const Type* t, ODesc* d, bool top_level) const;
};

void TypeTracker::DescribeType(const Type* t, ODesc* d, bool top_level) const
	{
	auto t_name = t->GetName();

	if ( t_name.length() > 0 )
		{
		// Always prefer to use a type name.
		d->Add(t_name.c_str());
		return;
		}

	switch ( t->Tag() ) {
	case TYPE_VOID:
	case TYPE_BOOL:
	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_DOUBLE:
	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_STRING:
	case TYPE_PATTERN:
	case TYPE_TIMER:
	case TYPE_PORT:
	case TYPE_ADDR:
	case TYPE_SUBNET:
	case TYPE_ANY:
	case TYPE_ERROR:
		t->Describe(d);
		break;

	case TYPE_ENUM:
		reporter->InternalError("enum type without a name");
		break;

	case TYPE_TYPE:
		d->AddSP("type {");
		DescribeType(t->AsTypeType()->GetType(), d, false);
		d->Add("}");
		break;

	case TYPE_TABLE:
		{
		auto tbl = t->AsTableType();
		auto yt = tbl->YieldType();

		if ( yt )
			d->Add("table[");
		else
			d->Add("set[");

		DescribeType(tbl->Indices(), d, false);

		d->Add("]");

		if ( yt )
			{
			d->Add(" of ");
			DescribeType(yt, d, false);
			}
		break;
		}

	case TYPE_FUNC:
		{
		auto f = t->AsFuncType();

		d->Add(f->FlavorString());
		d->Add("(");

		auto args = f->Args();
		int n = args->NumFields();

		for ( auto i = 0; i < n; ++i )
			{
			d->Add(args->FieldName(i));
			d->AddSP(":");

			DescribeType(args->FieldType(i), d, false);

			if ( i < n - 1 )
				d->AddSP(",");
			}

		d->Add(")");
		auto yt = f->YieldType();

		if ( f->Flavor() == FUNC_FLAVOR_FUNCTION &&
		     yt && yt->Tag() != TYPE_VOID )
			{
			d->AddSP(":");
			DescribeType(yt, d, false);
			}

		break;
		}

	case TYPE_RECORD:
		{
		auto rt = t->AsRecordType();
		int n = rt->NumFields();

		d->Add("record { ");

		for ( auto i = 0; i < n; ++i )
			{
			d->Add(rt->FieldName(i));
			d->AddSP(":");

			DescribeType(rt->FieldType(i), d, false);
			d->AddSP(";");
			}

		d->Add("}");
		break;
		}

	case TYPE_LIST:
		{
		if ( top_level )
			d->AddSP("list {");

		auto l = t->AsTypeList()->Types();
		int n = l->length();

		for ( auto i = 0; i < n; ++i )
			{
			DescribeType((*l)[i], d, false);
			if ( i < n - 1 )
				d->AddSP(",");
			}

		if ( top_level )
			d->Add(" }");

		break;
		}

	case TYPE_VECTOR:
	case TYPE_FILE:
		d->Add(type_name(t->Tag()));
		d->Add(" of ");
		DescribeType(t->YieldType(), d, false);
		break;

	case TYPE_OPAQUE:
		d->Add("opaque of ");
		d->Add(t->AsOpaqueType()->Name());
		break;

	case TYPE_UNION:
		reporter->InternalError("union type in ZBody::DescribeType()");
	}
	}


class AuxTracker : public ItemTracker<const ZInstAux*> {
public:
	// AuxTracker's are complex because to describe a ZInstAux
	// requires referencing the types and values within it, so
	// we need those trackers too.
	AuxTracker(TypeTracker& _tt, ValTracker& _vt)
	: tt(_tt), vt(_vt)
		{
		}

	// A version of AddItem that knows how to unpack the elements
	// of a ZInstAux.  Note that if iteration information (iter_info)
	// is present, we require that its 'n' field is set uniquely
	// (and consistently for subsequent access via FindItem).
	// This is important because iteration information isn't reentrant -
	// two concurrent loops must have distinct information even if
	// they completely match on the static elements.
	void AddItem(const ZInstAux* item) override;

protected:
	RepType ItemRep(const ZInstAux* item) const override;

	TypeTracker& tt;
	ValTracker& vt;
};

void AuxTracker::AddItem(const ZInstAux* item)
	{
	if ( ! item )
		return;

	if ( item->types )
		for ( auto i = 0; i < item->n; ++i )
			{
			tt.AddItem(item->types[i].get());
			vt.AddItem(item->constants[i].get());
			}

	auto ii = item->iter_info;
	if ( ii )
		{
		for ( auto t : ii->loop_var_types )
			tt.AddItem(t.get());

		tt.AddItem(ii->value_var_type.get());
		tt.AddItem(ii->vec_type.get());
		tt.AddItem(ii->yield_type.get());
		}

	// Now that we've added all of our components, we can render
	// a representation of this item, so add it too using the normal
	// mechanism.
	ItemTracker::AddItem(item);
	}

RepType AuxTracker::ItemRep(const ZInstAux* item) const
	{
	ODesc d(DESC_PARSEABLE);

	d.Add(item->n);
	d.SP();

	if ( item->n > 0 )
		{
		for ( auto i = 0; i < item->n; ++i )
			{
			d.AddSP("{");

			auto c = item->constants[i].get();
			if ( c )
				{
				d.Add(vt.FindItem(c));
				d.AddSP(",");
				d.Add(NA);
				}
			else
				{
				d.Add(NA);
				d.AddSP(",");
				d.Add(item->ints[i]);
				}

			d.AddSP(",");

			auto t = item->types[i].get();
			if ( t )
				d.Add(tt.FindItem(t));
			else
				d.Add(NA);

			d.AddSP(" }");
			}

		if ( item->map )
			{
			d.AddSP("; {");

			d.Add(item->n);
			d.SP();

			for ( auto i = 0; i < item->n; ++i )
				{
				d.Add(item->map[i]);
				d.SP();
				}

			d.AddSP("}");
			}
		}

	auto& ii = item->iter_info;
	if ( ii )
		{
		d.Add(" [");
		d.Add(int(ii->loop_var_types.size()));
		d.AddSP(",");

		for ( auto v : ii->loop_vars )
			{
			d.Add(v);
			d.AddSP(",");
			}

		for ( auto t : ii->loop_var_types )
			{
			d.Add(tt.FindItem(t.get()));
			d.AddSP(",");
			}

		if ( ii->value_var_type )
			d.Add(tt.FindItem(ii->value_var_type.get()));
		else
			d.Add(NA);

		d.AddSP(",");

		if ( ii->vec_type )
			d.Add(tt.FindItem(ii->vec_type.get()));
		else
			d.Add(NA);

		d.AddSP(",");

		if ( ii->yield_type )
			d.Add(tt.FindItem(ii->yield_type.get()));
		else
			d.Add(NA);

		// Here we add in the unique/consistent field, to prevent
		// sharing of items that otherwise fully match.  This
		// field is ignored when parsing a save file, since its
		// sole role is to ensure uniqueness.
		d.AddSP(",");
		d.Add(ii->n);

		d.Add("]");
		}

	d.AddSP(",");

	if ( item->id_val )
		d.Add(item->id_val->Name());
	else
		d.Add(NA);

	return RepType(d.Description());
	}


void ZBody::SaveTo(FILE* f, int interp_frame_size) const
	{
	TypeTracker types;
	ValTracker vals;
	AuxTracker auxes(types, vals);
	AttrTracker attrs;
	LocFileTracker loc_files;
	LocTracker locs(loc_files);

	int iter_cnt = 0;

	for ( auto ii = 0U; ii < ninst; ++ii )
		{
		auto i = &insts[ii];

		if ( i->e )
			reporter->InternalError("ZAM save file needs support for expressions");

		types.AddItem(i->t.get());
		types.AddItem(i->t2.get());
		vals.AddItem(i->ConstVal().get());

		if ( i->aux && i->aux->iter_info )
			i->aux->iter_info->n = ++iter_cnt;
		auxes.AddItem(i->aux);

		attrs.AddItem(i->attrs);
		locs.AddItem(i->loc);
		}

	fprintf(f, "<ZAM-file> %s %d %d %d\n",
		func_name, interp_frame_size, num_iters, ! fixed_frame);

	if ( frame_size > 0 )
		{
		fprintf(f, "<frame> {\n");

		for ( auto& fr : frame_denizens )
			{
			int n = fr.names.size();

			for ( auto i = 0; i < n; ++i )
				fprintf(f, " {\"%s\", %d},",
					fr.names[i], fr.id_start[i]);

			fprintf(f, " %d\n", fr.is_managed);
			}

		fprintf(f, "}\n");
		}

	if ( globals.size() > 0 )
		{
		fprintf(f, "<globals> {\n");

		for ( auto& g : globals )
			fprintf(f, " %s, %d,", g.id->Name(), g.slot);

		fprintf(f, "\n}\n");
		}

	SaveCaseMaps(f, int_cases, "int");
	SaveCaseMaps(f, uint_cases, "count");
	SaveCaseMaps(f, double_cases, "double");
	SaveCaseMaps(f, str_cases, "string");

	types.Render(f, "types");
	vals.Render(f, "vals");
	auxes.Render(f, "aux");
	attrs.Render(f, "attrs");
	loc_files.Render(f, "loc-files");
	locs.Render(f, "locs");

	fprintf(f, "<insts> {\n");

	int inst_num = 0;

	for ( auto ii = 0U; ii < ninst; ++ii )
		{
		auto i = &insts[ii];

		fprintf(f, "%d %d %d %s", inst_num++, i->op, i->op_type,
			ZOP_name(i->op));

		int n = i->NumSlots();
		int v;

		for ( v = 0; v < n; ++v )
			{
			int s;
			switch ( v ) {
			case 0:	s = i->v1; break;
			case 1:	s = i->v2; break;
			case 2:	s = i->v3; break;
			case 3:	s = i->v4; break;

			default:
				reporter->InternalError("slot inconsistency");
			}

			fprintf(f, " %d", s);
			}

		for ( ; v < 4; ++v )
			fprintf(f, SP_NA);

		auto val = i->ConstVal();
		if ( val )
			fprintf(f, " %d", vals.FindItem(val.get()));
		else
			fprintf(f, SP_NA);

		if ( i->t )
			fprintf(f, " %d", types.FindItem(i->t.get()));
		else
			fprintf(f, SP_NA);
		if ( i->t2 )
			fprintf(f, " %d", types.FindItem(i->t2.get()));
		else
			fprintf(f, SP_NA);

		if ( i->aux )
			fprintf(f, " %d", auxes.FindItem(i->aux));
		else
			fprintf(f, SP_NA);

		if ( i->attrs )
			fprintf(f, " %d", attrs.FindItem(i->attrs));
		else
			fprintf(f, SP_NA);

		if ( i->loc )
			fprintf(f, " %d", locs.FindItem(i->loc));
		else
			fprintf(f, SP_NA);

		// The stupid comma in the following is to keep the
		// overly-thinking-it scanner from converting a sequence
		// like "0 hrw_hash" to be "0 hr" (an interval!).
		fprintf(f, " %d,", i->is_managed);

		if ( i->func )
			fprintf(f, " %s", i->aux->id_val->Name());
		else
			fprintf(f, SP_NA);

		if ( i->event_handler )
			fprintf(f, " %s", i->event_handler->Name());
		else
			fprintf(f, SP_NA);

		fprintf(f, "\n");
		}

	fprintf(f, "}\n");
	}


void ZBody::SaveCaseMap(FILE* f, const bro_int_t& val) const
	{
	fprintf(f, "%lld", val);
	}
void ZBody::SaveCaseMap(FILE* f, const bro_uint_t& val) const
	{
	fprintf(f, "%llu", val);
	}
void ZBody::SaveCaseMap(FILE* f, const double& val) const
	{
	fprintf(f, "%lf", val);
	}
void ZBody::SaveCaseMap(FILE* f, const std::string& val) const
	{
	StringVal vs(val.c_str());
	ODesc d(DESC_PARSEABLE);
	vs.Describe(&d);
	fprintf(f, "%s", d.Description());
	}

template<class T> void ZBody::SaveCaseMaps(FILE* f, const CaseMaps<T>& cms,
						const char* cms_name) const
	{
	if ( cms.size() == 0 )
		return;

	fprintf(f, "<cases> %s {\n", cms_name);

	for ( auto& cm : cms )
		{
		fprintf(f, " {");
		for ( auto& cmv : cm )
			{
			fprintf(f, " ");
			SaveCaseMap(f, cmv.first);
			fprintf(f, ", %d, ", cmv.second);
			}
		fprintf(f, "}\n");
		}

	fprintf(f, "}\n");
	}

#if 0
	for ( int i = 0; i < int_casesI.size(); ++i )
		DumpIntCases(i);
	for ( int i = 0; i < uint_casesI.size(); ++i )
		DumpUIntCases(i);
	for ( int i = 0; i < double_casesI.size(); ++i )
		DumpDoubleCases(i);
	for ( int i = 0; i < str_casesI.size(); ++i )
		DumpStrCases(i);
#endif
