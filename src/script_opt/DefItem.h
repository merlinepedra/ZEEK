// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/script_opt/DefPoint.h"
#include "zeek/ID.h"
#include "zeek/Type.h"


namespace zeek::detail {


// A definition item is a Zeek script entity that can be assigned to.
// Currently, we track variables and record fields; the latter can
// be nested (for example, a field that's in a record that itself is
// a field in another record).  In principle we could try to track
// table or vector elements, but that's only going to be feasible for
// constant indices, so presumably not much bang-for-the-buck.
//
// For script optimization, we only need to track variables, and we could
// considerably simplify the code by doing so.  However, there's long
// been a desire to be able to statically determine that a record field
// will be used without first having been set, hence we go the more
// complicated route here.

class DefinitionItem {
public:
	// Constructor for the simple case of tracking assignments to
	// a variable.
	DefinitionItem(const ID* _id);

	// The more complicated case of assigning to a field in a record
	// (which itself might be a field in a record).
	DefinitionItem(const DefinitionItem* _di, const char* _field_name,
			TypePtr _t);

	~DefinitionItem();

	bool IsRecord() const	{ return t->Tag() == TYPE_RECORD; }

	const char* Name() const	{ return name ? name : id->Name(); }
	TypePtr GetType() const		{ return t; }

	// For this definition item, look for a field corresponding
	// to the given name/offset.
	DefinitionItem* FindField(const char* field) const;
	DefinitionItem* FindField(int offset) const;

	// Start tracking a field in this definition item with the
	// given name/offset.
	DefinitionItem* CreateField(const char* field, TypePtr t);
	DefinitionItem* CreateField(int offset, TypePtr t);

protected:
	void CheckForRecord();

	bool is_id;
	const ID* id;
	const DefinitionItem* di;
	const char* field_name;

	TypePtr t;

	char* name;

	const RecordType* rt;
	DefinitionItem** fields;	// indexed by field offset
	int num_fields;
};

// For a given identifier, locates its associated definition item.
typedef std::unordered_map<const ID*, DefinitionItem*> ID_to_DI_Map;

// Class for managing a set of IDs and their associated definition items.
class DefItemMap {
public:
	~DefItemMap()
		{
		for ( auto& i2d : i2d )
			delete i2d.second;
		}

	// Gets the definition for either a name or a record field reference.
	// Returns nil if "expr" lacks such a form, or if there isn't
	// any such definition.
	DefinitionItem* GetExprDI(const Expr* expr);

	// Returns the definition item for a given ID; creates it if
	// it doesn't already exist.
	DefinitionItem* GetID_DI(const ID* id);

	// Returns the definition item for a given ID, or nil if it
	// doesn't exist.
	const DefinitionItem* GetConstID_DI(const ID* id) const;

	// The same for a record field for a given definition item.
	const DefinitionItem* GetConstID_DI(const DefinitionItem* di,
						const char* field_name) const;

protected:
	ID_to_DI_Map i2d;
};


} // zeek::detail
