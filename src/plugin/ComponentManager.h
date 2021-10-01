#pragma once

#include <list>
#include <map>
#include <string>

#include "zeek/DebugLogger.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/Var.h" // for add_type()
#include "zeek/zeekygen/Manager.h"
#include "zeek/Tag.h"
#include "zeek/module_util.h"
#include "zeek/Expr.h"
#include "zeek/Attr.h"

namespace zeek::plugin
	{

/**
 * A class that manages tracking of plugin components (e.g. analyzers) and
 * installs identifiers in the script-layer to identify them by a unique tag,
 * (a script-layer enum value).
 *
 * @tparam C A plugin::Component type derivative.
 */
template <class C> class ComponentManager
	{
public:
	/**
	 * Constructor creates a new enum type to associate with
	 * a component.
	 *
	 * @param module The script-layer module in which to install the ID
	 * representing an enum type.
	 *
	 * @param local_id The local part of the ID of the new enum type
	 * (e.g., "Tag").
	 */
	ComponentManager(const std::string& module, const std::string& local_id);

	/**
	 * @return The script-layer module in which the component's "Tag" ID lives.
	 */
	const std::string& GetModule() const;

	/**
	 * @return A list of all registered components.
	 */
	std::list<C*> GetComponents() const;

	/**
	 * @return The enum type associated with the script-layer "Tag".
	 */
	[[deprecated("Remove in v5.1. Use Tag::global_enum_type.")]]
	const EnumTypePtr& GetTagType() const;

	/**
	 * Get a component name from its tag.
	 *
	 * @param tag A component's tag.
	 * @return The canonical component name.
	 */
	const std::string& GetComponentName(zeek::Tag tag) const;

	/**
	 * Get a component name from it's enum value.
	 *
	 * @param val A component's enum value.
	 * @return The canonical component name.
	 */
	const std::string& GetComponentName(EnumValPtr val) const;

	/**
	 * Get a component tag from its name.
	 *
	 * @param name A component's canonical name.
	 * @return The component's tag, or a tag representing an error if
	 * no such component assoicated with the name exists.
	 */
	zeek::Tag GetComponentTag(const std::string& name) const;

	/**
	 * Get a component tag from its enum value.
	 *
	 * @param v A component's enum value.
	 * @return The component's tag, or a tag representing an error if
	 * no such component assoicated with the value exists.
	 */
	zeek::Tag GetComponentTag(Val* v) const;

	/**
	 * Add a component the internal maps used to keep track of it and create
	 * a script-layer ID for the component's enum value.
	 *
	 * @param component A component to track.
	 * @param prefix The script-layer ID associated with the component's enum
	 * value will be a concatenation of this prefix and the component's
	 * canonical name.
	 */
	void RegisterComponent(C* component, const std::string& prefix = "");

	/**
	 * @param name The canonical name of a component.
	 * @return The component associated with the name or a null pointer if no
	 * such component exists.
	 */
	C* Lookup(const std::string& name) const;

	/**
	 * @param name A component tag.
	 * @return The component associated with the tag or a null pointer if no
	 * such component exists.
	 */
	C* Lookup(const zeek::Tag& tag) const;

	/**
	 * @param name A component's enum value.
	 * @return The component associated with the value or a null pointer if no
	 * such component exists.
	 */
	C* Lookup(EnumVal* val) const;

private:
	/** Script layer module in which component tags live. */
	std::string module;

	/** Module-local type of component tags. */
	[[deprecated("Remove in v5.1. Use ComponentManager::tag_enum_type.")]] EnumTypePtr tag_enum_type;

	std::map<std::string, C*> components_by_name;
	std::map<zeek::Tag, C*> components_by_tag;
	std::map<int, C*> components_by_val;
	};

template <class C>
ComponentManager<C>::ComponentManager(const std::string& arg_module, const std::string& local_id)
	: module(arg_module), tag_enum_type(make_intrusive<EnumType>(module + "::" + local_id))
	{
	auto id = zeek::detail::install_ID(local_id.c_str(), module.c_str(), true, true);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
	zeek::detail::add_type(id.get(), tag_enum_type, nullptr);
#pragma GCC diagnostic pop
	zeek::detail::zeekygen_mgr->Identifier(std::move(id));
	}

template <class C> const std::string& ComponentManager<C>::GetModule() const
	{
	return module;
	}

template <class C> std::list<C*> ComponentManager<C>::GetComponents() const
	{
	std::list<C*> rval;
	typename std::map<zeek::Tag, C*>::const_iterator i;

	for ( i = components_by_tag.begin(); i != components_by_tag.end(); ++i )
		rval.push_back(i->second);

	return rval;
	}

template <class C>
const EnumTypePtr& ComponentManager<C>::GetTagType() const
	{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
	return tag_enum_type;
#pragma GCC diagnostic pop
	}

template <class C> const std::string& ComponentManager<C>::GetComponentName(zeek::Tag tag) const
	{
	static const std::string error = "<error>";

	if ( ! tag )
		return error;

	C* c = Lookup(tag);

	if ( c )
		return c->CanonicalName();

	reporter->InternalWarning("requested name of unknown component tag %s", tag.AsString().c_str());
	return error;
	}

template <class C>
const std::string& ComponentManager<C>::GetComponentName(EnumValPtr val) const
	{
	return GetComponentName(zeek::Tag(std::move(val)));
	}

template <class C> zeek::Tag ComponentManager<C>::GetComponentTag(const std::string& name) const
	{
	C* c = Lookup(name);
	return c ? c->Tag() : zeek::Tag();
	}

template <class C> zeek::Tag ComponentManager<C>::GetComponentTag(Val* v) const
	{
	C* c = Lookup(v->AsEnumVal());
	return c ? c->Tag() : zeek::Tag();
	}

template <class C> C* ComponentManager<C>::Lookup(const std::string& name) const
	{
	typename std::map<std::string, C*>::const_iterator i = components_by_name.find(
		util::to_upper(name));
	return i != components_by_name.end() ? i->second : 0;
	}

	template <class C> C* ComponentManager<C>::Lookup(const zeek::Tag& tag) const
	{
	typename std::map<zeek::Tag, C*>::const_iterator i = components_by_tag.find(tag);
	return i != components_by_tag.end() ? i->second : 0;
	}

template <class C> C* ComponentManager<C>::Lookup(EnumVal* val) const
	{
	typename std::map<int, C*>::const_iterator i = components_by_val.find(val->InternalInt());
	return i != components_by_val.end() ? i->second : 0;
	}

template <class C>
void ComponentManager<C>::RegisterComponent(C* component, const std::string& prefix)
	{
	std::string cname = component->CanonicalName();

	if ( Lookup(cname) )
		reporter->FatalError("Component '%s::%s' defined more than once", module.c_str(),
		                     cname.c_str());

	DBG_LOG(DBG_PLUGINS, "Registering component %s (tag %s)", component->Name().c_str(),
	        component->Tag().AsString().c_str());

	// Create a string for the global tag that looks like Module::TagName.
	std::string global_id = module;
	global_id.append("::");
	global_id.append(util::to_upper(cname));

	components_by_name.insert(std::make_pair(cname, component));
	components_by_tag.insert(std::make_pair(component->Tag(), component));
	components_by_val.insert(std::make_pair(component->Tag().AsVal()->InternalInt(), component));

	// Install an identfier for enum value
	std::string id = util::fmt("%s%s", prefix.c_str(), cname.c_str());
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated"
	tag_enum_type->AddName(module, id.c_str(), component->Tag().AsVal()->InternalInt(), true,
	                       nullptr);
#pragma GCC diagnostic pop

	Tag::global_enum_type->AddName(zeek::detail::GLOBAL_MODULE_NAME, global_id.c_str(),
	                               component->Tag().AsVal()->InternalInt(), true, nullptr);
	}

	} // namespace zeek::plugin
