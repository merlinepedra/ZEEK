// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Tag.h"

#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/Scope.h"
#include "zeek/module_util.h"
#include "zeek/zeekygen/Manager.h"

namespace zeek
	{

const Tag Tag::Error;
EnumTypePtr Tag::global_enum_type;

Tag::Tag(type_t arg_type, subtype_t arg_subtype) : type(arg_type), subtype(arg_subtype)
	{
	assert(arg_type > 0);

	int64_t i = (int64_t)(type) | ((int64_t)subtype << 31);
	val = Tag::global_enum_type->GetEnumVal(i);
	}

Tag::Tag(EnumValPtr arg_val)
	{
	assert(arg_val);

	val = std::move(arg_val);

	int64_t i = val->InternalInt();
	type = i & 0xffffffff;
	subtype = (i >> 31) & 0xffffffff;
	}

Tag::Tag(const Tag& other)
	{
	type = other.type;
	subtype = other.subtype;
	val = other.val;
	}

Tag::Tag()
	{
	type = 0;
	subtype = 0;
	val = nullptr;
	}

Tag::~Tag() = default;

Tag& Tag::operator=(const Tag& other)
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		val = other.val;
		}

	return *this;
	}

Tag& Tag::operator=(const Tag&& other) noexcept
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		val = std::move(other.val);
		}

	return *this;
	}

const EnumValPtr& Tag::AsVal() const
	{
	// TODO: this probably isn't valid, and we should just return the null val
	// if it's null.
	// TODO: should we check for a valid etype here or just let the assert fail?
	if ( ! val )
		{
		assert(type == 0 && subtype == 0 && Tag::global_enum_type != nullptr);
		val = Tag::global_enum_type->GetEnumVal(0);
		}

	return val;
	}

std::string Tag::AsString() const
	{
	return util::fmt("%" PRIu32 "/%" PRIu32, type, subtype);
	}

void Tag::InitializeGlobalEnumType()
	{
	std::string global_module = zeek::detail::GLOBAL_MODULE_NAME;
	global_module.append("::Tag");

	global_enum_type = make_intrusive<EnumType>(global_module);
	auto id = zeek::detail::install_ID("Tag", zeek::detail::GLOBAL_MODULE_NAME, true, true);
	zeek::detail::add_type(id.get(), global_enum_type, nullptr);
	zeek::detail::zeekygen_mgr->Identifier(std::move(id));
	}

	} // namespace zeek
