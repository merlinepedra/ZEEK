// See the file "COPYING" in the main distribution directory for copyright.

// Classes for tracking constants that require run-time construction.

#pragma once

namespace zeek::detail
	{

class CPP_Consts
	{
public:
	CPP_Consts(std::string _tag, std::string _type)
		: tag(std::move(_tag)), type(std::move(_type))
		{
		base_name = std::string("CPP__") + tag + "const__";
		}

	virtual ~CPP_Consts() { }

	std::string NextName() const;
	virtual int Size() const = 0;

	std::vector<std::string> GenInitInfo();
	std::vector<std::string> GenInit() const;

protected:
	virtual void DoGenInitInfo(std::vector<std::string>& inits) const = 0;
	virtual std::string DoGenInit() const = 0;

	// Tag used to distinguish a particular set of constants.
	std::string tag;

	// C++ type associated with a single instance of these constants.
	std::string type;

	// C++ name for this set of constants.
	std::string base_name;

	// Whether we've generated the initialization information for
	// this set of constants.  We track this to make sure no constants
	// are subsequently added.
	bool did_init_info = false;
	};

class CPP_StringConsts : public CPP_Consts
	{
public:
	CPP_StringConsts() : CPP_Consts("str", "StringValPtr") { }

	int Size() const override { return static_cast<int>(reps.size()); }

private:
	void DoGenInitInfo(std::vector<std::string>& inits) const override;
	std::string DoGenInit() const override;

	std::vector<int> lens;
	std::vector<std::string> reps;
	};

	} // zeek::detail
