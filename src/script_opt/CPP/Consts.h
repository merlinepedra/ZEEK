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

	std::vector<std::string> GenInitInfo() const;
	std::vector<std::string> GenInit();

protected:
	virtual int NumVecs() const = 0;
	virtual void DoGenInitSetup(int which_init, std::vector<std::string>& inits) const = 0;
	virtual std::string DoGenInitCore() const = 0;

	std::string NthInitVec(int init_vec) const;

	// Tag used to distinguish a particular set of constants.
	std::string tag;

	// C++ type associated with a single instance of these constants.
	std::string type;

	// C++ name for this set of constants.
	std::string base_name;

	// Whether we've generated the initializations for this set of
	// constants.  We track this to make sure no constants are
	// subsequently added.
	bool did_init = false;
	};

class CPP_StringConsts : public CPP_Consts
	{
public:
	CPP_StringConsts() : CPP_Consts("str", "StringValPtr") { }

	int Size() const override { return static_cast<int>(reps.size()); }

private:
	int NumVecs() const override { return 2; }
	void DoGenInitSetup(int which_init, std::vector<std::string>& inits) const override;
	std::string DoGenInitCore() const override;

	std::vector<int> lens;
	std::vector<std::string> reps;
	};

	} // zeek::detail
