// See the file "COPYING" in the main distribution directory for copyright.

// Classes for tracking constants that require run-time construction.

#include "zeek/Val.h"

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

	virtual void AddInit(const ValPtr& v) = 0;

	void GenInitInfo(std::vector<std::string>& inits) const;
	void GenInit(std::vector<std::string>& inits);

	std::string GenInitCall() const;

protected:
	virtual int NumVecs() const = 0;
	virtual std::string NthInitVecType(int init_vec) const = 0;

	std::string NthInitVec(int init_vec) const;
	std::string InitFuncName() const;

	virtual void DoGenInitSetup(int which_init, std::vector<std::string>& inits) const = 0;
	virtual std::string DoGenInitCore() const = 0;

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

	void AddInit(const ValPtr& v) override;

private:
	int NumVecs() const override { return 2; }
	std::string NthInitVecType(int init_vec) const override;

	void DoGenInitSetup(int which_init, std::vector<std::string>& inits) const override;
	std::string DoGenInitCore() const override;

	std::vector<int> lens;
	std::vector<std::string> reps;
	};

	} // zeek::detail
