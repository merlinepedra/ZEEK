// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zeek/script_opt/CPP/Compile.h"

namespace zeek::detail
	{

using namespace std;

void CPPCompile::StartBlock()
	{
	++block_level;
	Emit("{");
	}

void CPPCompile::EndBlock(bool needs_semi)
	{
	Emit("}%s", needs_semi ? ";" : "");
	--block_level;
	}

void CPPCompile::Indent() const
	{
	for ( auto i = 0; i < block_level; ++i )
		fprintf(write_file, "%s", "\t");
	}

	} // zeek::detail
