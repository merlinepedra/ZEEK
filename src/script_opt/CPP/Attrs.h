// See the file "COPYING" in the main distribution directory for copyright.

// Definitions associated with type attributes.

#pragma once

namespace zeek::detail
	{

	enum AttrExprType
		{
		AE_NONE,
		AE_CONST,
		AE_NAME,
		AE_RECORD,
		AE_CALL,
		};

	} // zeek::detail
