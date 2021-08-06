// See the file "COPYING" in the main distribution directory for copyright.

// Auxiliary information associated with statements to aid script
// optimization.

#pragma once

namespace zeek::detail {

class StmtOptInfo {
public:
	int stmt_num = -1;	// -1 = not assigned yet
	int block_level = -1;
};

} // namespace zeek::detail
