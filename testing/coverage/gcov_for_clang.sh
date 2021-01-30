# This script is required because the --gcov-tool argument for lcov only accepts a single value. If you try
# to pass "llvm-cov gcov" to it, lcov will complain about the arguments being wrong. This helper script gets
# around that.

#!/bin/bash
exec llvm-cov gcov "$@"
