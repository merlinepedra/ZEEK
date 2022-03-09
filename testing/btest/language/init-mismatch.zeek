# @TEST-EXEC-FAIL: zeek -b %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff .stderr

global a: count = [3, 5];
global b [4, 6];

print a, b;
