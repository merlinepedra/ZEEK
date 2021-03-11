# @TEST-EXEC: zeek -b %INPUT >output
# @TEST-EXEC: btest-diff output

module rec_ref_test;

type State: record {
	host: string &default="NOT SET";
};

global session: State;
global s: State;

event zeek_init()
	{
	s = session;
	s$host = "XXX";
	print s$host, session$host;
	}
