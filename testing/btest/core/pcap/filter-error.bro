# @TEST-EXEC-FAIL: bro -r $TRACES/workshop_2011_browse.trace -f "kaputt" >>output 2>&1
# @TEST-EXEC-FAIL: test -e conn.log
# @TEST-EXEC: echo ---- >>output
# @TEST-EXEC: bro -r $TRACES/workshop_2011_browse.trace  %INPUT >>output 2>&1
# @TEST-EXEC: test -e conn.log
# @TEST-EXEC: btest-diff output

redef enum PcapFilterID += { A };

event bro_init()
	{
	if ( ! precompile_pcap_filter(A, "kaputt, too") )
		print "error", pcap_error();
	}


