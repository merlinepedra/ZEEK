
global test_file_analysis_source: string = "" &redef;

global test_file_actions: set[FileAnalysis::ActionArgs];

global test_get_file_name: function(f: fa_file): string =
	function(f: fa_file): string { return ""; } &redef;

global test_print_file_data_events: bool = F &redef;

event file_chunk(f: fa_file, data: string, off: count)
	{
	if ( test_print_file_data_events )
		print "file_chunk", f$id, |data|, off, data;
	}

event file_stream(f: fa_file, data: string)
	{
	if ( test_print_file_data_events )
		print "file_stream", f$id, |data|, data;
	}

event file_new(f: fa_file)
	{
	print "FILE_NEW";

	print f$id, f$seen_bytes, f$missing_bytes;

	if ( test_file_analysis_source == "" ||
	     f$source == test_file_analysis_source )
		{
		for ( act in test_file_actions )
			FileAnalysis::add_action(f, act);

		local filename: string = test_get_file_name(f);
		if ( filename != "" )
			FileAnalysis::add_action(f, [$act=FileAnalysis::ACTION_EXTRACT,
			                             $extract_filename=filename]);
		FileAnalysis::add_action(f, [$act=FileAnalysis::ACTION_DATA_EVENT,
		                             $chunk_event=file_chunk,
		                             $stream_event=file_stream]);
		}

	if ( f?$bof_buffer )
		{
		print "FILE_BOF_BUFFER";
		print f$bof_buffer[0:10];
		}

	if ( f?$file_type || f?$mime_type )
		print "FILE_TYPE";
	# not actually printing the values due to libmagic variances
	if ( f?$file_type )
		{
		print "file type is set";
		f$file_type = "set";
		}
	if ( f?$mime_type )
		{
		print "mime type is set";
		f$mime_type = "set";
		}
	}

event file_over_new_connection(f: fa_file)
	{
	print "FILE_OVER_NEW_CONNECTION";
	}

event file_timeout(f: fa_file)
	{
	print "FILE_TIMEOUT";
	}

event file_gap(f: fa_file)
	{
	print "FILE_GAP";
	}

event file_state_remove(f: fa_file)
	{
	print "FILE_STATE_REMOVE";
	print f$id, f$seen_bytes, f$missing_bytes;
	if ( f?$conns )
		for ( cid in f$conns )
			print cid;

	if ( f?$total_bytes )
		print "total bytes: " + fmt("%s", f$total_bytes);
	if ( f?$source )
		print "source: " + f$source;

	if ( ! f?$info ) return;

	if ( f$info?$md5 )
		print fmt("MD5: %s", f$info$md5);
	if ( f$info?$sha1 )
		print fmt("SHA1: %s", f$info$sha1);
	if ( f$info?$sha256 )
		print fmt("SHA256: %s", f$info$sha256);
	}

event bro_init()
	{
	add test_file_actions[[$act=FileAnalysis::ACTION_MD5]];
	add test_file_actions[[$act=FileAnalysis::ACTION_SHA1]];
	add test_file_actions[[$act=FileAnalysis::ACTION_SHA256]];
	}
