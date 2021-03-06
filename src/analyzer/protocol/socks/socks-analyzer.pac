
%header{
zeek::StringValPtr array_to_string(vector<uint8> *a);
%}

%code{
zeek::StringValPtr array_to_string(vector<uint8> *a)
	{
	int len = a->size();
	auto tmp = std::make_unique<char[]>(len);
	char *s = tmp.get();
	for ( vector<uint8>::iterator i = a->begin(); i != a->end(); *s++ = *i++ );

	while ( len > 0 && tmp[len-1] == '\0' )
		--len;

	return zeek::make_intrusive<zeek::StringVal>(len, tmp.get());
	}
%}

refine connection SOCKS_Conn += {

	function socks4_request(request: SOCKS4_Request): bool
		%{
		if ( socks_request )
			{
			static auto socks_address = zeek::id::find_type<zeek::RecordType>("SOCKS::Address");
			auto sa = zeek::make_intrusive<zeek::RecordVal>(socks_address);
			sa->Assign(0, zeek::make_intrusive<zeek::AddrVal>(htonl(${request.addr})));

			if ( ${request.v4a} )
				sa->Assign(1, array_to_string(${request.name}));

			zeek::BifEvent::enqueue_socks_request(zeek_analyzer(),
			                                zeek_analyzer()->Conn(),
			                                4,
			                                ${request.command},
			                                std::move(sa),
			                                zeek::val_mgr->Port(${request.port}, TRANSPORT_TCP),
			                                array_to_string(${request.user}));
			}

		static_cast<zeek::analyzer::socks::SOCKS_Analyzer*>(zeek_analyzer())->EndpointDone(true);

		return true;
		%}

	function socks4_reply(reply: SOCKS4_Reply): bool
		%{
		if ( socks_reply )
			{
			static auto socks_address = zeek::id::find_type<zeek::RecordType>("SOCKS::Address");
			auto sa = zeek::make_intrusive<zeek::RecordVal>(socks_address);
			sa->Assign(0, zeek::make_intrusive<zeek::AddrVal>(htonl(${reply.addr})));

			zeek::BifEvent::enqueue_socks_reply(zeek_analyzer(),
			                              zeek_analyzer()->Conn(),
			                              4,
			                              ${reply.status},
			                              std::move(sa),
			                              zeek::val_mgr->Port(${reply.port}, TRANSPORT_TCP));
			}

		zeek_analyzer()->AnalyzerConfirmation();
		static_cast<zeek::analyzer::socks::SOCKS_Analyzer*>(zeek_analyzer())->EndpointDone(false);
		return true;
		%}

	function socks5_request(request: SOCKS5_Request): bool
		%{
		if ( ${request.reserved} != 0 )
			{
			zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("invalid value in reserved field: %d", ${request.reserved}));
			zeek_analyzer()->SetSkip(true);
			return false;
			}

		if ( (${request.command} == 0) || (${request.command} > 3) )
			{
			zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("undefined value in command field: %d", ${request.command}));
			zeek_analyzer()->SetSkip(true);
			return false;
			}

		static auto socks_address = zeek::id::find_type<zeek::RecordType>("SOCKS::Address");
		auto sa = zeek::make_intrusive<zeek::RecordVal>(socks_address);

		// This is dumb and there must be a better way (checking for presence of a field)...
		switch ( ${request.remote_name.addr_type} )
			{
			case 1:
				sa->Assign(0, zeek::make_intrusive<zeek::AddrVal>(htonl(${request.remote_name.ipv4})));
				break;

			case 3:
				sa->Assign(1, zeek::make_intrusive<zeek::StringVal>(${request.remote_name.domain_name.name}.length(),
				                         (const char*) ${request.remote_name.domain_name.name}.data()));
				break;

			case 4:
				sa->Assign(0, zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv6, (const uint32_t*) ${request.remote_name.ipv6}, zeek::IPAddr::Network)));
				break;

			default:
				zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("invalid SOCKSv5 addr type: %d", ${request.remote_name.addr_type}));
				return false;
			}

		if ( socks_request )
			zeek::BifEvent::enqueue_socks_request(zeek_analyzer(),
			                                zeek_analyzer()->Conn(),
			                                5,
			                                ${request.command},
			                                std::move(sa),
			                                zeek::val_mgr->Port(${request.port}, TRANSPORT_TCP),
			                                zeek::val_mgr->EmptyString());

		static_cast<zeek::analyzer::socks::SOCKS_Analyzer*>(zeek_analyzer())->EndpointDone(true);

		return true;
		%}

	function socks5_reply(reply: SOCKS5_Reply): bool
		%{
		static auto socks_address = zeek::id::find_type<zeek::RecordType>("SOCKS::Address");
		auto sa = zeek::make_intrusive<zeek::RecordVal>(socks_address);

		// This is dumb and there must be a better way (checking for presence of a field)...
		switch ( ${reply.bound.addr_type} )
			{
			case 1:
				sa->Assign(0, zeek::make_intrusive<zeek::AddrVal>(htonl(${reply.bound.ipv4})));
				break;

			case 3:
				sa->Assign(1, zeek::make_intrusive<zeek::StringVal>(${reply.bound.domain_name.name}.length(),
				                         (const char*) ${reply.bound.domain_name.name}.data()));
				break;

			case 4:
				sa->Assign(0, zeek::make_intrusive<zeek::AddrVal>(zeek::IPAddr(IPv6, (const uint32_t*) ${reply.bound.ipv6}, zeek::IPAddr::Network)));
				break;

			default:
				zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("invalid SOCKSv5 addr type: %d", ${reply.bound.addr_type}));
				return false;
			}

		if ( socks_reply )
			zeek::BifEvent::enqueue_socks_reply(zeek_analyzer(),
			                              zeek_analyzer()->Conn(),
			                              5,
			                              ${reply.reply},
			                              std::move(sa),
			                              zeek::val_mgr->Port(${reply.port}, TRANSPORT_TCP));

		zeek_analyzer()->AnalyzerConfirmation();
		static_cast<zeek::analyzer::socks::SOCKS_Analyzer*>(zeek_analyzer())->EndpointDone(false);
		return true;
		%}

	function socks5_auth_request_userpass(request: SOCKS5_Auth_Request_UserPass_v1): bool
		%{
		if ( ! socks_login_userpass_request )
			return true;

		auto user = zeek::make_intrusive<zeek::StringVal>(${request.username}.length(), (const char*) ${request.username}.begin());
		auto pass = zeek::make_intrusive<zeek::StringVal>(${request.password}.length(), (const char*) ${request.password}.begin());

		zeek::BifEvent::enqueue_socks_login_userpass_request(zeek_analyzer(),
		                                               zeek_analyzer()->Conn(),
		                                               std::move(user), std::move(pass));
		return true;
		%}

	function socks5_unsupported_authentication_method(auth_method: uint8): bool
		%{
		zeek_analyzer()->Weird("socks5_unsupported_authentication_method", zeek::util::fmt("%d", auth_method));
		return true;
		%}

	function socks5_unsupported_authentication_version(auth_method: uint8, version: uint8): bool
		%{
		zeek_analyzer()->Weird("socks5_unsupported_authentication", zeek::util::fmt("method %d, version %d", auth_method, version));
		return true;
		%}

	function socks5_auth_reply_userpass(reply: SOCKS5_Auth_Reply_UserPass_v1): bool
		%{
		if ( socks_login_userpass_reply )
			zeek::BifEvent::enqueue_socks_login_userpass_reply(zeek_analyzer(),
			                                             zeek_analyzer()->Conn(),
			                                             ${reply.code});
		return true;
		%}

	function version_error(version: uint8): bool
		%{
		zeek_analyzer()->AnalyzerViolation(zeek::util::fmt("unsupported/unknown SOCKS version %d", version));
		return true;
		%}


};

refine typeattr SOCKS_Version_Error += &let {
	proc: bool = $context.connection.version_error(version);
};

refine typeattr SOCKS4_Request += &let {
	proc: bool = $context.connection.socks4_request(this);
};

refine typeattr SOCKS4_Reply += &let {
	proc: bool = $context.connection.socks4_reply(this);
};

refine typeattr SOCKS5_Request += &let {
	proc: bool = $context.connection.socks5_request(this);
};

refine typeattr SOCKS5_Reply += &let {
	proc: bool = $context.connection.socks5_reply(this);
};

refine typeattr SOCKS5_Auth_Negotiation_Reply += &let {
};

refine typeattr SOCKS5_Auth_Request_UserPass_v1 += &let {
	proc: bool = $context.connection.socks5_auth_request_userpass(this);
};

refine typeattr SOCKS5_Auth_Reply_UserPass_v1 += &let {
	proc: bool = $context.connection.socks5_auth_reply_userpass(this);
};

refine typeattr SOCKS5_Unsupported_Authentication_Method += &let {
	proc: bool = $context.connection.socks5_unsupported_authentication_method($context.connection.v5_auth_method());
};

refine typeattr SOCKS5_Unsupported_Authentication_Version += &let {
	proc: bool = $context.connection.socks5_unsupported_authentication_version($context.connection.v5_auth_method(), version);
};
