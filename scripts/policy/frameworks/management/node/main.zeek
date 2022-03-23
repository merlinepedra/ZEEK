##! This module provides Management framework functionality that needs to be
##! present in every data cluster node to allow Management agents to interact
##! with the data cluster nodes they manage.

@load policy/frameworks/management/agent/config
@load policy/frameworks/management/log

@load ./config

module Management::Node;

# Tag our logs correctly
redef Management::Log::role = Management::NODE;

event zeek_init()
	{
	local epi = Management::Agent::endpoint_info();

	Broker::peer(epi$network$address, epi$network$bound_port, Management::connect_retry);
	Broker::subscribe(node_topic);

	# Response events automatically sent to the Management agent.
	local events: vector of any = [
	    ];

	for ( i in events )
		Broker::auto_publish(node_topic, events[i]);
	}
