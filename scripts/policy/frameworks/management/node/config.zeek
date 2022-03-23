##! Configuration settings for data nodes controlled by the Management framework.

module Management::Node;

export {
	## The nodes' Broker topic. Data cluster nodes automatically subscribe
	## to it, to receive request events from the Management framework.
	const node_topic = "zeek/management/node" &redef;
}
