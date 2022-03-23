##! The Management event API of data cluster nodes. The API consists of event
##! pairs, like elsewhere in the Management, Supervisor, or Control frameworks.

@load policy/frameworks/management/types

module Management::Node::API;

export {
	global get_id_value_request: event(reqid: string, id: string);
	global get_id_value_response: event(reqid: string, result: Management::Result);
}
