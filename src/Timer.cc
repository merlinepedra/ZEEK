// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "util.h"
#include "Timer.h"
#include "Desc.h"
#include "Net.h"
#include "NetVar.h"
#include "broker/Manager.h"
#include "iosource/Manager.h"
#include "iosource/PktSrc.h"

namespace zeek::detail {

// Names of timers in same order than in TimerType.
const char* TimerNames[] = {
	"BackdoorTimer",
	"BreakpointTimer",
	"ConnectionDeleteTimer",
	"ConnectionExpireTimer",
	"ConnectionInactivityTimer",
	"ConnectionStatusUpdateTimer",
	"ConnTupleWeirdTimer",
	"DNSExpireTimer",
	"FileAnalysisInactivityTimer",
	"FlowWeirdTimer",
	"FragTimer",
	"InterconnTimer",
	"IPTunnelInactivityTimer",
	"NetbiosExpireTimer",
	"NetWeirdTimer",
	"NetworkTimer",
	"NTPExpireTimer",
	"ProfileTimer",
	"RotateTimer",
	"RemoveConnection",
	"RPCExpireTimer",
	"ScheduleTimer",
	"TableValTimer",
	"TCPConnectionAttemptTimer",
	"TCPConnectionDeleteTimer",
	"TCPConnectionExpireTimer",
	"TCPConnectionPartialClose",
	"TCPConnectionResetTimer",
	"TriggerTimer",
	"ParentProcessIDCheck",
	"TimerMgrExpireTimer",
	"ThreadHeartbeat",
};

const char* timer_type_to_string(TimerType type)
	{
	return TimerNames[type];
	}

void Timer::Describe(ODesc* d) const
	{
	d->Add(TimerNames[type]);
	d->Add(" at " );
	d->Add(Time());
	}

unsigned int TimerMgr::current_timers[NUM_TIMER_TYPES];

TimerMgr::TimerMgr()
	{
	t = 0.0;
	num_expired = 0;
	last_advance = last_timestamp = 0;

	q = new PriorityQueue();

	if ( iosource_mgr )
		iosource_mgr->Register(this, true);
	}

TimerMgr::~TimerMgr()
	{
	delete q;
	}

int TimerMgr::Advance(double arg_t, int max_expire)
	{
	DBG_LOG(zeek::DBG_TM, "advancing timer mgr to %.6f", arg_t);

	t = arg_t;
	last_timestamp = 0;
	num_expired = 0;
	last_advance = timer_mgr->Time();
	broker_mgr->AdvanceTime(arg_t);

	return DoAdvance(t, max_expire);
	}

void TimerMgr::Process()
	{
	// If we don't have a source, or the source is closed, or we're reading live (which includes
	// pseudo-realtime), advance the timer here to the current time since otherwise it won't
	// move forward and the timers won't fire correctly.
	iosource::PktSrc* pkt_src = iosource_mgr->GetPktSrc();
	if ( ! pkt_src || ! pkt_src->IsOpen() || reading_live || net_is_processing_suspended() )
		net_update_time(current_time());

	// Just advance the timer manager based on the current network time. This won't actually
	// change the time, but will dispatch any timers that need dispatching.
	current_dispatched += Advance(network_time, max_timer_expires - current_dispatched);
	}

void TimerMgr::InitPostScript()
	{
	if ( iosource_mgr )
		iosource_mgr->Register(this, true);
	}

void TimerMgr::Add(Timer* timer)
	{
	DBG_LOG(zeek::DBG_TM, "Adding timer %s (%p) at %.6f",
	        timer_type_to_string(timer->Type()), timer, timer->Time());

	if ( timer->Time() - ::network_time == 5.0 )
		q_5s.push_back(timer);
	else if ( timer->Time() - ::network_time == 6.0 )
		q_6s.push_back(timer);
	else
		// Add the timer even if it's already expired - that way, if
		// multiple already-added timers are added, they'll still
		// execute in sorted order.
		if ( ! q->Add(timer) )
			zeek::reporter->InternalError("out of memory");

	cumulative_num++;
	if ( Size() > peak_size )
		peak_size = Size();

	++current_timers[timer->Type()];
	}

void TimerMgr::Expire()
	{
	Timer* timer;
	while ( (timer = Remove()) )
		{
		DBG_LOG(zeek::DBG_TM, "Dispatching timer %s (%p)",
		        timer_type_to_string(timer->Type()), timer);
		timer->Dispatch(t, true);
		--current_timers[timer->Type()];
		delete timer;
		}
	}

int TimerMgr::DoAdvance(double new_t, int max_expire)
	{
	auto res = Top();
	Timer* timer = res.second;

	for ( num_expired = 0; (num_expired < max_expire || max_expire == 0) &&
		      timer && timer->Time() <= new_t; ++num_expired )
		{
		last_timestamp = timer->Time();
		--current_timers[timer->Type()];

		// Remove it before dispatching, since the dispatch
		// can otherwise delete it, and then we won't know
		// whether we should delete it too.
		(void) Remove();

		DBG_LOG(zeek::DBG_TM, "Dispatching timer %s (%p)",
		        timer_type_to_string(timer->Type()), timer);
		timer->Dispatch(new_t, false);
		delete timer;

		res = Top();
		timer = res.second;
		}

	return num_expired;
	}

void TimerMgr::Remove(Timer* timer)
	{
	std::deque<Timer*>::iterator it;

	if ( ! q_5s.empty() )
		{
		it = std::find(q_5s.begin(), q_5s.end(), timer);
		if ( it != q_5s.end() )
			{
			q_5s.erase(it);
			--current_timers[timer->Type()];
			delete timer;
			return;
			}
		}

	if ( ! q_6s.empty() )
		{
		it = std::find(q_6s.begin(), q_6s.end(), timer);
		if ( it != q_6s.end() )
			{
			q_6s.erase(it);
			--current_timers[timer->Type()];
			delete timer;
			return;
			}
		}

	if ( ! q->Remove(timer) )
		zeek::reporter->InternalError("asked to remove a missing timer");

	--current_timers[timer->Type()];

	delete timer;
	}

double TimerMgr::GetNextTimeout()
	{
	const auto& [ index, top ] = Top();
	if ( top )
		return std::max(0.0, top->Time() - ::network_time);

	return -1;
	}

Timer* TimerMgr::Remove()
	{
	const auto& [ index, top ] = Top();

	if ( index == QueueIndex::Q5 )
		q_5s.pop_front();
	else if ( index == QueueIndex::Q6 )
		q_6s.pop_front();
	else if ( index == QueueIndex::PQ )
		q->Remove();

	return top;
	}

std::pair<TimerMgr::QueueIndex, Timer*> TimerMgr::Top()
	{
	Timer* top = nullptr;
	QueueIndex index = QueueIndex::NONE;

	if ( ! q_5s.empty() )
		{
		top = q_5s.front();
		index = QueueIndex::Q5;
		}

	if ( ! q_6s.empty() )
		{
		Timer* t = q_6s.front();
		if ( ! top || t->Time() < top->Time() )
			{
			top = t;
			index = QueueIndex::Q6;
			}
		}

	if ( q->Size() > 0 )
		{
		Timer* t = static_cast<Timer*>(q->Top());
		if ( ! top || t->Time() < top->Time() )
			{
			index = QueueIndex::PQ;
			top = t;
			}
		}

	return { index, top };
	}

} // namespace zeek::detail
