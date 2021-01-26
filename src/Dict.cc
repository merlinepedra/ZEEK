// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/Dict.h"

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <algorithm>
#include <signal.h>
#include <climits>
#include <fstream>

#include "zeek/3rdparty/doctest.h"

#include "zeek/Reporter.h"
#include "zeek/util.h"

namespace zeek {

TEST_SUITE_BEGIN("Dict");

TEST_CASE("dict construction")
	{
	PDict<int> dict;
	CHECK(! dict.IsOrdered());
	CHECK(dict.Length() == 0);

	PDict<int> dict2(ORDERED);
	CHECK(dict2.IsOrdered());
	CHECK(dict2.Length() == 0);
	}

TEST_CASE("dict operation")
	{
	PDict<uint32_t> dict;

	uint32_t val = 10;
	uint32_t key_val = 5;

	detail::HashKey* key = new detail::HashKey(key_val);
	dict.Insert(key, &val);
	CHECK(dict.Length() == 1);

	detail::HashKey* key2 = new detail::HashKey(key_val);
	uint32_t* lookup = dict.Lookup(key2);
	CHECK(*lookup == val);

	dict.Remove(key2);
	CHECK(dict.Length() == 0);
	uint32_t* lookup2 = dict.Lookup(key2);
	CHECK(lookup2 == (uint32_t*)0);
	delete key2;

	CHECK(dict.MaxLength() == 1);
	CHECK(dict.NumCumulativeInserts() == 1);

	dict.Insert(key, &val);
	dict.Remove(key);

	CHECK(dict.MaxLength() == 1);
	CHECK(dict.NumCumulativeInserts() == 2);

	uint32_t val2 = 15;
	uint32_t key_val2 = 25;
	key2 = new detail::HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);
	CHECK(dict.Length() == 2);
	CHECK(dict.NumCumulativeInserts() == 4);

	dict.Clear();
	CHECK(dict.Length() == 0);

	delete key;
	delete key2;
	}

TEST_CASE("dict nthentry")
	{
	PDict<uint32_t> unordered(UNORDERED);
	PDict<uint32_t> ordered(ORDERED);

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* okey = new detail::HashKey(key_val);
	detail::HashKey* ukey = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* okey2 = new detail::HashKey(key_val2);
	detail::HashKey* ukey2 = new detail::HashKey(key_val2);

	unordered.Insert(ukey, &val);
	unordered.Insert(ukey2, &val2);

	ordered.Insert(okey, &val);
	ordered.Insert(okey2, &val2);

	// NthEntry returns null for unordered dicts
	uint32_t* lookup = unordered.NthEntry(0);
	CHECK(lookup == (uint32_t*)0);

	// Ordered dicts are based on order of insertion, nothing about the
	// data itself
	lookup = ordered.NthEntry(0);
	CHECK(*lookup == 15);

	delete okey;
	delete okey2;
	delete ukey;
	delete ukey2;
	}

TEST_CASE("dict iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	detail::HashKey* it_key;
	IterCookie<uint32_t>* it = dict.InitForIteration();
	CHECK(it != nullptr);
	int count = 0;

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		switch ( count )
			{
			case 0:
				// The DictEntry constructor typecasts this down to a uint32_t, so
				// we can't just check the value directly.
				// Explanation: hash_t is 64bit, open-dict only uses 32bit hash to
				// save space for each item (24 bytes aligned). OpenDict has table
				// size of 2^N and only take the lower bits of the hash. (The
				// original hash takes transformation in FibHash() to map into a
				// smaller 2^N range).
				CHECK(it_key->Hash() == (uint32_t)key2->Hash());
				CHECK(*entry == 10);
				break;
			case 1:
				CHECK(it_key->Hash() == (uint32_t)key->Hash());
				CHECK(*entry == 15);
				break;
			default:
				break;
			}
		count++;

		delete it_key;
		}

	CHECK(count == 2);

#pragma GCC diagnostic pop

	delete key;
	delete key2;
	}

TEST_CASE("dict new iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

	int count = 0;

	for ( const auto& entry : dict )
		{
		auto* v = static_cast<uint32_t*>(entry.value);
		uint64_t k = *(uint32_t*) entry.GetKey();

		switch ( count )
			{
			case 0:
				CHECK(k == key_val2);
				CHECK(*v == val2);
				break;
			case 1:
				CHECK(k == key_val);
				CHECK(*v == val);
				break;
			default:
				break;
			}

		count++;
		}

	CHECK(count == 2);

	delete key;
	delete key2;
	}

TEST_CASE("dict robust iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	uint32_t val3 = 20;
	uint32_t key_val3 = 35;
	detail::HashKey* key3 = new detail::HashKey(key_val3);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	detail::HashKey* it_key;
	IterCookie<uint32_t>* it = dict.InitForIteration();
	CHECK(it != nullptr);
	dict.MakeRobustCookie(it);

	int count = 0;

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		switch ( count )
			{
			case 0:
				CHECK(it_key->Hash() == (uint32_t)key2->Hash());
				CHECK(*entry == 10);
				dict.Insert(key3, &val3);
				break;
			case 1:
				CHECK(it_key->Hash() == (uint32_t)key->Hash());
				CHECK(*entry == 15);
				break;
			case 2:
				CHECK(it_key->Hash() == (uint32_t)key3->Hash());
				CHECK(*entry == 20);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}

		count++;
		delete it_key;
		}

	CHECK(count == 3);

	IterCookie<uint32_t>* it2 = dict.InitForIteration();
	CHECK(it2 != nullptr);
 	dict.MakeRobustCookie(it2);

	count = 0;
	while ( uint32_t* entry = dict.NextEntry(it_key, it2) )
		{
		switch ( count )
			{
			case 0:
				CHECK(it_key->Hash() == (uint32_t)key2->Hash());
				CHECK(*entry == 10);
				dict.Remove(key3);
				break;
			case 1:
				CHECK(it_key->Hash() == (uint32_t)key->Hash());
				CHECK(*entry == 15);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}

		count++;
		delete it_key;
		}

	CHECK(count == 2);

#pragma GCC diagnostic pop

	delete key;
	delete key2;
	delete key3;
	}

TEST_CASE("dict new robust iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	uint32_t val3 = 20;
	uint32_t key_val3 = 35;
	detail::HashKey* key3 = new detail::HashKey(key_val3);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

	{
	int count = 0;
	auto it = dict.begin_robust();

	for ( ; it != dict.end_robust(); ++it )
		{
		auto* v = it->value;
		uint64_t k = *(uint32_t*) it->GetKey();

		switch ( count )
			{
			case 0:
				CHECK(k == key_val2);
				CHECK(*v == val2);
				dict.Insert(key3, &val3);
				break;
			case 1:
				CHECK(k == key_val);
				CHECK(*v == val);
				break;
			case 2:
				CHECK(k == key_val3);
				CHECK(*v == val3);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}
		count++;
		}

	CHECK(count == 3);
	}

	{
	int count = 0;
	auto it = dict.begin_robust();

	for ( ; it != dict.end_robust(); ++it )
		{
		auto* v = it->value;
		uint64_t k = *(uint32_t*) it->GetKey();

		switch ( count )
			{
			case 0:
				CHECK(k == key_val2);
				CHECK(*v == val2);
				dict.Insert(key3, &val3);
				dict.Remove(key3);
				break;
			case 1:
				CHECK(k == key_val);
				CHECK(*v == val);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}
		count++;
		}

	CHECK(count == 2);
	}

	delete key;
	delete key2;
	delete key3;
	}

TEST_CASE("dict iterator invalidation")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	auto key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	auto key2 = new detail::HashKey(key_val2);

	uint32_t val3 = 42;
	uint32_t key_val3 = 37;
	auto key3 = new detail::HashKey(key_val3);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

	detail::HashKey* it_key;
	bool iterators_invalidated = false;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	auto* it = dict.InitForIteration();
	CHECK(it != nullptr);

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		iterators_invalidated = false;
		dict.Remove(key3, &iterators_invalidated);
		// Key doesn't exist, nothing to remove, iteration not invalidated.
		CHECK(!iterators_invalidated);

		iterators_invalidated = false;
		dict.Insert(key, &val2, &iterators_invalidated);
		// Key exists, value gets overwritten, iteration not invalidated.
		CHECK(!iterators_invalidated);

		iterators_invalidated = false;
		dict.Remove(key2, &iterators_invalidated);
		// Key exists, gets removed, iteration is invalidated.
		CHECK(iterators_invalidated);

		delete it_key;
		dict.StopIteration(it);
		break;
		}

	it = dict.InitForIteration();
	CHECK(it != nullptr);

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		iterators_invalidated = false;
		dict.Insert(key3, &val3, &iterators_invalidated);
		// Key doesn't exist, gets inserted, iteration is invalidated.
		CHECK(iterators_invalidated);

		delete it_key;
		dict.StopIteration(it);
		break;
		}
#pragma GCC diagnostic pop

	CHECK(dict.Length() == 2);
	CHECK(*static_cast<uint32_t*>(dict.Lookup(key)) == val2);
	CHECK(*static_cast<uint32_t*>(dict.Lookup(key3)) == val3);
	CHECK(static_cast<uint32_t*>(dict.Lookup(key2)) == nullptr);

	delete key;
	delete key2;
	delete key3;
	}

TEST_SUITE_END();

void generic_delete_func(void* v)
	{
	free(v);
	}

} // namespace zeek
