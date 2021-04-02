// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Desc.h"
#include "zeek/script_opt/CPPTracker.h"
#include "zeek/script_opt/CPPUtil.h"
#include "zeek/script_opt/ProfileFunc.h"


namespace zeek::detail {

template<class T1, class T2>
void CPPTracker<T1, T2>::AddKey(T2 key, hash_type h)
	{
	if ( HasKey(key) )
		return;

	if ( h == 0 )
		h = Hash(key);

	if ( map2.count(h) == 0 )
		{
		int index;
		if ( mapper && mapper->count(h) > 0 )
			{
			const auto& pair = (*mapper)[h];
			index = pair.index;
			scope2[h] = Fmt(pair.scope);
			inherited.insert(h);
			}
		else
			{
			index = num_non_inherited++;
			keys.push_back(key);
			}

		map2[h] = index;
		reps[h] = key.get();
		}

	ASSERT(h != 0);	// check for hash botches

	map[key.get()] = h;
	}

template<class T1, class T2>
std::string CPPTracker<T1, T2>::KeyName(T1 key)
	{
	ASSERT(HasKey(key));

	auto hash = map[key];
	ASSERT(hash != 0);

	auto index = map2[hash];

	std::string scope;
	if ( IsInherited(hash) )
		scope = scope_prefix(scope2[hash]);

	return scope + std::string(base_name) + "_" + Fmt(index) + "__CPP";
	}

template<class T1, class T2>
void CPPTracker<T1, T2>::LogIfNew(T2 key, int scope, FILE* log_file)
	{
	if ( IsInherited(key) )
		return;

	auto hash = map[key.get()];
	auto index = map2[hash];

	fprintf(log_file, "hash\n%llu %d %d\n", hash, index, scope);
	}

template<class T1, class T2>
hash_type CPPTracker<T1, T2>::Hash(T2 key) const
	{
	ODesc d;
	d.SetDeterminism(true);
	key->Describe(&d);
	std::string desc = d.Description();
	auto h = std::hash<std::string>{}(base_name + desc);
	return hash_type(h);
	}


// Instantiate the templates we'll need.
template class CPPTracker<const Type*, TypePtr>;
template class CPPTracker<const Attributes*, AttributesPtr>;
template class CPPTracker<const Expr*, ExprPtr>;

} // zeek::detail
