#include <benchmark/benchmark.h>
#include <urcu/uatomic.h>
#if defined(RCU_MEMB)
#include <urcu.h>
#elif defined(RCU_BP)
#include <urcu-bp.h>
#else
#error None of RCU_* defined
#endif

#if !defined(_LGPL_SOURCE)
#error URCU is very slow w/o _LGPL_SOURCE
#endif

static void BM_userspace_rcu(benchmark::State& state)
{
    rcu_init();

    unsigned atomic = 0;
    while (state.KeepRunning())
    {
        rcu_read_lock();
        ++atomic;
        rcu_read_unlock();
    }
}
BENCHMARK(BM_userspace_rcu);

static void BM_userspace_rcu_uatomic_add(benchmark::State& state)
{
    unsigned atomic = 0;
    while (state.KeepRunning())
    {
        uatomic_add(&atomic, 1);
    }
}
BENCHMARK(BM_userspace_rcu_uatomic_add);

static void BM_userspace_rcu_uatomic_add_return(benchmark::State& state)
{
    unsigned atomic = 0;
    while (state.KeepRunning())
    {
        uatomic_add_return(&atomic, 1);
    }
}
BENCHMARK(BM_userspace_rcu_uatomic_add_return);
