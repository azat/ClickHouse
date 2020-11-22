#include <benchmark/benchmark.h>
#include <urcu/uatomic.h>

static void BM_userspace_rcu_uatomic_add_return(benchmark::State& state)
{
    unsigned atomic = 0;
    while (state.KeepRunning())
    {
        uatomic_add_return(&atomic, 1);
    }
}
BENCHMARK(BM_userspace_rcu_uatomic_add_return);
