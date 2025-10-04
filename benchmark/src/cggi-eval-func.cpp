/*
 * This file benchmarks FHEW-GINX function evaluation
 */

#include "benchmark/benchmark.h"
#include "binfhecontext.h"
#include "benchmark_utils.h"

using namespace lbcrypto;

/*
 * Context setup utility methods
 */

BinFHEContext GenerateFHEWContext(BINFHE_PARAMSET set)
{
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(set, GINX);
    return cc;
}

/*
 * FHEW benchmarks
 */

template <class ParamSet>
void FHEW_BTKEYGEN(benchmark::State &state, ParamSet param_set)
{
    
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

    for (auto _ : state)
    {
        double power = benchutils::get_total_cpu_energy_j();
        // double power = 1.0;
        power_sum+= power;
        cnt+=1;

        LWEPrivateKey sk = cc.KeyGen();
        cc.BTKeyGen(sk);

        rss_after = benchutils::get_rss_kb();
    }
    
    double avg_power = (power_sum) / cnt;

    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK_CAPTURE(FHEW_BTKEYGEN, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_BTKEYGEN, STD128, STD128)->Unit(benchmark::kMicrosecond);

template <class ParamSet>
void FHEW_ENCRYPT(benchmark::State &state, ParamSet param_set)
{
    
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);
    
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

    LWEPrivateKey sk = cc.KeyGen();
    for (auto _ : state)
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum+= power;
        cnt+=1;

        LWECiphertext ct1 = cc.Encrypt(sk, 1, SMALL_DIM);

        rss_after = benchutils::get_rss_kb();
    }
    
    double avg_power = (power_sum) / cnt;

    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK_CAPTURE(FHEW_ENCRYPT, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_ENCRYPT, STD128, STD128)->Unit(benchmark::kMicrosecond);

// benchmark for Eval function
template <class ParamSet>
void FHEW_EVAL_FUNC(benchmark::State &state, ParamSet param_set)
{
    
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);
    
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;
    
    LWEPrivateKey sk = cc.KeyGen();

    cc.BTKeyGen(sk);

    int p = cc.GetMaxPlaintextSpace().ConvertToInt(); // Obtain the maximum plaintext space

    // Function f(x) = x^3 % p
    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger
    {
        if (m < p1)
            return (m * m * m) % p1;
        else
            return ((m - p1 / 2) * (m - p1 / 2) * (m - p1 / 2)) % p1;
    };

    LWECiphertext ct1 = cc.Encrypt(sk, 1, LARGE_DIM, p);

    auto lut = cc.GenerateLUTviaFunction(fp, p);

    for (auto _ : state)
    {

        double power = benchutils::get_total_cpu_energy_j();
        power_sum+= power;
        cnt+=1;

        
        LWECiphertext ct11 = cc.EvalFunc(ct1, lut);


        rss_after = benchutils::get_rss_kb();
    }
    
    double avg_power = (power_sum) / cnt;

    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK_CAPTURE(FHEW_EVAL_FUNC, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_EVAL_FUNC, STD128, STD128)->Unit(benchmark::kMicrosecond);

// --- Additional basic ops: KeyGen, Decrypt, Bootstrapping (GINX/CGGI) ---

template <class ParamSet>
void FHEW_KEYGEN_ONLY(benchmark::State &state, ParamSet param_set)
{
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

    for (auto _ : state)
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum+= power;
        cnt+=1;

        LWEPrivateKey sk = cc.KeyGen();
        (void)sk;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK_CAPTURE(FHEW_KEYGEN_ONLY, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_KEYGEN_ONLY, STD128, STD128)->Unit(benchmark::kMicrosecond);

template <class ParamSet>
void FHEW_DECRYPT_ONLY(benchmark::State &state, ParamSet param_set)
{
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

    LWEPrivateKey sk = cc.KeyGen();
    // Encrypt a sample under a small dimension to match gate-style measurements
    LWECiphertext ct = cc.Encrypt(sk, 1, SMALL_DIM);

    for (auto _ : state)
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum+= power;
        cnt+=1;

        LWEPlaintext result;
        cc.Decrypt(sk, ct, &result);

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK_CAPTURE(FHEW_DECRYPT_ONLY, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_DECRYPT_ONLY, STD128, STD128)->Unit(benchmark::kMicrosecond);

template <class ParamSet>
void FHEW_BOOTSTRAP_ONLY(benchmark::State &state, ParamSet param_set)
{
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

    LWEPrivateKey sk = cc.KeyGen();
    cc.BTKeyGen(sk);
    LWECiphertext ct = cc.Encrypt(sk, 1);

    for (auto _ : state)
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum+= power;
        cnt+=1;

        // Use NOT to trigger PBS without extra operand cost
        auto refreshed = cc.EvalNOT(ct);
        (void)refreshed;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK_CAPTURE(FHEW_BOOTSTRAP_ONLY, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_BOOTSTRAP_ONLY, STD128, STD128)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();