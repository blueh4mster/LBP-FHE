/*
 * This file benchmarks FHEW-GINX function evaluation
 */

#include "benchmark/benchmark.h"
#include "binfhecontext.h"

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

    for (auto _ : state)
    {
        LWEPrivateKey sk = cc.KeyGen();
        cc.BTKeyGen(sk);
    }
}

BENCHMARK_CAPTURE(FHEW_BTKEYGEN, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_BTKEYGEN, STD128, STD128)->Unit(benchmark::kMicrosecond);

template <class ParamSet>
void FHEW_ENCRYPT(benchmark::State &state, ParamSet param_set)
{
    BINFHE_PARAMSET param(param_set);
    BinFHEContext cc = GenerateFHEWContext(param);

    LWEPrivateKey sk = cc.KeyGen();
    for (auto _ : state)
    {
        LWECiphertext ct1 = cc.Encrypt(sk, 1, SMALL_DIM);
    }
}

BENCHMARK_CAPTURE(FHEW_ENCRYPT, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_ENCRYPT, STD128, STD128)->Unit(benchmark::kMicrosecond);

// benchmark for Eval function
template <class ParamSet>
void FHEW_EVAL_FUNC(benchmark::State &state, ParamSet param_set)
{
    BINFHE_PARAMSET param(param_set);

    BinFHEContext cc = GenerateFHEWContext(param);

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
        LWECiphertext ct11 = cc.EvalFunc(ct1, lut);
    }
}

BENCHMARK_CAPTURE(FHEW_EVAL_FUNC, MEDIUM, MEDIUM)->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(FHEW_EVAL_FUNC, STD128, STD128)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
