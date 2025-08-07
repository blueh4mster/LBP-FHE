#include "benchmark/benchmark.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"
#include <iostream>
using namespace lbcrypto;

void CKKS_FULL_PACKING_BTKEYGEN(benchmark::State &state)
{
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    std::vector<uint32_t> levelBudget = {4, 4};
    usint levelsAvailableAfterBootstrap = 10;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);

    parameters.SetRingDim(1 << 12);
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(59);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);

    usint numSlots = parameters.GetRingDim() / 2;
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    while (state.KeepRunning())
    {
        cc->EvalBootstrapSetup(levelBudget);
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);
    }
}

BENCHMARK(CKKS_FULL_PACKING_BTKEYGEN)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_ENCRYPT(benchmark::State &state)
{
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    std::vector<uint32_t> levelBudget = {4, 4};
    usint levelsAvailableAfterBootstrap = 10;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);

    parameters.SetRingDim(1 << 12);
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(59);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    usint numSlots = parameters.GetRingDim() / 2;
    auto keyPair = cc->KeyGen();
    cc->EvalBootstrapSetup(levelBudget);
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    size_t encodedLength = x.size();
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    ptxt->SetLength(encodedLength);
    while (state.KeepRunning())
    {
        Ciphertext<DCRTPoly> ciph = cc->Encrypt(keyPair.publicKey, ptxt);
    }
}

BENCHMARK(CKKS_FULL_PACKING_ENCRYPT)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();