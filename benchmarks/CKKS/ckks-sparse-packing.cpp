#include "benchmark/benchmark.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"
#include <iostream>
using namespace lbcrypto;

void CKKS_SPARSE_PACKING_BTKEYGEN(benchmark::State& state) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist         = UNIFORM_TERNARY;
    //  bootstrapping parameter
    //  We must choose values smaller than ceil(log2(slots))
    std::vector<uint32_t> levelBudget   = {3, 3};
    usint levelsAvailableAfterBootstrap = 10;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);

    parameters.SetRingDim(1 << 12);
    parameters.SetMultiplicativeDepth(depth);
    parameters.SetScalingModSize(59);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetFirstModSize(60);
    parameters.SetSecurityLevel(HEStd_NotSet);

    auto cc        = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);

    usint numSlots = 32;
    // default value
    std::vector<uint32_t> bsgsDim = {0, 0};
    while (state.KeepRunning()) {
        // precomputation for bootstrapping
        cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
        // generate key pair
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        // generate bootstrapping key
        cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);
    }
}

BENCHMARK(CKKS_SPARSE_PACKING_BTKEYGEN)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_ENCRYPT(benchmark::State& state) {
    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist         = UNIFORM_TERNARY;
    std::vector<uint32_t> levelBudget   = {3, 3};
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

    usint numSlots = 32;
    // default value
    std::vector<uint32_t> bsgsDim = {0, 0};

    while (state.KeepRunning()) {
        // precomputation for bootstrapping
        cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
        // generate key pair
        auto keyPair   = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        // generate bootstrapping key
        cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

        // generate random input
        std::vector<double> x;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        for (size_t i = 0; i < numSlots; i++) {
            x.push_back(dis(gen));
        }

        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
        ptxt->SetLength(numSlots);

        Ciphertext<DCRTPoly> ciph = cc->Encrypt(keyPair.publicKey, ptxt);
    }
}

BENCHMARK(CKKS_SPARSE_PACKING_ENCRYPT)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();