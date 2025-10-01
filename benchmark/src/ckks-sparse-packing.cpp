#include "benchmark/benchmark.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"
#include "benchmark_utils.h"
#include <iostream>
using namespace lbcrypto;

void CKKS_SPARSE_PACKING_BTKEYGEN(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;
    
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

        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        // precomputation for bootstrapping
        cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
        // generate key pair
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        // generate bootstrapping key
        cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);


        rss_after = benchutils::get_rss_kb();
    }
    
    double avg_power = (power_sum) / cnt;

    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_BTKEYGEN)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_ENCRYPT(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

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

        rss_after = benchutils::get_rss_kb();
    }
    
    double avg_power = (power_sum) / cnt;

    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_ENCRYPT)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_DECRYPT(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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
    std::vector<uint32_t> bsgsDim = {0, 0};
    cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
    auto keyPair   = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x;
    for (size_t i = 0; i < numSlots; i++) x.push_back(static_cast<double>(i));
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    ptxt->SetLength(numSlots);
    Ciphertext<DCRTPoly> ciph = cc->Encrypt(keyPair.publicKey, ptxt);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        Plaintext result;
        cc->Decrypt(keyPair.secretKey, ciph, &result);
        result->SetLength(numSlots);

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_DECRYPT)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_BOOTSTRAP(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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
    std::vector<uint32_t> bsgsDim = {0, 0};
    cc->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
    auto keyPair   = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    std::vector<double> x;
    for (size_t i = 0; i < numSlots; i++) x.push_back(static_cast<double>(i));
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    ptxt->SetLength(numSlots);
    Ciphertext<DCRTPoly> ciph = cc->Encrypt(keyPair.publicKey, ptxt);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        auto after = cc->EvalBootstrap(ciph);
        (void)after;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_BOOTSTRAP)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_ADD(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    usint numSlots = 32;
    std::vector<double> a(numSlots, 0.5);
    std::vector<double> b(numSlots, 1.0);
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(a, 1, depth - 1, nullptr, numSlots);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(b, 1, depth - 1, nullptr, numSlots);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keyPair.publicKey, p2);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        auto csum = cc->EvalAdd(c1, c2);
        (void)csum;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_ADD)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_SUB(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    usint numSlots = 32;
    std::vector<double> a(numSlots, 1.5);
    std::vector<double> b(numSlots, 0.5);
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(a, 1, depth - 1, nullptr, numSlots);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(b, 1, depth - 1, nullptr, numSlots);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keyPair.publicKey, p2);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        auto cdiff = cc->EvalSub(c1, c2);
        (void)cdiff;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_SUB)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_MUL(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    usint numSlots = 32;
    std::vector<double> a(numSlots, 1.5);
    std::vector<double> b(numSlots, 0.5);
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(a, 1, depth - 1, nullptr, numSlots);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(b, 1, depth - 1, nullptr, numSlots);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keyPair.publicKey, p2);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        auto cmul = cc->EvalMult(c1, c2);
        (void)cmul;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_MUL)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_NEG(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    usint numSlots = 32;
    std::vector<double> a(numSlots, 1.5);
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(a, 1, depth - 1, nullptr, numSlots);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        auto cneg = cc->EvalNegate(c1);
        (void)cneg;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_NEG)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_SQR(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    usint numSlots = 32;
    std::vector<double> a(numSlots, 1.25);
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(a, 1, depth - 1, nullptr, numSlots);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        auto csq = cc->EvalSquare(c1);
        (void)csq;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_SQR)->Unit(benchmark::kMicrosecond);

void CKKS_SPARSE_PACKING_ROT_1(benchmark::State& state) {
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalRotateKeyGen(keyPair.secretKey, {1});

    usint numSlots = 32;
    std::vector<double> a(numSlots, 0.5);
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(a, 1, depth - 1, nullptr, numSlots);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);

    while (state.KeepRunning()) {
        long freq = benchutils::get_cpu_freq();
        double volt = benchutils::get_cpu_volt();
        double power = benchutils::estimate_power(volt, freq, 1.0);
        power_sum+= power;
        cnt+=1;

        auto crot = cc->EvalRotate(c1, 1);
        (void)crot;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_SPARSE_PACKING_ROT_1)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();