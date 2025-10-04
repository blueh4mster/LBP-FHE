#include "benchmark/benchmark.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"
#include "benchmark_utils.h"
#include <iostream>
using namespace lbcrypto;

void CKKS_FULL_PACKING_BTKEYGEN(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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
    while (state.KeepRunning()){
        double power = benchutils::get_total_cpu_energy_j();
        power_sum+= power;
        cnt+=1;

        cc->EvalBootstrapSetup(levelBudget);
        auto keyPair = cc->KeyGen();
        cc->EvalMultKeyGen(keyPair.secretKey);
        cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);
        
        rss_after = benchutils::get_rss_kb();
    }
    
    double avg_power = (power_sum) / cnt;

    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_BTKEYGEN)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_ENCRYPT(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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
        double power = benchutils::get_total_cpu_energy_j();
        power_sum+= power;
        cnt+=1;
        
        Ciphertext<DCRTPoly> ciph = cc->Encrypt(keyPair.publicKey, ptxt);

        rss_after = benchutils::get_rss_kb();
    }
    
    double avg_power = (power_sum) / cnt;

    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_ENCRYPT)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_DECRYPT(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    size_t encodedLength = x.size();
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    ptxt->SetLength(encodedLength);
    Ciphertext<DCRTPoly> ciph = cc->Encrypt(keyPair.publicKey, ptxt);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        Plaintext result;
        cc->Decrypt(keyPair.secretKey, ciph, &result);
        result->SetLength(encodedLength);

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_DECRYPT)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_BOOTSTRAP(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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
    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    size_t encodedLength = x.size();

    cc->EvalBootstrapSetup(levelBudget);
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    ptxt->SetLength(encodedLength);
    Ciphertext<DCRTPoly> ciph = cc->Encrypt(keyPair.publicKey, ptxt);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        auto ciphertextAfter = cc->EvalBootstrap(ciph);
        (void)ciphertextAfter;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_BOOTSTRAP)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_ADD(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    std::vector<double> y = {1.25, 1.5, 1.75, 2.0};
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(y, 1, depth - 1);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keyPair.publicKey, p2);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        auto csum = cc->EvalAdd(c1, c2);
        (void)csum;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_ADD)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_SUB(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    std::vector<double> y = {1.25, 1.5, 1.75, 2.0};
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(y, 1, depth - 1);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keyPair.publicKey, p2);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        auto cdiff = cc->EvalSub(c1, c2);
        (void)cdiff;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_SUB)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_MUL(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    std::vector<double> y = {1.25, 1.5, 1.75, 2.0};
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(y, 1, depth - 1);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);
    Ciphertext<DCRTPoly> c2 = cc->Encrypt(keyPair.publicKey, p2);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        auto cmul = cc->EvalMult(c1, c2);
        (void)cmul;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_MUL)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_NEG(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        auto cneg = cc->EvalNegate(c1);
        (void)cneg;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_NEG)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_SQR(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        auto csq = cc->EvalSquare(c1);
        (void)csq;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_SQR)->Unit(benchmark::kMicrosecond);

void CKKS_FULL_PACKING_ROT_1(benchmark::State &state)
{
    double power_sum = 0.0;
    int cnt = 0;
    size_t rss_after = 0;

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

    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    cc->EvalRotateKeyGen(keyPair.secretKey, {1});

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0};
    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x, 1, depth - 1);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keyPair.publicKey, p1);

    while (state.KeepRunning())
    {
        double power = benchutils::get_total_cpu_energy_j();
        power_sum += power;
        cnt += 1;

        auto crot = cc->EvalRotate(c1, 1);
        (void)crot;

        rss_after = benchutils::get_rss_kb();
    }

    double avg_power = (power_sum) / cnt;
    state.counters["RSS_kB"] = rss_after;
    state.counters["Power_W"] = avg_power;
}

BENCHMARK(CKKS_FULL_PACKING_ROT_1)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();