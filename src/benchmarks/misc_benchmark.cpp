#include <iostream>
#include <vector>
#include <fstream>

#include <benchmark/benchmark.h>

#include "../server.hpp"

static Server *serverInstance;

static const unsigned long Q = 17293;
static const unsigned long P = 131;
static const unsigned long R = 1;
static const unsigned long BITS = 431;

static void DoSetup(const benchmark::State &state)
{
    static bool callSetup = true;
    if (callSetup)
    {
        serverInstance = new Server(constants::P131, false);
    }
    callSetup = false;
}

static void BM_EncrpytCiphertext(benchmark::State &state)
{
    std::vector<unsigned long> data = std::vector<unsigned long>(1000);

    for (auto _ : state)
    {
        auto result = serverInstance->Encrypt(data);
        benchmark::DoNotOptimize(result);
    }
}

static void BM_GeneratePublicKeySwitch(benchmark::State &state)
{
    helib::Context context = helib::ContextBuilder<helib::BGV>()
                                 .m(Q)
                                 .p(P)
                                 .r(R)
                                 .bits(BITS)
                                 .c(state.range(0))
                                 .build();
    uint32_t size = 0;

    helib::SecKey owner_secret_key(context);
    owner_secret_key.GenSecKey();
    helib::PubKey owner_public_key(owner_secret_key);

    helib::SecKey client_secret_key(context);
    client_secret_key.GenSecKey();
    helib::PubKey client_public_key(client_secret_key);

    for (auto _ : state)
    {
        pair<vector<helib::DoubleCRT>, vector<helib::DoubleCRT>> ksk = client_public_key.genPublicKeySwitchingKey(owner_secret_key, 0);
        benchmark::DoNotOptimize(ksk);

        state.PauseTiming();
        std::stringstream stream;
        ksk.first.at(0).writeTo(stream);
        std::string serializedData = stream.str();
        uint32_t numBytes = serializedData.size();
        size = (ksk.first.size() + ksk.second.size()) * numBytes;
        state.ResumeTiming();
    }

    state.counters["Storage (B)"] = size;
}

static void BM_SwithPublicKeySwitch(benchmark::State &state)
{
    helib::Context context = helib::ContextBuilder<helib::BGV>()
                                 .m(Q)
                                 .p(P)
                                 .r(R)
                                 .bits(BITS)
                                 .c(state.range(0))
                                 .build();

    helib::SecKey owner_secret_key(context);
    owner_secret_key.GenSecKey();
    helib::PubKey owner_public_key(owner_secret_key);

    helib::SecKey client_secret_key(context);
    client_secret_key.GenSecKey();
    helib::PubKey client_public_key(client_secret_key);

    pair<vector<helib::DoubleCRT>, vector<helib::DoubleCRT>> ksk = client_public_key.genPublicKeySwitchingKey(owner_secret_key, 0);

    helib::Ptxt<helib::BGV> ptxt(context);
    int num_slots = 10;
    vector<long> original_values = vector<long>(num_slots);
    for (int i = 0; i < num_slots; i++)
    {
        ptxt[i] = i;
        original_values[i] = i;
    }

    helib::Ctxt ctxt(owner_public_key);
    owner_public_key.Encrypt(ctxt, ptxt);

    for (auto _ : state)
    {
        state.PauseTiming();
        helib::Ctxt clone = ctxt;
        state.ResumeTiming();

        clone.PublicKeySwitch(ksk.first, ksk.second, 0, client_secret_key);
        benchmark::DoNotOptimize(clone);
    }
}

static void BM_ParallelSimilarityQuery(benchmark::State &state)
{
    if (state.range(0) > serverInstance->GetCols())
    {
        serverInstance->GenData(1, state.range(0));
    }

    vector<helib::Ctxt> d = vector<helib::Ctxt>();
    for (int i = 0; i < state.range(0); i++)
    {
        d.push_back(serverInstance->Encrypt(0));
    }
    uint32_t targetSnp = 0;
    uint32_t threshold = 100;

    for (auto _ : state)
    {
        auto result = serverInstance->SimilarityQueryP(targetSnp, d, threshold, state.range(1));

        state.PauseTiming();
        if (!result.first.isCorrect() || !result.second.isCorrect())
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();

        benchmark::DoNotOptimize(result);
    }
}

static void BM_ParallelPRSQuery(benchmark::State &state)
{
    if (state.range(0) > serverInstance->GetCols())
    {
        serverInstance->GenDataDummy(1, state.range(0));
    }

    vector<pair<uint32_t, int32_t>> query = vector<pair<uint32_t, int32_t>>();
    for (uint32_t i = 0; i < state.range(0); i++)
    {
        query.push_back(pair(i, 0));
    }
    for (auto _ : state)
    {
        auto result = serverInstance->PRSQueryP(query, state.range(1));

        state.PauseTiming();
        if (!result.isCorrect())
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();

        benchmark::DoNotOptimize(result);
    }
}

static void BM_ParallelMAFQuery(benchmark::State &state)
{
    if (state.range(0) > serverInstance->GetCols())
    {
        serverInstance->GenDataDummy(1, state.range(0));
    }

    vector<pair<uint32_t, uint32_t>> query = vector<pair<uint32_t, uint32_t>>();
    for (uint32_t i = 0; i < state.range(0); i++)
    {
        query.push_back(pair(i, 0));
    }
    for (auto _ : state)
    {
        auto result = serverInstance->MAFQueryP(0, query, state.range(1));

        state.PauseTiming();
        if (!result.first.isCorrect() || !result.second.isCorrect())
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();

        benchmark::DoNotOptimize(result);
    }
}

static void BM_ParallelCountQuery(benchmark::State &state)
{
    if (state.range(0) > serverInstance->GetCols())
    {
        serverInstance->GenDataDummy(1, state.range(0));
    }

    vector<pair<uint32_t, uint32_t>> query = vector<pair<uint32_t, uint32_t>>();
    for (uint32_t i = 0; i < state.range(0); i++)
    {
        query.push_back(pair(i, 0));
    }
    for (auto _ : state)
    {
        auto result = serverInstance->CountQueryP(query, state.range(1));

        state.PauseTiming();
        if (!result.isCorrect())
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();

        benchmark::DoNotOptimize(result);
    }
}

static void BM_UpdateOneValue(benchmark::State &state)
{
    int db_snps = state.range(0);
    serverInstance->GenDataDummy(1, db_snps);

    vector<uint32_t> vals = vector<uint32_t>(db_snps);
    for (int i = 0; i < db_snps; i++)
    {
        vals[i] = 0;
    }

    for (auto _ : state)
    {
        serverInstance->UpdateOneValue(0, 0, 0);
    }
}
static void BM_UpdateOneRow(benchmark::State &state)
{
    int db_snps = state.range(0);
    serverInstance->GenDataDummy(1, db_snps);

    vector<uint32_t> vals = vector<uint32_t>(db_snps);
    for (int i = 0; i < db_snps; i++)
    {
        vals[i] = 0;
    }

    for (auto _ : state)
    {
        serverInstance->UpdateOneRow(0, vals);
    }
}

static void BM_InsertRow(benchmark::State &state)
{
    int db_snps = state.range(0);
    serverInstance->GenDataDummy(1, db_snps);

    vector<uint32_t> vals = vector<uint32_t>(db_snps);
    for (int i = 0; i < db_snps; i++)
    {
        vals[i] = 0;
    }

    for (auto _ : state)
    {
        serverInstance->InsertOneRow(vals);
    }
}
static void BM_DeleteRowAddition(benchmark::State &state)
{
    int db_snps = state.range(0);
    serverInstance->GenDataDummy(1, db_snps);

    vector<uint32_t> vals = vector<uint32_t>(db_snps);
    for (int i = 0; i < db_snps; i++)
    {
        vals[i] = 0;
    }

    for (auto _ : state)
    {
        serverInstance->DeleteRowAddition(0);
    }
}
static void BM_DeleteRowMultiplication(benchmark::State &state)
{
    int db_snps = state.range(0);
    serverInstance->GenDataDummy(1, db_snps);

    vector<uint32_t> vals = vector<uint32_t>(db_snps);
    for (int i = 0; i < db_snps; i++)
    {
        vals[i] = 0;
    }

    for (auto _ : state)
    {
        serverInstance->DeleteRowMultiplication(0);
    }
}

BENCHMARK(BM_GeneratePublicKeySwitch)->ArgsProduct({{2, 3, 4, 5, 6, 7, 8, 9, 10, 11}})->Unit(benchmark::kSecond);
BENCHMARK(BM_SwithPublicKeySwitch)->ArgsProduct({{2, 3, 4, 5, 6, 7, 8, 9, 10, 11}})->Unit(benchmark::kSecond);
BENCHMARK(BM_ParallelSimilarityQuery)->ArgsProduct({{16, 128, 1024}, benchmark::CreateRange(1, 16, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_ParallelPRSQuery)->ArgsProduct({{16, 128, 1024}, benchmark::CreateRange(1, 16, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_ParallelMAFQuery)->ArgsProduct({{16, 128, 1024}, benchmark::CreateRange(1, 16, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_ParallelCountQuery)->ArgsProduct({{16, 128, 1024, 8196}, benchmark::CreateRange(1, 16, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_EncrpytCiphertext)->Unit(benchmark::kSecond)->Setup(DoSetup);

BENCHMARK(BM_UpdateOneValue)->ArgsProduct({benchmark::CreateRange(1, 1024, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_UpdateOneRow)->ArgsProduct({benchmark::CreateRange(1, 1024, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_InsertRow)->ArgsProduct({benchmark::CreateRange(1, 1024, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_DeleteRowAddition)->ArgsProduct({benchmark::CreateRange(1, 1024, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_DeleteRowMultiplication)->ArgsProduct({benchmark::CreateRange(1, 1024, /*step=*/2)})->Unit(benchmark::kSecond)->Setup(DoSetup);

BENCHMARK_MAIN();