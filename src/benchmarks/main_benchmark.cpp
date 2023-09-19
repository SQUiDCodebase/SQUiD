#include <iostream>
#include <vector>
#include <fstream>

#include <benchmark/benchmark.h>

#include "../server.hpp"

const int MOST_SNPS = 1024;

static Server *serverInstance;

static void DoSetup(const benchmark::State &state)
{
    static bool callSetup = true;
    if (callSetup)
    {
        serverInstance = new Server(constants::P131, false);

        serverInstance->GenData(1, MOST_SNPS);
    }
    callSetup = false;
}

static void BM_CountQuery(benchmark::State &state)
{
    if (state.range(2) != serverInstance->GetCompressedRows())
    {
        serverInstance->GenData(1 + (state.range(2) - 1) * serverInstance->GetSlotSize(), MOST_SNPS);
    }

    uint32_t commBytes = 0;
    vector<pair<uint32_t, uint32_t>> query = vector<pair<uint32_t, uint32_t>>();
    bool conjunctive = state.range(1);
    for (uint32_t i = 0; i < state.range(0); i++)
    {
        query.push_back(pair(i, 0));
    }

    commBytes += query.size() * sizeof(query[0]);
    commBytes += sizeof(conjunctive);

    for (auto _ : state)
    {
        auto result = serverInstance->CountQuery(conjunctive, query);
        state.PauseTiming();
        if (!result.isCorrect())
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();
        benchmark::DoNotOptimize(result);
    }
    commBytes += serverInstance->StorageOfOneElement();

    state.counters["Communication (B)"] = commBytes;
}

static void BM_MAFQuery(benchmark::State &state)
{
    if (state.range(2) != serverInstance->GetCompressedRows())
    {
        serverInstance->GenData(1 + (state.range(2) - 1) * serverInstance->GetSlotSize(), MOST_SNPS);
    }
    uint32_t commBytes = 0;
    vector<pair<uint32_t, uint32_t>> query = vector<pair<uint32_t, uint32_t>>();
    bool conjunctive = state.range(1);
    uint32_t snp = 0;

    for (uint32_t i = 0; i < state.range(0); i++)
    {
        query.push_back(pair(i, 0));
    }

    commBytes += query.size() * sizeof(query[0]);
    commBytes += sizeof(conjunctive);
    commBytes += sizeof(snp);

    for (auto _ : state)
    {
        auto result = serverInstance->MAFQuery(snp, conjunctive, query);

        state.PauseTiming();
        if (!result.first.isCorrect() || !result.second.isCorrect())
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();

        benchmark::DoNotOptimize(result);
    }
    commBytes += 2 * serverInstance->StorageOfOneElement();
    state.counters["Communication (B)"] = commBytes;
}

static void BM_PRSQuery(benchmark::State &state)
{
    if (state.range(2) != serverInstance->GetCompressedRows())
    {
        serverInstance->GenData(1 + (state.range(2) - 1) * serverInstance->GetSlotSize(), MOST_SNPS);
    }
    uint32_t commBytes = 0;
    vector<pair<uint32_t, int32_t>> query = vector<pair<uint32_t, int32_t>>();
    for (uint32_t i = 0; i < state.range(0); i++)
    {
        query.push_back(pair(i, 0));
    }

    commBytes += query.size() * sizeof(query[0]);

    for (auto _ : state)
    {
        auto result = serverInstance->PRSQuery(query);
        state.PauseTiming();
        bool exceedError = false;
        for (size_t i = 0; i < result.size(); i++)
        {
            if (!result[i].isCorrect())
            {
                exceedError = true;
            }
        }
        if (exceedError)
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();
        benchmark::DoNotOptimize(result);
    }
    commBytes += serverInstance->GetCompressedRows() * serverInstance->StorageOfOneElement();

    state.counters["Communication (B)"] = commBytes;
}

static void BM_SimilarityQuery(benchmark::State &state)
{
    if (state.range(2) != serverInstance->GetCompressedRows())
    {
        serverInstance->GenData(1 + (state.range(2) - 1) * serverInstance->GetSlotSize(), MOST_SNPS);
    }
    uint32_t commBytes = 0;

    vector<helib::Ctxt> d = vector<helib::Ctxt>();
    for (int i = 0; i < state.range(0); i++)
    {
        d.push_back(serverInstance->Encrypt(0));
    }
    uint32_t targetSnp = 0;
    uint32_t threshold = 100;

    commBytes += d.size() * serverInstance->StorageOfOneElement();
    commBytes += sizeof(targetSnp);
    commBytes += sizeof(threshold);

    for (auto _ : state)
    {
        auto result = serverInstance->SimilarityQuery(targetSnp, d, threshold);

        state.PauseTiming();
        if (!result.first.isCorrect() || !result.second.isCorrect())
        {
            std::cout << "ERROR EXCEEDED" << std::endl;
        }
        state.ResumeTiming();

        benchmark::DoNotOptimize(result);
    }
    commBytes += 2 * serverInstance->StorageOfOneElement();

    state.counters["Communication (B)"] = commBytes;
}

BENCHMARK(BM_CountQuery)->ArgsProduct({benchmark::CreateRange(2, MOST_SNPS, /*multi=*/2), benchmark::CreateDenseRange(0, 1, /*step=*/1), {1, 2, 3, 4}})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_MAFQuery)->ArgsProduct({benchmark::CreateRange(2, MOST_SNPS, /*multi=*/2), benchmark::CreateDenseRange(0, 1, /*step=*/1), {1, 2, 3, 4}})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_PRSQuery)->ArgsProduct({benchmark::CreateRange(2, MOST_SNPS, /*multi=*/2), {1, 2, 3, 4}})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK(BM_SimilarityQuery)->ArgsProduct({benchmark::CreateRange(2, MOST_SNPS, /*multi=*/2), {1, 2, 3, 4}})->Unit(benchmark::kSecond)->Setup(DoSetup);
BENCHMARK_MAIN();