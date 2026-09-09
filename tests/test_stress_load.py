from tests.stress.thesis_legacy_load import LoadStats, summarize


def test_search_summary_records_fixture_count_and_latency_metrics():
    stats = LoadStats()
    stats.record_success(12.5)
    stats.record_success(20.0)

    result = summarize(stats, 1.0, "search", 2, search_fixtures=250)

    assert result["search_fixture_count"] == 250
    assert result["throughput_rps"] == 2.0
    assert result["latency_ms"]["p95"] == 12.5
