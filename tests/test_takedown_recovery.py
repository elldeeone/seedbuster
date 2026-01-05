from src.analyzer.takedown_checker import TakedownStatus
from src.main import SeedBusterPipeline


def test_takedown_recovered_only_on_down_to_active():
    assert SeedBusterPipeline._takedown_recovered(
        "confirmed_down", TakedownStatus.ACTIVE
    )
    assert SeedBusterPipeline._takedown_recovered("likely_down", TakedownStatus.ACTIVE)
    assert not SeedBusterPipeline._takedown_recovered("active", TakedownStatus.ACTIVE)
    assert not SeedBusterPipeline._takedown_recovered(None, TakedownStatus.ACTIVE)
    assert not SeedBusterPipeline._takedown_recovered(
        "confirmed_down", TakedownStatus.CONFIRMED_DOWN
    )
