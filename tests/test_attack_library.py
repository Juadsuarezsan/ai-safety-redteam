from src.attacks.library import all_attacks


def test_attacks_cover_multiple_categories():
    attacks = all_attacks()
    categories = {a.category for a in attacks}
    assert "LLM01_prompt_injection" in categories
    assert "LLM02_insecure_output" in categories
    assert "LLM06_info_disclosure" in categories
    assert len(attacks) >= 10


def test_attack_ids_are_unique():
    ids = [a.id for a in all_attacks()]
    assert len(ids) == len(set(ids))
