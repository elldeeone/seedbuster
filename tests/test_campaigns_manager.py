from src.analyzer.campaigns import ThreatCampaignManager


def test_campaign_member_replaces_indicators(tmp_path):
    manager = ThreatCampaignManager(tmp_path)

    campaign, is_new = manager.add_to_campaign(
        domain="kaspa.insure",
        score=80,
        backends=["api.kaspa-example.tld"],
        kit_matches=["kaspa_stealer_v1"],
        nameservers=["ns1.streetplug.me"],
        asn="1337",
        ip_address="1.2.3.4",
    )
    assert is_new is True
    assert campaign.shared_nameservers == {"ns1.streetplug.me"}

    campaign, is_new = manager.add_to_campaign(
        domain="kaspa.insure",
        score=80,
        backends=["api.kaspa-example.tld"],
        kit_matches=["kaspa_stealer_v1"],
        nameservers=["ns1.dyna-ns.net"],
        asn="4242",
        ip_address="5.6.7.8",
    )
    assert is_new is False

    member = campaign.members[0]
    assert member.nameservers == ["ns1.dyna-ns.net"]
    assert member.asn == "4242"
    assert member.ip_address == "5.6.7.8"
    assert campaign.shared_nameservers == {"ns1.dyna-ns.net"}
    assert "ns1.streetplug.me" not in manager._ns_index
