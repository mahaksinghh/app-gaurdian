import asyncio
import json
from datetime import datetime, timezone

import httpx
import pytest

from guardian.assistant import Advisor, guide
from guardian.catalog import Catalog
from guardian.models import GuidanceRequest


def test_rules_work_bilingually_without_provider_and_keep_verification_last():
    request = GuidanceRequest(
        scenario="before-install", language="hi", evidence=["debuggable", "sms", "sms"], use_ai=True
    )
    advice = asyncio.run(guide(request, None))
    assert advice.mode == "rules-fallback"
    assert [step.id for step in advice.steps] == ["start", "sms", "debuggable", "verify"]
    assert "पुष्टि" in advice.steps[-1].title


def test_provider_sees_only_category_ids_and_cannot_add_any(monkeypatch):
    configured = Advisor("https://example.test/chat/completions", "test-model", "test-token")

    def response(request):
        context = json.loads(json.loads(request.content)["messages"][1]["content"])
        assert context == {"scenario": "installed-app", "language": "en", "ids": ["sms", "camera"]}
        return httpx.Response(200, json={"choices": [{"message": {"content": '["camera","invented-verdict"]'}}]})

    with pytest.raises(ValueError, match="outside the selected set"):
        asyncio.run(configured.order(["sms", "camera"], "installed-app", "en", httpx.MockTransport(response)))

    async def accepted(self, ids, scenario, language):
        return ids[::-1]

    monkeypatch.setattr(Advisor, "order", accepted)
    advice = asyncio.run(guide(GuidanceRequest(
        scenario="installed-app", evidence=["sms", "camera"], use_ai=True
    ), configured))
    assert advice.mode == "ai-prioritized"
    assert [step.id for step in advice.steps] == ["start", "camera", "sms", "verify"]


def test_catalog_reports_exact_matches_and_attribution():
    catalog = Catalog.model_validate({
        "catalogVersion": "fixture",
        "dateReleased": datetime.now(timezone.utc),
        "count": 1,
        "vulnerabilities": [{
            "cveID": "CVE-2020-0001",
            "vendorProject": "Test Publisher",
            "product": "Test Product",
            "dateAdded": "2020-01-02",
            "requiredAction": "Install the vendor patch.",
        }],
    })
    result = catalog.assessment(["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0001"])
    assert result.applicability == "human-review-required"
    assert result.license == "CC0-1.0"
    assert [entry.cveID for entry in result.matches] == ["CVE-2020-0001"]
    assert result.unlisted_ids == ["CVE-2020-0002"]
