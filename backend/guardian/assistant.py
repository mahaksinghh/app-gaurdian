import json
from dataclasses import dataclass
from urllib.parse import urlsplit

import anyio
import httpx

from .models import Guidance, GuidanceRequest, GuidanceStep, Language


@dataclass(frozen=True)
class Advisor:
    url: str
    model: str
    token: str

    def __post_init__(self) -> None:
        url = urlsplit(self.url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment or url.query:
            raise ValueError("The assistant endpoint must be an HTTPS URL without credentials or query.")
        if not self.model.strip() or not self.token.strip():
            raise ValueError("Configure the assistant model and token together.")

    async def order(self, code_ids: list[str], scenario: str, language: Language, transport=None) -> list[str]:
        body = {
            "model": self.model,
            "max_tokens": 160,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return a JSON array containing every supplied evidence identifier exactly once, "
                        "ordered by which is most useful to explain first in the given scenario. "
                        "Do not add text, observations, judgments, or identifiers."
                    ),
                },
                {"role": "user", "content": json.dumps({"scenario": scenario, "language": language, "ids": code_ids})},
            ],
        }
        with anyio.fail_after(5):
            async with httpx.AsyncClient(timeout=4, follow_redirects=False, trust_env=False, transport=transport) as client:
                async with client.stream(
                    "POST", self.url, headers={"Authorization": f"Bearer {self.token}"}, json=body
                ) as response:
                    response.raise_for_status()
                    data = bytearray()
                    async for part in response.aiter_bytes():
                        if len(part) > 12_000 - len(data):
                            raise ValueError("Model response limit exceeded.")
                        data.extend(part)
        message = json.loads(data)["choices"][0]["message"]["content"]
        order = json.loads(message)
        if not isinstance(order, list) or not all(isinstance(code, str) for code in order):
            raise ValueError("Invalid evidence ordering.")
        if len(order) != len(code_ids) or set(order) != set(code_ids):
            raise ValueError("Model returned evidence outside the selected set.")
        return order


@dataclass(frozen=True)
class Action:
    title_en: str
    instruction_en: str
    title_hi: str
    instruction_hi: str

    def step(self, id: str, language: Language) -> GuidanceStep:
        if language == "hi":
            return GuidanceStep(id=id, title=self.title_hi, instruction=self.instruction_hi)
        return GuidanceStep(id=id, title=self.title_en, instruction=self.instruction_en)


START = {
    "before-install": Action(
        "Pause before installing", "Confirm the publisher and download source. Leave the APK uninstalled if either is unexpected.",
        "इंस्टॉल करने से पहले रुकें", "प्रकाशक और डाउनलोड का स्रोत जाँचें। कोई बात संदिग्ध लगे तो APK इंस्टॉल न करें।",
    ),
    "installed-app": Action(
        "Review the app in Android Settings", "Open App info and review the permissions and special access that the app actually has.",
        "Android सेटिंग में ऐप देखें", "ऐप की जानकारी खोलें और मिली हुई अनुमतियाँ व विशेष पहुँच जाँचें।",
    ),
    "account-incident": Action(
        "Secure account access", "On a trusted device, go to the provider’s official security page and change the password.",
        "खाते की पहुँच सुरक्षित करें", "विश्वसनीय डिवाइस पर सेवा की आधिकारिक सुरक्षा सेटिंग खोलकर पासवर्ड बदलें।",
    ),
}
VERIFY = {
    "before-install": Action(
        "Verify the source", "Compare the APK hash or signing fingerprint with a value published on the publisher’s trusted site.",
        "स्रोत की पुष्टि करें", "APK हैश या हस्ताक्षर की फ़िंगरप्रिंट की तुलना प्रकाशक की विश्वसनीय साइट पर दिए गए मान से करें।",
    ),
    "installed-app": Action(
        "Recheck what changed", "Reopen AppGuardian after changing permissions or uninstalling. Confirm the current state in Android Settings.",
        "बदलाव दोबारा जाँचें", "अनुमति बदलने या ऐप हटाने के बाद AppGuardian फिर खोलें। Android सेटिंग में वर्तमान स्थिति की पुष्टि करें।",
    ),
    "account-incident": Action(
        "Verify recovery", "Review signed-in devices and recovery details again. Make sure two-step verification is enabled.",
        "रिकवरी की पुष्टि करें", "साइन इन किए गए डिवाइस और रिकवरी जानकारी फिर देखें। दो-चरणीय सत्यापन चालू होना चाहिए।",
    ),
}
EVIDENCE = {
    "signature-unverified": Action(
        "Signature needs verification", "Get a trusted copy and compare signing information before relying on the file.",
        "हस्ताक्षर की पुष्टि करें", "फ़ाइल पर भरोसा करने से पहले विश्वसनीय प्रति लें और हस्ताक्षर की जानकारी मिलाएँ।",
    ),
    "accessibility": Action(
        "Review accessibility access", "If the app offers an accessibility service, enable it only when you recognize and need that function.",
        "सुलभता की पहुँच जाँचें", "ऐप की सुलभता सेवा तभी चालू करें जब आप उसके काम को समझते हैं और उसकी ज़रूरत है।",
    ),
    "sms": Action(
        "Review text-message access", "Confirm whether reading or receiving texts is necessary. Texts may contain sensitive messages and codes.",
        "SMS की पहुँच जाँचें", "जाँचें कि संदेश पढ़ना या पाना ज़रूरी है या नहीं। SMS में निजी संदेश और सत्यापन कोड हो सकते हैं।",
    ),
    "package-installer": Action(
        "Review app installation access", "Check the system’s Install unknown apps setting if this app can request package installs.",
        "ऐप इंस्टॉल करने की पहुँच जाँचें", "अगर यह ऐप दूसरे ऐप इंस्टॉल करने का अनुरोध करता है, तो Android की अज्ञात ऐप इंस्टॉलेशन सेटिंग देखें।",
    ),
    "microphone": Action(
        "Review microphone access", "Allow the microphone only if it supports a feature you use.",
        "माइक्रोफ़ोन की पहुँच जाँचें", "माइक्रोफ़ोन की अनुमति तभी दें जब उसका इस्तेमाल आपके काम के फ़ीचर में हो।",
    ),
    "camera": Action(
        "Review camera access", "Check whether the app needs the camera for a feature you use.",
        "कैमरे की पहुँच जाँचें", "देखें कि जिस फ़ीचर का आप इस्तेमाल करते हैं, उसके लिए कैमरा ज़रूरी है या नहीं।",
    ),
    "location": Action(
        "Review location access", "Choose approximate or while-in-use access when it is sufficient for the app’s purpose.",
        "लोकेशन की पहुँच जाँचें", "अगर पर्याप्त हो, तो अनुमानित लोकेशन या सिर्फ़ उपयोग के समय वाली अनुमति चुनें।",
    ),
    "contacts": Action(
        "Review contacts access", "Decide whether sharing your address book is needed for the app’s purpose.",
        "संपर्कों की पहुँच जाँचें", "तय करें कि इस ऐप के काम के लिए आपकी संपर्क सूची साझा करना ज़रूरी है या नहीं।",
    ),
    "debuggable": Action(
        "Check the build type", "Ask the publisher whether this debug build is expected before you rely on the app.",
        "बिल्ड का प्रकार जाँचें", "ऐप पर भरोसा करने से पहले प्रकाशक से पूछें कि क्या यह डिबग बिल्ड अपेक्षित है।",
    ),
    "cleartext": Action(
        "Check encryption", "Ask the publisher which connections use encryption before entering sensitive information.",
        "एन्क्रिप्शन जाँचें", "संवेदनशील जानकारी देने से पहले प्रकाशक से पूछें कि कौन से कनेक्शन एन्क्रिप्टेड हैं।",
    ),
}


async def guide(request: GuidanceRequest, advisor: Advisor | None) -> Guidance:
    code_ids = [code for code in EVIDENCE if code in request.evidence]
    mode = "rules"
    if request.use_ai and len(code_ids) > 1:
        mode = "rules-fallback"
        if advisor:
            try:
                code_ids = await advisor.order(code_ids, request.scenario, request.language)
                mode = "ai-prioritized"
            except (httpx.HTTPError, TimeoutError, ValueError, TypeError, KeyError, IndexError):
                pass
    steps = [START[request.scenario].step("start", request.language)]
    steps.extend(EVIDENCE[code].step(code, request.language) for code in code_ids)
    steps.append(VERIFY[request.scenario].step("verify", request.language))
    scope = (
        "ये कदम चुने गए संकेतों पर आधारित हैं। इनसे ऐप के व्यवहार या खाते की सुरक्षा की पुष्टि नहीं होती।"
        if request.language == "hi" else
        "These steps use the selected evidence. They cannot confirm app behavior or account recovery."
    )
    return Guidance(mode=mode, language=request.language, steps=steps, scope=scope)
