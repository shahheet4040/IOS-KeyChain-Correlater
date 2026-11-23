import os
from pathlib import Path
import pytest
from PIL import Image, ImageDraw

from correlator.neural_key_scorer import NeuralKeyScorer, extract_key_features
from correlator.neural_semantic_search import (
    SemanticNeuralSearch,
    compute_dense_embedding,
    cosine_similarity,
)
from correlator.neural_lead_triage import NeuralLeadClassifier
from correlator.neural_vision_classifier import (
    NeuralVisionClassifier,
    analyze_image_properties,
)


def test_neural_key_scorer():
    scorer = NeuralKeyScorer()

    # 1. Real 32-byte AES Master Key
    real_aes_key = os.urandom(32)
    score_real = scorer.predict_score(
        real_aes_key,
        service="net.whatsapp.WhatsApp",
        account="db_encryption_key",
        access_group="group.net.whatsapp.WhatsApp.shared",
    )
    assert score_real >= 0.70, f"Expected high score for real AES key, got {score_real}"

    # 2. ASCII OAuth Bearer Token
    token_bytes = b"bearer_token_1234567890abcdef12"
    score_token = scorer.predict_score(
        token_bytes,
        service="com.apple.account.OAuth",
        account="refresh_token",
        access_group="com.apple.token",
    )
    assert score_token <= 0.45, f"Expected low score for token, got {score_token}"

    # 3. Null bytes
    score_null = scorer.predict_score(b"\x00" * 32)
    assert score_null <= 0.20

    # 4. Candidate Ranking
    cands = [
        {"key_bytes": token_bytes, "service": "oauth"},
        {"key_bytes": real_aes_key, "service": "db_key"},
    ]
    ranked = scorer.rank_candidates(cands)
    assert ranked[0]["key_bytes"] == real_aes_key


def test_neural_semantic_search():
    searcher = SemanticNeuralSearch()

    searcher.index_message("msg1", "Wired 50000 dollars to the offshore bank account in Zurich", sender="Bob")
    searcher.index_message("msg2", "Bring the gun and knife to the corner tonight", sender="Alice")
    searcher.index_message("msg3", "The pizza was delicious yesterday", sender="Charlie")

    # Search for financial concept without exact matching keywords
    res_fin = searcher.search("stolen cash crypto payment transaction", top_k=2)
    assert len(res_fin) > 0
    assert res_fin[0]["doc_id"] == "msg1"

    # Search for violence concept
    res_threat = searcher.search("weapons shoot kill attack assault", top_k=2)
    assert len(res_threat) > 0
    assert res_threat[0]["doc_id"] == "msg2"


def test_neural_lead_triage():
    classifier = NeuralLeadClassifier()

    # Financial with Bitcoin wallet
    btc_text = "Please send payment to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq immediately"
    res_btc = classifier.classify_text(btc_text)
    assert res_btc["primary_category"] == "FINANCIAL"
    assert "btc_wallets" in res_btc["entities"]
    assert len(res_btc["entities"]["btc_wallets"]) == 1

    # Credentials exfiltration
    pwd_text = "Here are the login details: password: SecretMasterPass2026!"
    res_pwd = classifier.classify_text(pwd_text)
    assert res_pwd["primary_category"] == "CREDENTIALS"
    assert "extracted_credentials" in res_pwd["entities"]

    # Violence threat
    threat_text = "If you don't bring the cash I will kill you"
    res_threat = classifier.classify_text(threat_text)
    assert res_threat["primary_category"] == "THREATS_VIOLENCE"
    assert res_threat["is_high_priority"] is True


def test_neural_vision_classifier(tmp_path):
    classifier = NeuralVisionClassifier()

    # 1. Synthetic Credit Card / ID (856x540 -> aspect ratio 1.585)
    card_img_path = tmp_path / "credit_card.jpg"
    card = Image.new("RGB", (856, 540), color=(40, 80, 150))
    draw = ImageDraw.Draw(card)
    draw.rectangle([50, 50, 800, 100], fill=(200, 200, 200))
    card.save(card_img_path)

    res_card = classifier.classify_image(card_img_path)
    assert res_card["category"] == "ID_OR_PAYMENT_CARD"

    # 2. Synthetic Smartphone Screenshot (1170x2532 -> ratio ~2.164, iPhone 14)
    screenshot_path = tmp_path / "screenshot.png"
    screen = Image.new("RGB", (1170, 2532), color=(240, 240, 245))
    screen.save(screenshot_path)

    res_screen = classifier.classify_image(screenshot_path)
    assert res_screen["category"] == "SCREENSHOT"

    # 3. Synthetic Document (High brightness white paper with black text lines)
    doc_path = tmp_path / "document.jpg"
    doc = Image.new("RGB", (800, 1000), color=(250, 250, 250))
    draw_doc = ImageDraw.Draw(doc)
    for y in range(100, 900, 40):
        draw_doc.line([(100, y), (700, y)], fill=(0, 0, 0), width=4)
    doc.save(doc_path)

    res_doc = classifier.classify_image(doc_path)
    assert res_doc["category"] == "DOCUMENT"
