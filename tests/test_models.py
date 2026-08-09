import sys, os, numpy as np, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from pathlib import Path

MODELS_DIR = Path.home() / "Dissertation__" / "models" / "saved"

def test_models_exist():
    for f in ["rf_final.pkl","scaler_final.pkl","threshold_final.npy","autoencoder_final.keras"]:
        assert (MODELS_DIR/f).exists(), f"Missing: {f}"

def test_rf_prediction_shape():
    import joblib
    rf = joblib.load(MODELS_DIR/"rf_final.pkl")
    scaler = joblib.load(MODELS_DIR/"scaler_final.pkl")
    X = np.random.randn(10, rf.n_features_in_).astype(np.float32)
    preds = rf.predict(scaler.transform(X))
    assert preds.shape == (10,)
    assert set(preds).issubset({0,1})

def test_threshold_positive():
    threshold = float(np.load(MODELS_DIR/"threshold_final.npy"))
    assert threshold > 0

def test_hybrid_verdict_logic():
    def classify(rf_pred, anomaly):
        if rf_pred==1 and anomaly: return "CONFIRMED_ATTACK"
        if rf_pred==1: return "KNOWN_ATTACK"
        if anomaly: return "ZERO_DAY"
        return "BENIGN"
    valid = {"CONFIRMED_ATTACK","KNOWN_ATTACK","ZERO_DAY","BENIGN"}
    for rf_p in [0,1]:
        for anom in [True,False]:
            assert classify(rf_p,anom) in valid

if __name__ == "__main__":
    pytest.main([__file__,"-v"])
