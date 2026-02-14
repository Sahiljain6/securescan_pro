from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier

MODEL_PATH = Path(__file__).with_name("model.pkl")


def _training_data():
    samples = [
        [18, 2, 0, 0, 1, 0],
        [23, 2, 0, 0, 1, 1],
        [30, 3, 0, 0, 1, 2],
        [72, 5, 1, 1, 0, 8],
        [68, 6, 1, 1, 0, 7],
        [60, 5, 1, 1, 0, 6],
        [54, 5, 1, 1, 0, 5],
        [24, 2, 0, 0, 1, 1],
        [52, 4, 1, 0, 0, 4],
        [61, 5, 1, 1, 0, 7],
        [27, 2, 0, 0, 1, 2],
        [59, 6, 1, 1, 0, 8],
    ]
    labels = [0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1]
    return samples, labels


def _train_and_save_model() -> RandomForestClassifier:
    features, labels = _training_data()
    model = RandomForestClassifier(n_estimators=150, random_state=42)
    model.fit(features, labels)
    joblib.dump(model, MODEL_PATH)
    return model


def get_model() -> RandomForestClassifier:
    if not MODEL_PATH.exists():
        return _train_and_save_model()

    try:
        model = joblib.load(MODEL_PATH)
        if not hasattr(model, "predict_proba"):
            return _train_and_save_model()
        return model
    except Exception:
        return _train_and_save_model()
