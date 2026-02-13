from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier

MODEL_PATH = Path(__file__).resolve().parent / "model.pkl"


def _training_data():
    samples = [
        [18, 1, 0, 0, 1, 0],
        [22, 2, 0, 0, 1, 1],
        [15, 1, 0, 0, 1, 0],
        [28, 3, 1, 0, 0, 3],
        [35, 4, 0, 1, 0, 4],
        [40, 4, 1, 1, 0, 5],
        [30, 3, 0, 0, 0, 3],
        [26, 2, 0, 0, 1, 2],
        [55, 5, 1, 1, 0, 6],
        [65, 6, 1, 1, 0, 7],
        [20, 1, 0, 0, 1, 0],
        [45, 4, 1, 0, 0, 4],
    ]
    labels = [0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1]
    return samples, labels


def _train_and_save_model() -> RandomForestClassifier:
    X, y = _training_data()
    model = RandomForestClassifier(n_estimators=150, random_state=42)
    model.fit(X, y)
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
