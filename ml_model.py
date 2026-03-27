import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest

# ── CONFIG ───────────────────────────────────────────────────────────────────
DATASET_PATH = "anomalyfi_dataset.csv"
MODEL_PATH   = "model.pkl"
THRESHOLD    = 70


# ── STEP 1: TRAIN AND SAVE MODEL ─────────────────────────────────────────────
def train_model():
    """
    Trains Isolation Forest on dataset and saves model.pkl.
    Only needs to run ONCE. After that, model.pkl is loaded directly.
    """
    data = pd.read_csv(DATASET_PATH)

    # ── FEATURE ENGINEERING ──────────────────────────────────────────────────
    data['copy_rate'] = data['files_copied'] / data['session_duration']
    data['delete_rate'] = data['files_deleted'] / data['session_duration']
    data['access_rate'] = data['files_accessed'] / data['session_duration']
    data['activity_rate'] = (
        data['files_accessed'] + data['files_deleted'] + data['files_copied']
    ) / data['session_duration']

    data['is_idle'] = ((data['activity_rate'] == 0) & 
                       (data['session_duration'] > 60)).astype(int)

    # ── FEATURES USED BY MODEL ───────────────────────────────────────────────
    X = data[['login_time', 'files_accessed', 'files_deleted',
              'files_copied', 'session_duration',
              'copy_rate', 'delete_rate', 'access_rate',
              'activity_rate', 'is_idle']]

    model = IsolationForest(
        n_estimators=100,
        contamination='auto',
        random_state=42
    )
    model.fit(X)

    joblib.dump(model, MODEL_PATH)
    print(f"[OK] Model trained and saved → {MODEL_PATH}")
    return model


# ── STEP 2: LOAD MODEL ───────────────────────────────────────────────────────
def load_model():
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"[OK] Model loaded → {MODEL_PATH}")
    else:
        print("[..] No model.pkl found, training now...")
        model = train_model()
    return model


# ── STEP 3: SCORE CONVERSION ─────────────────────────────────────────────────
def convert_to_its(raw_score):
    its = (1 - (raw_score + 0.5)) * 100
    its = max(0.0, min(100.0, its))
    return round(its, 2)


# ── STEP 4: LOAD MODEL ONCE ──────────────────────────────────────────────────
_model = load_model()


# ── STEP 5: PREDICT FUNCTION ─────────────────────────────────────────────────
def get_its_score(login_time, files_accessed, files_deleted,
                  files_copied, session_duration):

    # ── FEATURE ENGINEERING FOR NEW INPUT ────────────────────────────────────
    copy_rate = files_copied / session_duration if session_duration != 0 else 0
    delete_rate = files_deleted / session_duration if session_duration != 0 else 0
    access_rate = files_accessed / session_duration if session_duration != 0 else 0
    activity_rate = (
        files_accessed + files_deleted + files_copied
    ) / session_duration if session_duration != 0 else 0

    is_idle = 1 if activity_rate == 0 and session_duration > 60 else 0

    input_data = pd.DataFrame([{
        'login_time'      : login_time,
        'files_accessed'  : files_accessed,
        'files_deleted'   : files_deleted,
        'files_copied'    : files_copied,
        'session_duration': session_duration,
        'copy_rate'       : copy_rate,
        'delete_rate'     : delete_rate,
        'access_rate'     : access_rate,
        'activity_rate'   : activity_rate,
        'is_idle'         : is_idle
    }])

    raw_score = _model.decision_function(input_data)[0]
    its_score = convert_to_its(raw_score)

    # ── RISK CLASSIFICATION ──────────────────────────────────────────────────
    if its_score >= THRESHOLD:
        risk = "HIGH"
    elif its_score >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return its_score, risk


# ── QUICK TEST ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n── Testing NORMAL session ──")
    score, risk = get_its_score(
        login_time=10, files_accessed=12,
        files_deleted=1, files_copied=3, session_duration=60
    )
    print(f"ITS Score : {score}")
    print(f"Risk Level: {risk}")

    print("\n── Testing FAST COPY anomaly ──")
    score, risk = get_its_score(
        login_time=14, files_accessed=10,
        files_deleted=0, files_copied=20, session_duration=2
    )
    print(f"ITS Score : {score}")
    print(f"Risk Level: {risk}")

    print("\n── Testing IDLE anomaly ──")
    score, risk = get_its_score(
        login_time=11, files_accessed=0,
        files_deleted=0, files_copied=0, session_duration=120
    )
    print(f"ITS Score : {score}")
    print(f"Risk Level: {risk}")