"""
Sprint 2 - Task 2.2: ThreatDetector (fixed)

Changes from v1:
  - _preprocess() now returns a named DataFrame so sklearn stops warning
    about missing feature names.
  - Added _apply_heuristics() to catch cases the ML model misses due to the
    fundamental feature mismatch between NSL-KDD (session-level bytes) and
    live single-packet capture. Production IDS systems always layer rules on
    top of ML for exactly this reason.
"""

import pickle
import pandas as pd

MODEL_PATH = "model.pkl"

# Must match encoding used in train_model.py
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}

# Feature column order must match what the model was trained on
FEATURE_COLUMNS = ["duration", "protocol_type", "src_bytes", "dst_bytes"]

# ── Heuristic rules ──────────────────────────────────────────────────────────
# These catch cases where the NSL-KDD feature mapping is too lossy for the
# ML model to decide correctly on its own.

# Ports strongly associated with malware C2, reverse shells, or attack tools
SUSPICIOUS_PORTS = {
    4444,   # Metasploit default
    1337,   # leet — common backdoor
    31337,  # Back Orifice
    6667,   # IRC botnet C2
    6666,
    9001,   # Tor / Cobalt Strike
    8888,   # common RAT port
    12345,  # NetBus
    27374,  # Sub7
}

# Packet sizes that suggest flooding (single packets should never be this large
# in normal traffic — jumbo frames top out at ~9000 bytes on most networks)
FLOOD_SIZE_THRESHOLD = 9001   # bytes


class ThreatDetector:
    """
    Classifies incoming packet dicts as Benign or Malicious using a
    combination of a trained Random Forest model and fast rule-based heuristics.

    Decision logic (in order):
      1. Heuristics: if a rule fires → Malicious immediately (high confidence)
      2. ML model: final say when no rule fires
    """

    def __init__(self):
        self.model = None

    # ── Public API ──────────────────────────────────────────────────────────

    def load_model(self, path: str = MODEL_PATH) -> None:
        """Loads the pickled RandomForest model from disk."""
        try:
            with open(path, "rb") as f:
                self.model = pickle.load(f)
            print(f"[+] ThreatDetector: model loaded from '{path}'")
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Model file not found at '{path}'. "
                "Run train_model.py first to generate it."
            )

    def predict(self, packet_data: dict) -> tuple[str, float]:
        """
        Classifies a packet dictionary.

        Args:
            packet_data: dict with keys src_ip, dst_ip, protocol, size, dst_port

        Returns:
            (label, confidence) — label is 'Benign' or 'Malicious',
            confidence is the model's (or heuristic's) probability (0-1).
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")

        # Step 1: rule-based fast path
        heuristic_result = self._apply_heuristics(packet_data)
        if heuristic_result is not None:
            return heuristic_result

        # Step 2: ML model
        features_df  = self._preprocess(packet_data)
        prediction   = self.model.predict(features_df)[0]
        probability  = self.model.predict_proba(features_df)[0]

        label      = "Malicious" if prediction == 1 else "Benign"
        confidence = float(probability[prediction])
        return label, confidence

    # ── Private helpers ─────────────────────────────────────────────────────

    def _apply_heuristics(self, packet_data: dict) -> tuple[str, float] | None:
        """
        Fast rule-based pre-filter. Returns (label, confidence) if a rule
        fires, or None to fall through to the ML model.

        Why this exists:
          NSL-KDD is session-level data (total bytes per connection). A single
          65,535-byte packet doesn't look anomalous to a model trained on
          session totals. Rules give us reliable signal for the obvious cases.
        """
        size     = packet_data.get("size", 0)
        dst_port = packet_data.get("dst_port", 0)

        # Rule 1: packet size far exceeds normal traffic
        # (jumbo frames top out at ~9000 bytes; anything beyond that is a flood)
        if size >= FLOOD_SIZE_THRESHOLD:
            return ("Malicious", 0.97)

        # Rule 2: destination port is a known malware/attack port
        if dst_port in SUSPICIOUS_PORTS:
            return ("Malicious", 0.91)

        return None  # no rule fired — let the ML model decide

    def _preprocess(self, packet_data: dict) -> pd.DataFrame:
        """
        Maps the agent's packet dict to the 4-feature DataFrame the model
        expects: [duration, protocol_type, src_bytes, dst_bytes]

        Returning a named DataFrame (not a raw numpy array) eliminates the
        sklearn "X does not have valid feature names" UserWarning.
        """
        protocol_str  = packet_data.get("protocol", "")
        protocol_code = PROTOCOL_MAP.get(str(protocol_str).upper(), -1)

        return pd.DataFrame(
            [[0, protocol_code, packet_data.get("size", 0), 0]],
            columns=FEATURE_COLUMNS,
        )
