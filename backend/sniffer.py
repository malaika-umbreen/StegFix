from model_detector import predict_flow

# Example test input (replace with real features later)
feature_dict = {
    "duration": 5.0,
    "iat_mean": 0.2,
    "iat_std": 0.1
}

label, technique = predict_flow(feature_dict)

if label == 1:
    print(f"🚨 COVERT DETECTED | Technique: {technique}")
else:
    print("✅ NORMAL TRAFFIC")