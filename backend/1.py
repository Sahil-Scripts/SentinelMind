python - << 'PY'
import os
print("API_KEY set?      ", bool(os.getenv("WATSONX_API_KEY")))
print("PROJECT_ID looks ok:", os.getenv("WATSONX_PROJECT_ID"))
print("BASE_URL:         ", os.getenv("WATSONX_BASE_URL"))
print("MODEL_ID:         ", os.getenv("WATSONX_MODEL_ID"))
PY
