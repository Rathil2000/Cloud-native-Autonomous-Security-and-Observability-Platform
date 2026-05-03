FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY models.py serve.py ./

# Create models directory
RUN mkdir -p models

# Train models at build time (uses synthetic data)
COPY train.py .
RUN python train.py

EXPOSE 8080

CMD ["uvicorn", "serve:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2"]
