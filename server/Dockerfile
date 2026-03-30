FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train the model during image build if model.pkl isn't committed
RUN python train_model.py

EXPOSE 8000 9999

# Start the FastAPI server (adjust the command if your entrypoint differs)
CMD ["python", "main.py"]