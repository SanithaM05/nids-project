# Base image
FROM python:3.10

# Set working directory
WORKDIR /app

# Copy files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir scapy pandas scikit-learn streamlit joblib

# Expose port for dashboard
EXPOSE 8501

# Run dashboard
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]