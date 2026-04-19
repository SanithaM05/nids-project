# Use Python image
FROM python:3.10

# Set working directory
WORKDIR /app

# Copy files
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port (for Streamlit)
EXPOSE 8501

# Run app
CMD ["streamlit", "run", "app.py"]