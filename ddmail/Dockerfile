# Use Python 3.11 base image
FROM python:3.11-slim

# Set work directory
WORKDIR /app

# Copy dependencies files
COPY requirements.txt ./

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    pkg-config \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose Flask app port
EXPOSE 8000

# Set environment variables for Flask
ENV MODE=DEVELOPMENT

# Run Flask app
CMD ["flask", "--app", "ddmail:create_app", "run", "--host=0.0.0.0", "--port", "8000", "--debug"]
