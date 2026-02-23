FROM python:3.11-slim

WORKDIR /app

# Copy source first
COPY prompt_guard/ prompt_guard/
COPY pyproject.toml .

# Install prompt-guard from local source
RUN pip install --no-cache-dir -e .

# Install FastAPI and uvicorn
RUN pip install --no-cache-dir fastapi uvicorn pydantic

# Copy app
COPY app.py .

# Expose port
EXPOSE 8080

# Run
CMD ["python", "app.py"]
