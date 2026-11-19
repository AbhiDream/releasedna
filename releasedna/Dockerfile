FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt && pip check
COPY backend/ ./backend/
COPY frontend/ ./frontend/
RUN mkdir /app/data && chown 65534:65534 /app/data
WORKDIR /app/backend
# Fail the image build if the trusted application's offline regression suite fails.
RUN python -m unittest discover -s tests -v
USER 65534:65534
EXPOSE 8000
CMD ["python", "-m", "app.container_start"]
