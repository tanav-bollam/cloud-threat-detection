FROM python:3.12-slim

# Free/open-source stack only. No AWS credentials or account are used or needed.
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements-runtime.txt .
RUN pip install -r requirements-runtime.txt

COPY app ./app
COPY src ./src
COPY config ./config
COPY rules ./rules
COPY demo ./demo
COPY .streamlit ./.streamlit
COPY reports ./reports
COPY docs ./docs

# Runtime state (live database, saved settings, suppressions) lives here so it can be a volume.
RUN mkdir -p /app/data
ENV CTD_DB=/app/data/live.duckdb CTD_SETTINGS=/app/data/settings.json CTD_SUPPRESSIONS=/app/data/suppressions.json \
    CTD_SPEED=120 CTD_SCALE=0.3 CTD_DAYS=2

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=4).status==200 else 1)"
CMD ["streamlit", "run", "app/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
