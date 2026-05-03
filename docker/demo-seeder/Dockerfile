FROM python:3.12-slim
RUN pip install --no-cache-dir psycopg2-binary==2.9.9
COPY seed.py /seed.py
CMD ["python", "/seed.py"]
