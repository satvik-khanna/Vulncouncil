FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.143.0 uvicorn==0.54.0 pydantic==2.14.0
COPY schemas /app/schemas
COPY lab_target /app/lab_target
USER 65534:65534
EXPOSE 8001
CMD ["uvicorn", "lab_target.app:app", "--host", "0.0.0.0", "--port", "8001"]

