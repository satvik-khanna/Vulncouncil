FROM node:24-slim AS ui
WORKDIR /ui
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY app /app/app
COPY agents /app/agents
COPY tools /app/tools
COPY schemas /app/schemas
COPY lab_target /app/lab_target
COPY config /app/config
COPY --from=ui /ui/dist /app/frontend/dist
COPY frontend/package-lock.json /app/frontend/package-lock.json
RUN mkdir -p data && chown -R 65534:65534 data
USER 65534:65534
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

