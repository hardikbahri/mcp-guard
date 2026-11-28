FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY mcp_guard ./mcp_guard
COPY demo ./demo
COPY policies ./policies
RUN pip install --no-cache-dir . && useradd --create-home guard && mkdir -p /var/log/mcp-guard && chown guard /var/log/mcp-guard
USER guard
ENV MCP_GUARD_POLICY=/app/policies/complaintops.yaml \
    MCP_GUARD_AUDIT_LOG=/var/log/mcp-guard/audit.jsonl
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"
# HTTP policy decision point by default; `docker run -i ... mcp-guard proxy` runs the stdio gateway instead
ENTRYPOINT ["mcp-guard"]
CMD ["api", "--host", "0.0.0.0", "--port", "8080"]
