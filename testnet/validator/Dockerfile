FROM daturaai/compute-subnet-validator:latest

WORKDIR /opt/testnet

COPY mock_validator.py ./mock_validator.py
COPY templates ./templates

RUN pip install --no-cache-dir uvicorn bittensor cryptography asyncssh

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "uvicorn", "mock_validator:app", "--host", "0.0.0.0", "--port", "8080"]
