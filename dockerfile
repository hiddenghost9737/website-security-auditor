# Python 3.9 image use
FROM python:3.9-slim

# Working directory set
WORKDIR /usr/src/app

# Dependencies install
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Code copy
COPY . .

# Actor run command
CMD ["python3", "main.py"]
