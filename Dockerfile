FROM python:3.8
WORKDIR /usr/app/
COPY . .
RUN pip install --no-cache-dir -r ./requirements.txt
CMD ["python" , "./main.py", "--full"]