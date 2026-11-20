# Obraz aplikacji-sondy na zadanej bazie (badanie uzupelniajace).
# BASE to adres obrazu bazowego wskazany digestem, ten sam co w kampanii
# (results/scans.jsonl, grupa library/python:3.13:-:debian13).
ARG BASE
FROM ${BASE}

# Bez plikow .pyc, zeby aplikacja dzialala takze z systemem plikow tylko do odczytu.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY app.py /app/app.py

EXPOSE 8080

# Postac wektorowa, bo distroless nie ma powloki.
ENTRYPOINT ["python3", "/app/app.py"]
