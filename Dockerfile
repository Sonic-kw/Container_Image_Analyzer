# Używamy stabilnego Pythona
FROM python:3.11-slim

# Wersja Trivy jest przypięta i musi być zapisana w pracy (wpływa na wyniki skanów).
# Uwaga: aquasecurity/trivy usuwa binaria starych wydań z GitHub Releases - tagi gita
# zostają, ale pliki nie. Wersji z serii 0.4x nie da się już pobrać.
ARG TRIVY_VERSION=v0.74.0

# curl jest potrzebny wyłącznie do instalacji Trivy
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Instalacja Trivy. Jawna weryfikacja, bo obraz bez skanera byłby wykrywalny
# dopiero w trakcie kampanii skanowania.
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin "${TRIVY_VERSION}" \
    && trivy --version

# Katalog roboczy
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


# Domyślnie kontener będzie czekał na polecenie (interaktywny)
CMD ["bash"]
