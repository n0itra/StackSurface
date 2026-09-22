# ---- Build stage: compile Go-based recon/scan tools ----
FROM golang:latest AS toolbuilder

# إضافة بروكسي لتخطي مشاكل الشبكة وانقطاع التحميل في خوادم Go
ENV GOPROXY=https://goproxy.io,direct
ENV CGO_ENABLED=0

RUN apt-get -o Acquire::ForceIPv4=true update && apt-get -o Acquire::ForceIPv4=true install -y --no-install-recommends \
    ca-certificates curl git build-essential unzip \
    && rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6
RUN go install -v github.com/tomnomnom/assetfinder@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.8
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.7
RUN go install -v github.com/lc/gau/v2/cmd/gau@v2.2.4

RUN curl -sL https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_amd64.zip -o katana.zip \
    && unzip katana.zip -d /go/bin/ \
    && rm katana.zip

RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1
RUN go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@v1.1.9
RUN go install -v github.com/projectdiscovery/alterx/cmd/alterx@v0.0.6

RUN curl -sL https://github.com/trufflesecurity/trufflehog/releases/download/v3.82.6/trufflehog_3.82.6_linux_amd64.tar.gz -o trufflehog.tar.gz \
    && tar -xzf trufflehog.tar.gz trufflehog \
    && mv trufflehog /go/bin/ \
    && rm trufflehog.tar.gz

RUN go install -v github.com/d3mondev/puredns/v2@latest

# jsluice depends on go-tree-sitter
RUN CGO_ENABLED=1 go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest

RUN echo "GOPATH is: $(go env GOPATH)" && \
    for bin in subfinder assetfinder httpx nuclei katana dnsx cdncheck alterx trufflehog jsluice puredns gau; do \
        test -x "$(go env GOPATH)/bin/$bin" || (echo "MISSING BINARY: $bin" && exit 1); \
    done

# massdns for bulk DNS resolution
RUN git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns \
    && cd /tmp/massdns && make \
    && cp bin/massdns /go/bin/massdns \
    && test -x /go/bin/massdns || (echo "MISSING BINARY: massdns" && exit 1)

# feroxbuster ships as a prebuilt Rust binary
RUN curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash \
    && mv ./feroxbuster /go/bin/feroxbuster \
    && test -x /go/bin/feroxbuster || (echo "MISSING BINARY: feroxbuster" && exit 1)

# findomain ships as a prebuilt Linux binary release
RUN curl -sL https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip -o /tmp/findomain.zip \
    && cd /tmp && unzip -o findomain.zip \
    && mv findomain /go/bin/findomain && chmod +x /go/bin/findomain \
    && test -x /go/bin/findomain || (echo "MISSING BINARY: findomain" && exit 1)


# ---- Runtime stage ----
FROM python:3.12.7-slim

# ضفنا git هنا عشان waymore أحياناً بيحتاجها تسحب ملفات
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl procps unzip git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. تثبيت مكتبات البايثون بالإضافة لـ waymore
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 'httpx[cli]' waymore

# 2. نسخ أدوات الفحص
COPY --from=toolbuilder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=toolbuilder /go/bin/assetfinder /usr/local/bin/assetfinder
COPY --from=toolbuilder /go/bin/findomain /usr/local/bin/findomain
COPY --from=toolbuilder /go/bin/httpx /usr/local/bin/httpx
COPY --from=toolbuilder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=toolbuilder /go/bin/katana /usr/local/bin/katana
COPY --from=toolbuilder /go/bin/dnsx /usr/local/bin/dnsx
COPY --from=toolbuilder /go/bin/cdncheck /usr/local/bin/cdncheck
COPY --from=toolbuilder /go/bin/alterx /usr/local/bin/alterx
COPY --from=toolbuilder /go/bin/puredns /usr/local/bin/puredns
COPY --from=toolbuilder /go/bin/massdns /usr/local/bin/massdns
COPY --from=toolbuilder /go/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=toolbuilder /go/bin/jsluice /usr/local/bin/jsluice
COPY --from=toolbuilder /go/bin/feroxbuster /usr/local/bin/feroxbuster
COPY --from=toolbuilder /go/bin/gau /usr/local/bin/gau

# إعطاء صلاحيات التشغيل لكل الأدوات عشان نحل مشكلة massdns
RUN chmod +x /usr/local/bin/*

# Small, bounded wordlist for feroxbuster
COPY wordlist-small.txt /usr/local/share/wordlist-small.txt

# Trusted public resolvers for puredns's bulk resolution step
COPY resolvers-small.txt /usr/local/share/resolvers-small.txt

COPY app ./app

RUN useradd --create-home --shell /usr/sbin/nologin scanner \
    && mkdir -p /scans \
    && chown -R scanner:scanner /app /scans

ENV HOME=/home/scanner

# Pre-fetch nuclei's detection templates at build time
RUN nuclei -update-templates -ut -silent || true \
    && chown -R scanner:scanner /home/scanner

USER scanner

CMD ["sh", "-c", "python -u $(find /app -name worker.py | head -n 1)"]
