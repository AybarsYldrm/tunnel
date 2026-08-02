#!/usr/bin/env bash
# Test PKI üretir. SADECE GELİŞTİRME/TEST İÇİNDİR — üretimde kullanmayın.
#
#   certs/ca.crt          kök CA (her iki tarafa `ca:` olarak verilir)
#   certs/inter.crt       ara CA (kök tarafından imzalı, pathlen:0)
#   certs/inter-chain.pem sunucu zinciri: leaf + ara CA  (kök YOK)
#   certs/inter-leaf.crt  ara CA'nın imzaladığı sunucu sertifikası
#   certs/server.crt      kökün doğrudan imzaladığı sunucu sertifikası
#   certs/client.crt      istemci sertifikası (mTLS, CN=dtls-client)
#   certs/revoked.crt     iptal senaryoları için ikinci bir istemci sertifikası
#   certs/server.pem      kendinden imzalı tekil sertifika (parmak izi senaryoları)
#
# TASARIM NOTU — bu betik ESKİDEN her dosya için "yoksa üret" diyordu. Bu,
# dosyaların BİR KISMI silindiğinde (ör. ca.key gitti ama ca.crt kaldı)
# birbiriyle uyuşmayan bir PKI üretiyordu: yeni bir CA anahtarı üretilip eski
# CA sertifikası korunuyor, sonra da "sertifika doğrulaması başarısız" diyen
# ONLARCA test hatası çıkıyordu — sebebi koda değil, certs/ dizinine bakmadan
# anlaşılamıyordu. Artık demet BÜTÜN olarak doğrulanır; tutarsızsa (ya da
# --force verilirse) baştan üretilir.

set -euo pipefail
DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
DAYS="${DTLS_CERT_DAYS:-825}"
CURVE="${DTLS_CERT_CURVE:-prime256v1}"

# OCSP/CRL testleri bu adresleri sertifikalara gömer (AIA / CDP uzantıları).
OCSP_URL="${DTLS_OCSP_URL:-http://127.0.0.1:8888/ocsp}"
CRL_URL="${DTLS_CRL_URL:-http://127.0.0.1:8888/crl}"

FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE=1 ;;
    --help|-h)
      sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "bilinmeyen seçenek: $arg" >&2; exit 2 ;;
  esac
done

mkdir -p "$DIR"
cd "$DIR"

# ---------------------------------------------------------------- doğrulama
# Demet TUTARLI MI? (dosyalar var + anahtarlar sertifikalarla eşleşiyor +
# imza zinciri kuruluyor + beklenen SAN'lar yerinde)
pubkey_of_key()  { openssl pkey -in "$1" -pubout 2>/dev/null; }
pubkey_of_cert() { openssl x509 -in "$1" -noout -pubkey 2>/dev/null; }

bundle_ok() {
  local f
  for f in ca.key ca.crt inter.key inter.crt inter-leaf.crt inter-chain.pem \
           server.key server.crt client.key client.crt revoked.crt server.pem; do
    [[ -f "$f" ]] || { echo "eksik: $f"; return 1; }
  done

  # anahtar ↔ sertifika eşleşmesi
  [[ "$(pubkey_of_key ca.key)"     == "$(pubkey_of_cert ca.crt)"     ]] || { echo "ca.key ↔ ca.crt uyuşmuyor";     return 1; }
  [[ "$(pubkey_of_key inter.key)"  == "$(pubkey_of_cert inter.crt)"  ]] || { echo "inter.key ↔ inter.crt uyuşmuyor"; return 1; }
  [[ "$(pubkey_of_key server.key)" == "$(pubkey_of_cert server.crt)" ]] || { echo "server.key ↔ server.crt uyuşmuyor"; return 1; }
  [[ "$(pubkey_of_key client.key)" == "$(pubkey_of_cert client.crt)" ]] || { echo "client.key ↔ client.crt uyuşmuyor"; return 1; }

  # imza zincirleri
  openssl verify -CAfile ca.crt server.crt >/dev/null 2>&1 || { echo "server.crt kök CA ile doğrulanamıyor"; return 1; }
  openssl verify -CAfile ca.crt client.crt >/dev/null 2>&1 || { echo "client.crt kök CA ile doğrulanamıyor"; return 1; }
  openssl verify -CAfile ca.crt -untrusted inter.crt inter-leaf.crt >/dev/null 2>&1 \
    || { echo "inter-leaf.crt ara CA zinciriyle doğrulanamıyor"; return 1; }

  # testlerin dayandığı kimlik alanları
  openssl x509 -in server.crt -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:dtls.local' \
    || { echo "server.crt içinde 'dtls.local' SAN'ı yok"; return 1; }
  openssl x509 -in client.crt -noout -subject | grep -q 'dtls-client' \
    || { echo "client.crt CN'i 'dtls-client' değil"; return 1; }
  return 0
}

if [[ $FORCE -eq 0 ]] && reason="$(bundle_ok)"; then
  echo "[gen-certs] mevcut PKI tutarlı — yeniden üretilmedi (--force ile zorlayabilirsiniz)"
  SKIP_GEN=1
else
  if [[ $FORCE -eq 1 ]]; then
    echo "[gen-certs] --force: PKI baştan üretiliyor"
  else
    echo "[gen-certs] mevcut PKI kullanılamıyor (${reason:-tutarsız}) — baştan üretiliyor"
  fi
  SKIP_GEN=0
fi

if [[ ${SKIP_GEN} -eq 0 ]]; then
  # KISMİ durum bırakmamak için hepsini birlikte tazeleriz.
  rm -f ca.key ca.crt ca.srl inter.key inter.crt inter.srl inter-leaf.crt \
        inter-chain.pem server.key server.crt client.key client.crt \
        revoked.key revoked.crt server.pem ./*.csr ./*.ext

  gen_key() { openssl ecparam -name "$CURVE" -genkey -noout -out "$1"; }

  # -------------------------------------------------------------- kök CA
  echo "[gen-certs] kök CA üretiliyor..."
  gen_key ca.key
  openssl req -new -x509 -key ca.key -out ca.crt -days "$DAYS" -sha256 \
    -subj "/CN=node-dtls Test Root CA/O=node-dtls" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

  # -------------------------------------------------------------- ara CA
  echo "[gen-certs] ara CA üretiliyor..."
  gen_key inter.key
  openssl req -new -key inter.key -out inter.csr -subj "/CN=node-dtls Test Intermediate CA/O=node-dtls"
  cat > inter.ext <<EOF
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  openssl x509 -req -in inter.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out inter.crt -days "$DAYS" -sha256 -extfile inter.ext

  # ------------------------------------------------- sunucu (kök imzalı)
  echo "[gen-certs] sunucu sertifikası (kök imzalı) üretiliyor..."
  gen_key server.key
  openssl req -new -key server.key -out server.csr -subj "/CN=localhost/O=node-dtls"
  cat > server.ext <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:dtls.local, IP:127.0.0.1, IP:::1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "$DAYS" -sha256 -extfile server.ext

  # ------------------------------------------- sunucu (ara CA imzalı, zincirli)
  echo "[gen-certs] ara CA imzalı sunucu sertifikası + zincir üretiliyor..."
  # Bu sertifika testlerde HEM sunucu HEM istemci rolünde kullanılır; EKU
  # yalnızca serverAuth olsaydı istemci rolünde INVALID_PURPOSE ile reddedilirdi.
  cat > inter-leaf.ext <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:localhost, DNS:dtls.local, IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
  openssl x509 -req -in server.csr -CA inter.crt -CAkey inter.key -CAcreateserial \
    -out inter-leaf.crt -days "$DAYS" -sha256 -extfile inter-leaf.ext
  # TLS'in beklediği sıra: leaf önce, kök YOK (RFC 8446 §4.4.2).
  cat inter-leaf.crt inter.crt > inter-chain.pem

  # ------------------------------------------------------------- istemci
  echo "[gen-certs] istemci sertifikaları üretiliyor..."
  gen_key client.key
  openssl req -new -key client.key -out client.csr -subj "/CN=dtls-client/O=node-dtls"
  cat > client.ext <<EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:dtls-client
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
authorityInfoAccess = OCSP;URI:${OCSP_URL}
crlDistributionPoints = URI:${CRL_URL}
EOF
  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days "$DAYS" -sha256 -extfile client.ext

  # İptal senaryoları için ikinci istemci (aynı anahtar, farklı seri no).
  openssl req -new -key client.key -out revoked.csr -subj "/CN=dtls-revoked-client/O=node-dtls"
  openssl x509 -req -in revoked.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out revoked.crt -days "$DAYS" -sha256 -extfile client.ext
  cp client.key revoked.key

  # ----------------------------------------- kendinden imzalı (WebRTC tarzı)
  echo "[gen-certs] kendinden imzalı sertifika üretiliyor..."
  openssl req -new -x509 -key server.key -out server.pem -days "$DAYS" -sha256 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

  rm -f ./*.csr ./*.ext

  if ! reason="$(bundle_ok)"; then
    echo "[gen-certs] HATA: üretilen PKI doğrulanamadı: $reason" >&2
    exit 1
  fi
fi

echo
echo "[gen-certs] tamam:"
ls -1 "$DIR"
echo
printf 'Kök CA     : %s\n' "$(openssl x509 -in ca.crt         -noout -subject | sed 's/^subject=//')"
printf 'Ara CA     : %s\n' "$(openssl x509 -in inter.crt      -noout -subject | sed 's/^subject=//')"
printf 'Sunucu     : %s\n' "$(openssl x509 -in server.crt     -noout -subject | sed 's/^subject=//')"
printf 'Zincir uçu : %s\n' "$(openssl x509 -in inter-leaf.crt -noout -subject | sed 's/^subject=//')"
printf 'İstemci    : %s\n' "$(openssl x509 -in client.crt     -noout -subject | sed 's/^subject=//')"
printf 'SHA-256    : %s\n' "$(openssl x509 -in server.pem     -noout -fingerprint -sha256 | sed 's/^.*=//')"
