#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

VIRTUOSO_CONTAINER="${VIRTUOSO_CONTAINER:-virtuoso}"
VIRTUOSO_DB_PATH="${VIRTUOSO_DB_PATH:-/database}"
ISQL="${ISQL:-/opt/virtuoso-opensource/bin/isql}"
DBA_PASSWORD="${DBA_PASSWORD:-dba}"
TARGET_GRAPH="${SEPSES_LOCAL_GRAPH:-http://sepses.local}"
DUMP_DIR="${DUMP_DIR:-data/cskg_dumps}"

isql_exec() { docker exec -i "${VIRTUOSO_CONTAINER}" "${ISQL}" 1111 dba "${DBA_PASSWORD}" "exec=$1"; }

echo "======================================"
echo " SEPSES RDF Loader for Virtuoso"
echo " Container   : ${VIRTUOSO_CONTAINER}"
echo " Target graph: ${TARGET_GRAPH}"
echo " Dump dir    : ${DUMP_DIR}"
echo "======================================"

if ! docker ps --format '{{.Names}}' | grep -qx "${VIRTUOSO_CONTAINER}"; then
  echo "ERROR: container '${VIRTUOSO_CONTAINER}' tidak berjalan. Jalankan: docker compose up -d" >&2
  exit 1
fi

# 1) Tunggu Virtuoso siap (isql status()).
echo -n "Menunggu Virtuoso siap"
for _ in $(seq 1 40); do
  if isql_exec "status();" >/dev/null 2>&1; then echo " -> siap."; break; fi
  echo -n "."; sleep 2
done
if ! isql_exec "status();" >/dev/null 2>&1; then
  echo " -> GAGAL: Virtuoso tidak merespons isql." >&2
  exit 1
fi

rdf_files=( "${DUMP_DIR}"/*.ttl "${DUMP_DIR}"/*.turtle )
if [ ${#rdf_files[@]} -eq 0 ]; then
  echo "Tidak ada file *.ttl / *.turtle di ${DUMP_DIR}." >&2
  echo "Catatan: dump CVE & CPE besar dan TIDAK ikut di-commit (lihat .gitignore)." >&2
  echo "Untuk cakupan CVE penuh, unduh dump CVE/CPE SEPSES ke ${DUMP_DIR}/ lalu jalankan ulang." >&2
  exit 0
fi

for rdf_file in "${rdf_files[@]}"; do
  filename="$(basename "$rdf_file")"
  echo ""
  echo "--------------------------------------"
  echo "Loading: ${filename}  ->  ${TARGET_GRAPH}"
  echo "--------------------------------------"
  docker cp "$rdf_file" "${VIRTUOSO_CONTAINER}:${VIRTUOSO_DB_PATH}/${filename}"
  isql_exec "ld_dir('${VIRTUOSO_DB_PATH}', '${filename}', '${TARGET_GRAPH}'); rdf_loader_run(); checkpoint;"
  echo "Selesai: ${filename}"
done

echo ""
echo "Cek error loader (kosong = sukses):"
isql_exec "SELECT ll_file, ll_error FROM DB.DBA.LOAD_LIST WHERE ll_error IS NOT NULL;" || true

echo ""
echo "Jumlah triple di ${TARGET_GRAPH}:"
isql_exec "SPARQL SELECT COUNT(*) WHERE { GRAPH <${TARGET_GRAPH}> { ?s ?p ?o } };"

echo ""
echo "Selesai. Endpoint lokal: http://localhost:8890/sparql"
