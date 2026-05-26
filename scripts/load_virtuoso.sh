#!/bin/bash

VIRTUOSO_CONTAINER="virtuoso"
VIRTUOSO_DB_PATH="/opt/virtuoso-opensource/database"
ISQL="/opt/virtuoso-opensource/bin/isql"

echo "======================================"
echo " SEPSES RDF Loader for Virtuoso "
echo "======================================"

# Loop semua file .ttl di folder data
for ttlfile in data/*.ttl
do
    filename=$(basename "$ttlfile")
    shortname="${filename%.ttl}"

    graphfile="data/${shortname}.ttl.graph"

    # cek file graph ada atau tidak
    if [ ! -f "$graphfile" ]; then
        echo "Skipping $filename (missing .graph file)"
        continue
    fi

    # baca graph URI
    graphuri=$(cat "$graphfile")

    echo ""
    echo "--------------------------------------"
    echo "Loading: $filename"
    echo "Graph  : $graphuri"
    echo "--------------------------------------"

    # copy ttl ke container
    docker cp "$ttlfile" \
    ${VIRTUOSO_CONTAINER}:${VIRTUOSO_DB_PATH}/${filename}

    # load rdf ke virtuoso
    docker exec ${VIRTUOSO_CONTAINER} \
    ${ISQL} 1111 dba dba exec="
    ld_dir('${VIRTUOSO_DB_PATH}', '${filename}', '${graphuri}');
    rdf_loader_run();
    checkpoint;
    "

    echo "Finished loading $filename"

done

echo ""
echo "======================================"
echo " All RDF dumps loaded successfully "
echo "======================================"