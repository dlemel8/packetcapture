if [[ -z ${PFRING_DIR} ]]; then
        echo "please set PFRING_DIR to pfring source dir"
        exit 1
fi
echo "PFRING_DIR: ${PFRING_DIR}"
CGO_CFLAGS="-I${PFRING_DIR}/userland/lib -I${PFRING_DIR}/kernel" CGO_LDFLAGS="-L${PFRING_DIR}/userland/lib" go build packetcapture
echo "DONE"
