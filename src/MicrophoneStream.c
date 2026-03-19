#include "Limelight-internal.h"
#include "PlatformSockets.h"

#define MIC_IV_LEN 16
#define MIC_HEADER_FLAGS 0x00
#define MIC_DEFAULT_FRAME_DURATION_SAMPLES 960

static SOCKET micSocket = INVALID_SOCKET;
static PPLT_CRYPTO_CONTEXT micEncryptionCtx = NULL;
static uint32_t micRiKeyId = 0;
static uint16_t micSequenceNumber = 0;
static uint32_t micTimestamp = 0;

#pragma pack(push, 1)
typedef struct _MICROPHONE_PACKET_HEADER {
    uint8_t flags;
    uint8_t packetType;
    uint16_t sequenceNumber;
    uint32_t timestamp;
    uint32_t ssrc;
} MICROPHONE_PACKET_HEADER, *PMICROPHONE_PACKET_HEADER;
#pragma pack(pop)

int initializeMicrophoneStream(void) {
    if (micSocket != INVALID_SOCKET) {
        return 0;
    }

    micEncryptionCtx = PltCreateCryptoContext();
    if (micEncryptionCtx == NULL) {
        return -1;
    }

    memcpy(&micRiKeyId, StreamConfig.remoteInputAesIv, sizeof(micRiKeyId));
    micRiKeyId = BE32(micRiKeyId);
    micSequenceNumber = 0;
    micTimestamp = 0;

    micSocket = bindUdpSocket(RemoteAddr.ss_family, &LocalAddr, AddrLen, 0, SOCK_QOS_TYPE_AUDIO);
    if (micSocket == INVALID_SOCKET) {
        PltDestroyCryptoContext(micEncryptionCtx);
        micEncryptionCtx = NULL;
        return LastSocketFail();
    }

    return 0;
}

void destroyMicrophoneStream(void) {
    if (micSocket != INVALID_SOCKET) {
        closeSocket(micSocket);
        micSocket = INVALID_SOCKET;
    }

    if (micEncryptionCtx != NULL) {
        PltDestroyCryptoContext(micEncryptionCtx);
        micEncryptionCtx = NULL;
    }

    micRiKeyId = 0;
    micSequenceNumber = 0;
    micTimestamp = 0;
}

int LiSendMicrophoneOpusData(const unsigned char* opusData, int opusLength) {
    return LiSendMicrophoneOpusDataEx(opusData, opusLength, MIC_DEFAULT_FRAME_DURATION_SAMPLES);
}

int LiSendMicrophoneOpusDataEx(const unsigned char* opusData, int opusLength, uint32_t frameDurationSamples) {
    LC_SOCKADDR saddr;
    MICROPHONE_PACKET_HEADER header;
    unsigned char packet[MAX_MIC_PACKET_SIZE];
    int packetLength;
    int err;

    if (micSocket == INVALID_SOCKET || opusData == NULL || opusLength <= 0) {
        return -1;
    }

    if (opusLength > MAX_MIC_PACKET_SIZE - (int)sizeof(header)) {
        Limelog("MIC: Input data too large (%d)\n", opusLength);
        return -1;
    }

    memset(&header, 0, sizeof(header));
    header.flags = MIC_HEADER_FLAGS;
    header.packetType = MIC_PACKET_TYPE_OPUS;
    header.sequenceNumber = LE16(micSequenceNumber);
    header.timestamp = LE32(micTimestamp);
    header.ssrc = LE32(MIC_PACKET_MAGIC);

    if ((EncryptionFeaturesEnabled & SS_ENC_MICROPHONE) && micEncryptionCtx != NULL) {
        unsigned char iv[MIC_IV_LEN] = {0};
        unsigned char encryptedData[ROUND_TO_PKCS7_PADDED_LEN(MAX_MIC_PACKET_SIZE)];
        int encryptedLength = (int)sizeof(encryptedData);
        uint32_t ivSeq = BE32(micRiKeyId + micSequenceNumber);

        memcpy(iv, &ivSeq, sizeof(ivSeq));

        if (!PltEncryptMessage(micEncryptionCtx,
                               ALGORITHM_AES_CBC,
                               CIPHER_FLAG_RESET_IV | CIPHER_FLAG_FINISH | CIPHER_FLAG_PAD_TO_BLOCK_SIZE,
                               (unsigned char*)StreamConfig.remoteInputAesKey,
                               sizeof(StreamConfig.remoteInputAesKey),
                               iv, sizeof(iv),
                               NULL, 0,
                               (unsigned char*)opusData, opusLength,
                               encryptedData, &encryptedLength)) {
            Limelog("MIC: Encryption failed\n");
            return -1;
        }

        packetLength = (int)sizeof(header) + encryptedLength;
        if (packetLength > MAX_MIC_PACKET_SIZE || packetLength > (int)sizeof(packet)) {
            Limelog("MIC: Encrypted packet too large (%d > %d)\n", packetLength, MAX_MIC_PACKET_SIZE);
            return -1;
        }

        memcpy(packet, &header, sizeof(header));
        memcpy(packet + sizeof(header), encryptedData, encryptedLength);
    }
    else {
        packetLength = (int)sizeof(header) + opusLength;
        if (packetLength > MAX_MIC_PACKET_SIZE || packetLength > (int)sizeof(packet)) {
            Limelog("MIC: Packet too large (%d > %d)\n", packetLength, MAX_MIC_PACKET_SIZE);
            return -1;
        }

        memcpy(packet, &header, sizeof(header));
        memcpy(packet + sizeof(header), opusData, opusLength);
    }

    ++micSequenceNumber;
    micTimestamp += frameDurationSamples != 0 ? frameDurationSamples : MIC_DEFAULT_FRAME_DURATION_SAMPLES;

    memcpy(&saddr, &RemoteAddr, sizeof(saddr));
    SET_PORT(&saddr, MicPortNumber);

    err = sendto(micSocket, (const char*)packet, packetLength, 0, (struct sockaddr*)&saddr, AddrLen);
    if (err < 0) {
        return LastSocketError();
    }

    return err;
}

bool LiIsMicrophoneEncryptionEnabled(void) {
    return (EncryptionFeaturesEnabled & SS_ENC_MICROPHONE) != 0;
}

bool LiIsMicrophoneStreamActive(void) {
    return micSocket != INVALID_SOCKET;
}
