#include <stdint.h>

// Based on Telegram source code
// https://github.com/Telegram-FOSS-Team/Telegram-FOSS/blob/8476bf4741135f2aff0ae2ea9478dbbea3c69ab8/TMessagesProj/src/main/java/org/telegram/messenger/voip/EncryptionKeyEmojifier.java

long long bytesToLong(uint8_t* arr, int offset);
void emojify(uint8_t* key, char* emojified_key[4]);
void print_emojified_key(char* emojified_key[4]);
