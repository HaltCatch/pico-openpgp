/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "piv.h"

static const uint8_t piv_default_card_capability[] = {
    0xF0,
    0x00,
    0xF1,
    0x00,
    0xF2,
    0x00,
    0xF5,
    0x01,
    0x10,
};


int cmd_piv_get_data(void) {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 3) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] != 0x5C || (apdu.data[1] & 0x80) || apdu.data[1] >= 4 || apdu.data[1] == 0) {
        return SW_WRONG_DATA();
    }
    if (apdu.nc != (uint32_t)apdu.data[1] + 2u) {
        return SW_WRONG_LENGTH();
    }
    uint32_t fid = apdu.data[2];
    for (uint8_t lt = 1; lt < apdu.data[1]; lt++) {
        fid <<= 8;
        fid |= apdu.data[2 + lt];
    }
    if ((fid & 0xFFFF00) != 0x5FC100 && fid != EF_PIV_BITGT && fid != EF_PIV_DISCOVERY && !piv_writable_vendor_object(fid) && fid != PIV_DATA_ATTESTATION_ID) {
        return SW_FILE_NOT_FOUND();
    }
    uint16_t file_id = (uint16_t)(fid & 0xFFFF);
    // These PIV objects require PIN verification. Yubico clients also use
    // PRINTED for the PIN-protected management key.
    if ((file_id == EF_PIV_FINGERPRINTS || file_id == EF_PIV_FACIAL ||
         file_id == EF_PIV_PRINTED || file_id == EF_PIV_IRIS) && !has_pwpiv) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    bool is_card_capability = file_id == EF_PIV_CAPABILITY;
    file_t *ef = file_search_by_fid(file_id, NULL, SPECIFY_EF);
    if (ef || is_card_capability) {
        uint16_t data_len = 0;
        res_APDU_size = 2; // Minimum: TAG+LEN

        if (ef) {
            if ((file_get_type(ef) & FILE_DATA_FUNC) == FILE_DATA_FUNC) {
                int (*file_data_func)(const file_t *) = NULL;
                memcpy(&file_data_func, &ef->data, sizeof(file_data_func));
                data_len = file_data_func(ef);
            }
            else {
                if (ef->data) {
                    data_len = MIN(file_get_size(ef), OPENPGP_MAX_OBJECT_SIZE);
                    data_len = MIN(data_len, OPENPGP_MAX_RESPONSE_SIZE - 4);
                    if (file_id == EF_PIV_ATTESTATION && data_len > 0 && file_get_data(ef)[0] == 0x30) {
                        // Generated attestation is stored as DER. GET DATA uses
                        // the same certificate object encoding as user slots.
                        int wrapped = piv_format_certificate_object(file_get_data(ef), data_len,
                            res_APDU + res_APDU_size, OPENPGP_MAX_RESPONSE_SIZE - 6);
                        if (wrapped < 0) return SW_MEMORY_FAILURE();
                        data_len = (uint16_t)wrapped;
                    } else {
                        memcpy(res_APDU + res_APDU_size, file_get_data(ef), data_len);
                    }
                }
            }
        }

        if (data_len == 0 && is_card_capability) {
            data_len = sizeof(piv_default_card_capability);
            memcpy(res_APDU + res_APDU_size, piv_default_card_capability, data_len);
        }

        if (data_len == 0) {
            return SW_FILE_NOT_FOUND();
        }
        if (data_len > 255) {
            memmove(res_APDU + res_APDU_size + 2, res_APDU + res_APDU_size, data_len);
        }
        else if (data_len > 127) {
            memmove(res_APDU + res_APDU_size + 1, res_APDU + res_APDU_size, data_len);
        }
        res_APDU[0] = 0x53;
        res_APDU_size = 1 + tlv_format_len(data_len, res_APDU + 1) + data_len;
    }
    else {
        return SW_FILE_NOT_FOUND();
    }
    return SW_OK();
}
