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

static bool piv_reset_owns_file(const file_t *file) {
    uint16_t fid = file->fid;
    if (openpgp_key_container_physical_fid(fid)) {
        uint16_t key = fid & UINT8_MAX;
        return key != EF_PIV_KEY_ATTESTATION && openpgp_key_container_is_piv(key);
    }
    // Factory/device attestation and shared OpenPGP retry/vault records survive.
    if (fid == EF_PIV_KEY_ATTESTATION || fid == EF_PIV_ATTESTATION) return false;
    return openpgp_key_container_is_piv(fid) || fid == EF_PIV_PIN ||
        fid == EF_PIV_PUK || fid == EF_DEK_PWPIV || fid == EF_PIV_ADMIN_DATA ||
        (fid >= EF_PIV_MSCMAP && fid <= EF_PIV_MSROOTS5) ||
        (fid >= 0xc100 && fid <= 0xc1ff) || fid == EF_PIV_BITGT;
}

static bool piv_reset_clear_file(file_t *file, void *context) {
    int *result = context;
    if (!piv_reset_owns_file(file)) return true;
    *result = file_delete_no_commit(file);
    return *result == PICOKEYS_OK;
}

static int piv_reset_retry_fields(uint16_t fid, size_t offset) {
    file_t *file = file_search(fid);
    uint8_t data[64];
    size_t len = file_get_size(file);
    if (!file_has_data(file) || len > sizeof(data) || offset + 2 > len)
        return PICOKEYS_WRONG_DATA;
    memcpy(data, file_get_data(file), len);
    data[offset] = data[offset + 1] = 3;
    return file_put_data(file, CONST_BYTE_ARRAY(data, len));
}

int cmd_reset(void) {
    if (P1(apdu) != 0x0 || P2(apdu) != 0x0) {
        return SW_INCORRECT_P1P2();
    }
    file_t *pw_status;
    if (!(pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF)))
    {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t retPIN = *(file_get_data(pw_status) + 3 + (EF_PIV_PIN & 0xf)), retPUK = *(file_get_data(pw_status) + 3 + (EF_PIV_PUK & 0xf));
    if (retPIN != 0 || retPUK != 0) {
        return SW_INCORRECT_PARAMS();
    }
    int result = openpgp_vault_clear_piv();
    if (result != PICOKEYS_OK) return SW_MEMORY_FAILURE();
    for (file_entry_t *entry = file_entries; entry != file_last; entry++) {
        if ((entry->type & FILE_DATA_FLASH) && file_has_data(&entry->file) &&
            !piv_reset_clear_file(&entry->file, &result)) return SW_MEMORY_FAILURE();
    }
    file_for_each_dynamic(piv_reset_clear_file, &result);
    if (result != PICOKEYS_OK ||
        piv_reset_retry_fields(EF_PW_PRIV, 7) != PICOKEYS_OK ||
        piv_reset_retry_fields(EF_PW_RETRIES, 4) != PICOKEYS_OK ||
        !flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) return SW_MEMORY_FAILURE();
    init_piv();
    if (!flash_commit_sync(PIV_FLASH_COMMIT_TIMEOUT_MS)) return SW_MEMORY_FAILURE();
    return SW_OK();
}
