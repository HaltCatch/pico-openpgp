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


int cmd_move_key(void) {
    if (!has_mgm) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t to = P1(apdu), from = P2(apdu);
    if ((!IS_KEY(to) && to != 0xFF) || !IS_KEY(from)) {
        return SW_INCORRECT_P1P2();
    }
    if (to == from) {
        return SW_INCORRECT_P1P2();
    }
    const uint8_t from_slot = from, to_slot = to;
    if (from == 0x93) {
        from = EF_PIV_KEY_RETIRED18;
    }
    if (to == 0x93) {
        to = EF_PIV_KEY_RETIRED18;
    }
    file_t *efs, *efd;
    if (!(efs = file_search_by_fid(from, NULL, SPECIFY_EF)) || (!(efd = file_search_by_fid(to, NULL, SPECIFY_EF)) && to != 0xFF)) {
        return SW_FILE_NOT_FOUND();
    }
    // Certificates belong to slots and are managed separately via PUT DATA.
    uint8_t key_data[4096 / 8] = { 0 };
    byte_buffer_t key = BYTE_BUFFER(key_data, sizeof(key_data));
    uint8_t *meta_copy = NULL;
    size_t meta_len = 0;
    int status = SW_OK();
    int r = PICOKEYS_OK;

    if (to != 0xFF) {
        if (openpgp_key_container_is_marker(efs)) {
            r = openpgp_key_container_read_private(from, FILE_OBJECT_OPERATION_USE, true, &key);
        }
        else if (file_has_data(efs) && file_get_size(efs) <= sizeof(key_data)) {
            key.len = file_get_size(efs);
            r = file_read_at(efs, 0, BYTE_ARRAY(key_data, key.len));
        }
        else {
            r = PICOKEYS_WRONG_DATA;
        }
        if (r != PICOKEYS_OK) {
            status = SW_EXEC_ERROR();
            goto cleanup;
        }
        byte_array_t metadata = meta_find(from_slot);
        if (metadata.len > 0) {
            if (!metadata.data) {
                status = SW_MEMORY_FAILURE();
                goto cleanup;
            }
            meta_len = metadata.len;
            meta_copy = (uint8_t *)calloc(1, meta_len);
            if (!meta_copy) {
                status = SW_MEMORY_FAILURE();
                goto cleanup;
            }
            memcpy(meta_copy, metadata.data, meta_len);
        }

        r = openpgp_key_container_store(to, key_data, key.len, NULL, 0, true);
        if (r != PICOKEYS_OK) {
            status = SW_EXEC_ERROR();
            goto cleanup;
        }
        if (meta_len > 0) {
            r = meta_add(to_slot, CONST_BYTE_ARRAY(meta_copy, meta_len));
        }
        else {
            r = meta_delete(to_slot);
        }
        if (r != PICOKEYS_OK) {
            status = SW_MEMORY_FAILURE();
            goto cleanup;
        }
        // Keep the source usable until both destination key and policy are
        // durable. A failed commit must not turn a move into data loss.
        if (!flash_commit_sync(5000)) {
            status = SW_MEMORY_FAILURE();
            goto cleanup;
        }
    }

    r = meta_delete(from_slot);
    if (r != PICOKEYS_OK && r != PICOKEYS_ERR_FILE_NOT_FOUND) {
        status = SW_MEMORY_FAILURE();
        goto cleanup;
    }
    if (openpgp_key_container_is_marker(efs)) {
        if (openpgp_key_container_delete(from, true) != PICOKEYS_OK) {
            status = SW_EXEC_ERROR();
            goto cleanup;
        }
    }
    else if (flash_clear_file(efs) != PICOKEYS_OK) {
        status = SW_EXEC_ERROR();
        goto cleanup;
    }
    flash_commit();

cleanup:
    free(meta_copy);
    mbedtls_platform_zeroize(key_data, sizeof(key_data));
    return status;
}
