/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "openpgp.h"
#include "version.h"

WEAK void openpgp_app_version(uint8_t version[3]) { (void)version; }

int cmd_version_openpgp(void) {
    uint8_t version[3] = {PIPGP_VERSION_MAJOR, PIPGP_VERSION_MINOR, 0};
    openpgp_app_version(version);
    res_APDU[res_APDU_size++] = version[0];
    res_APDU[res_APDU_size++] = version[1];
    res_APDU[res_APDU_size++] = version[2];
    return SW_OK();
}