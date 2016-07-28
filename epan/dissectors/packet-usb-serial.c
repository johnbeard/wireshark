/* packet-vsock.c
 * Routines for AF_VSOCK dissection
 * Copyright 2016, Gerard Garcia <ggarcia@deic.uab.cat>
 *
 * Header definition:
 * https://github.com/GerardGarcia/linux/blob/vsockmon/include/uapi/linux/vsockmon.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * The AF_VSOCK socket allows zero-configuration communication between guests
 * and hypervisors using the standard socket API.
 */

#include <config.h>
#include <epan/packet.h>
#include <wsutil/pint.h>
#include <epan/address_types.h>
#include <stdio.h>

void proto_register_usbserial(void);

static int proto_usbserial = -1;

static int hf_usbserial_payload = -1;

static gint ett_usbserial = -1;


static int
dissect_usbserial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    gint length;
    gint32 payload_offset, payload_len;
    proto_item *ti;
    proto_tree *usbserial_tree;

    /* Create top tree */
    ti = proto_tree_add_protocol_format(tree, proto_usbserial, tvb, 0, -1,
            "USB Serial");
    usbserial_tree = proto_item_add_subtree(ti, ett_usbserial);

    length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB Serial");

    payload_offset = 0;
    // strip the front off if it's 0x0160
    if (length >= 2 && tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN) == 0x0160)
    {
        payload_offset = 2;
    }

    payload_len = tvb_reported_length_remaining(tvb, payload_offset);

    if (payload_len == 0) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "PING");
    }
    else
    {
        proto_tree_add_bytes_format(usbserial_tree, hf_usbserial_payload,
                tvb, payload_offset, payload_len,
                NULL, "Payload (%uB)", payload_len);
    }

    return length;
}

void
proto_register_usbserial(void)
{
    static hf_register_info hf[] = {
        { &hf_usbserial_payload,
            {"Payload", "usbserial.payload", FT_BYTES, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_usbserial,
    };

    proto_usbserial = proto_register_protocol("USB serial", "usbserial", "usbserial");
    proto_register_field_array(proto_usbserial, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("usbserial", dissect_usbserial, proto_usbserial);
}

void
proto_reg_handoff_usb_serial(void)
{
    dissector_handle_t usb_serial_handle;

    usb_serial_handle  = create_dissector_handle(dissect_usbserial, proto_usbserial);

    dissector_add_uint("usb.product", 0x04036001, usb_serial_handle);
    dissector_add_uint("usb.device", 0x000200013, usb_serial_handle);
}
/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
