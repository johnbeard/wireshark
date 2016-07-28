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
#include <packet-usb.h>
#include <wsutil/pint.h>
#include <epan/address_types.h>
#include <stdio.h>

void proto_register_usbserial(void);

static int proto_usbserial = -1;

// USB URB fields
static int hf_usbserial_request = -1;
static int hf_usbserial_value = -1;
static int hf_usbserial_index = -1;
static int hf_usbserial_length = -1;
static int hf_usbserial_zero = -1;
static int hf_usbserial_port = -1;
static int hf_usbserial_latency = -1;

static int hf_usbserial_payload = -1;

static gint ett_usbserial_wValue = -1;
static gint ett_usbserial_wIndex = -1;
static gint ett_usbserial_wLength = -1;
static gint ett_usbserial = -1;

/* Commands */
#define FTDI_SIO_RESET                  0 /* Reset the port */
#define FTDI_SIO_MODEM_CTRL             1 /* Set the modem control register */
#define FTDI_SIO_SET_FLOW_CTRL          2 /* Set flow control register */
#define FTDI_SIO_SET_BAUD_RATE          3 /* Set baud rate */
#define FTDI_SIO_SET_DATA               4 /* Set the data characteristics of
                                             the port */
#define FTDI_SIO_GET_MODEM_STATUS       5 /* Retrieve current value of modem
                                             status register */
#define FTDI_SIO_SET_EVENT_CHAR         6 /* Set the event character */
#define FTDI_SIO_SET_ERROR_CHAR         7 /* Set the error character */
#define FTDI_SIO_SET_LATENCY_TIMER      9 /* Set the latency timer */
#define FTDI_SIO_GET_LATENCY_TIMER      10 /* Get the latency timer */

#define FTDI_SIO_GET_LATENCY_TIMER_REQUEST_TYPE 0xC0
#define FTDI_SIO_SET_LATENCY_TIMER_REQUEST_TYPE 0x40

static const value_string setup_request_names_vals[] = {
    { FTDI_SIO_RESET,                  "RESET" },
    { FTDI_SIO_MODEM_CTRL,             "MODEM_CTRL" },
    { FTDI_SIO_SET_FLOW_CTRL,          "SET_FLOW_CTRL" },
    { FTDI_SIO_SET_BAUD_RATE,          "SET_BAUD_RATE" },
    { FTDI_SIO_SET_DATA,               "SET_DATA" },
    { FTDI_SIO_GET_MODEM_STATUS,       "GET_MODEM_STATUS" },
    { FTDI_SIO_SET_EVENT_CHAR,         "SET_EVENT_CHAR" },
    { FTDI_SIO_SET_ERROR_CHAR,         "SET_ERROR_CHAR" },
    { FTDI_SIO_SET_LATENCY_TIMER,      "SET_LATENCY_TIMER" },
    { FTDI_SIO_GET_LATENCY_TIMER,      "GET_LATENCY_TIMER" },
    { 0, NULL }
};

/* Dissection function for some type of USB serial USB packet */
typedef void (*usb_setup_dissector)(packet_info *pinfo, proto_tree *tree,
        tvbuff_t *tvb, int offset, gboolean is_request,
        usb_trans_info_t *usb_trans_info, usb_conv_info_t *usb_conv_info);

static void
dissect_usbserial_get_latency_timer(packet_info *pinfo _U_, proto_tree *tree,
        tvbuff_t *tvb, int offset, gboolean is_request,
        usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item = NULL;
    proto_tree *subtree = NULL;

    if (is_request) {
        item = proto_tree_add_item(tree, hf_usbserial_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_usbserial_wValue);
        proto_tree_add_item(subtree, hf_usbserial_zero, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        item = proto_tree_add_item(tree, hf_usbserial_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_usbserial_wIndex);
        proto_tree_add_item(subtree, hf_usbserial_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        item = proto_tree_add_item(tree, hf_usbserial_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_usbserial_wLength);
        proto_tree_add_item(subtree, hf_usbserial_zero, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        /*offset += 2;*/
    } else {
        proto_tree_add_item(tree, hf_usbserial_latency, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        /*offset += 2;*/
    }
}

static void
dissect_usbserial_set_latency_timer(packet_info *pinfo _U_, proto_tree *tree,
        tvbuff_t *tvb, int offset, gboolean is_request,
        usb_trans_info_t *usb_trans_info _U_, usb_conv_info_t *usb_conv_info _U_)
{
    proto_item *item = NULL;
    proto_tree *subtree = NULL;

    if (is_request) {
        item = proto_tree_add_item(tree, hf_usbserial_value, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_usbserial_wValue);
        proto_tree_add_item(subtree, hf_usbserial_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        item = proto_tree_add_item(tree, hf_usbserial_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_usbserial_wIndex);
        proto_tree_add_item(subtree, hf_usbserial_port, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        item = proto_tree_add_item(tree, hf_usbserial_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_usbserial_wLength);
        proto_tree_add_item(subtree, hf_usbserial_zero, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        /*offset += 2;*/
    } else {
        /* no data */
    }
}

typedef struct _usb_setup_dissector_table_t {
	guint8 request_type;
	guint8 request;
	usb_setup_dissector dissector;
} usb_setup_dissector_table_t;


/* Dispatch table for CONTROL request/response */
static const usb_setup_dissector_table_t setup_dissectors[] = {
    { FTDI_SIO_GET_LATENCY_TIMER_REQUEST_TYPE,
      FTDI_SIO_GET_LATENCY_TIMER,
      dissect_usbserial_get_latency_timer
    },

    { FTDI_SIO_SET_LATENCY_TIMER_REQUEST_TYPE,
      FTDI_SIO_SET_LATENCY_TIMER,
      dissect_usbserial_set_latency_timer
    },

    { 0, 0, NULL }
};

static gint
dissect_control(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree _U_, usb_conv_info_t *usb_conv_info _U_,
        usb_trans_info_t *usb_trans_info _U_, gboolean is_request)
{
    gint offset = 0;
    usb_setup_dissector dissector = NULL;
    const usb_setup_dissector_table_t *tmp;


    col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                 val_to_str(usb_trans_info->setup.request,
                            setup_request_names_vals, "Unknown type %x"),
                 is_request ? "Request " : "Response");

    if (is_request) {
        proto_tree_add_item(tree, hf_usbserial_request, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    /* Check valid values for bmRequestType and bRequest */
    for (tmp = setup_dissectors; tmp->dissector; tmp++) {
        if (tmp->request_type == usb_trans_info->setup.requesttype &&
            tmp->request == usb_trans_info->setup.request) {
            dissector = tmp->dissector;
            break;
        }
    }
    /* No, we could not find any class specific dissector for this request
     * return 0 and let USB try any of the standard requests.
     */
    if (!dissector) {
        return 0;
    }

    dissector(pinfo, tree, tvb, offset, is_request, usb_trans_info, usb_conv_info);
    return tvb_captured_length(tvb);
}

static int
dissect_usbserial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    gboolean is_request;
    gint length;
    gint32 payload_offset, payload_len;
    proto_item *ti;
    proto_tree *usbserial_tree;
    usb_conv_info_t *usb_conv_info;
    usb_trans_info_t *usb_trans_info;

    /* Reject the packet if data or usb_trans_info are NULL */
    if (data == NULL || ((usb_conv_info_t *)data)->usb_trans_info == NULL)
        return 0;

    usb_conv_info = (usb_conv_info_t *)data;
    usb_trans_info = usb_conv_info->usb_trans_info;

    is_request = (pinfo->srcport==NO_ENDPOINT);

    length = tvb_reported_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USB Serial");

    if (usb_conv_info->transfer_type == URB_CONTROL)
    {
        dissect_control(tvb, pinfo, tree, usb_conv_info, usb_trans_info,
                is_request);
        return length;
    }
    else if (usb_conv_info->transfer_type == URB_BULK)
    {
        int offset = 0;

        /* Create top tree */
        ti = proto_tree_add_protocol_format(tree, proto_usbserial, tvb, offset, -1,
                "USB Serial");
        usbserial_tree = proto_item_add_subtree(ti, ett_usbserial);

        /* BULK transfers are likely to be serial data or ping messages */
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
    }

    return length;
}

void
proto_register_usbserial(void)
{
    static hf_register_info hf[] = {
        /* USB HUB specific requests */
        { &hf_usbserial_request,
        { "bRequest", "usbserial.setup.bRequest", FT_UINT8, BASE_HEX,
            VALS(setup_request_names_vals), 0x0,
            NULL, HFILL }},

        { &hf_usbserial_value,
        { "wValue", "usbserial.setup.wValue", FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usbserial_index,
        { "wIndex", "usbserial.setup.wIndex", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usbserial_length,
        { "wLength", "usbserial.setup.wLength", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usbserial_zero,
        { "(zero)", "usbserial.setup.zero", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usbserial_port,
        { "Port", "usbserial.setup.Port", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usbserial_latency,
        { "Latency (ms)", "usbserial.setup.latency", FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},

        { &hf_usbserial_payload,
            {"Payload", "usbserial.payload", FT_BYTES, BASE_NONE, NULL,
                0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_usbserial,
        &ett_usbserial_wIndex,
        &ett_usbserial_wValue,
        &ett_usbserial_wLength
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
