/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
 * SCRAM library
 * Copyright (C) 2014 Collabora Ltd.
 *
 * SCRAM library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * SCRAM library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with SCRAM library.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Philip Withnall <philip.withnall@collabora.co.uk>
 */

#include <stddef.h>

#include <glib.h>


#ifndef _SCRAM_AUTHENTICATION_H_
#define _SCRAM_AUTHENTICATION_H_


/**
 * ScramAuthenticationMechanism:
 * @SCRAM_AUTHENTICATION_NONE: no authentication; this must not be used on the
 * wire, and exists only as a convenience for default values and error handling
 * @SCRAM_AUTHENTICATION_SCRAM_SHA_1: SCRAM with SHA-1 (‘SCRAM-SHA-1’)
 * @SCRAM_AUTHENTICATION_SCRAM_SHA_1_PLUS: SCRAM with SHA-1 and channel binding
 * (‘SCRAM-SHA-1-PLUS’)
 * @SCRAM_AUTHENTICATION_SCRAM_SHA_256: SCRAM with SHA-256 (‘SCRAM-SHA-256’)
 * @SCRAM_AUTHENTICATION_SCRAM_SHA_256_PLUS: SCRAM with SHA-256 and channel
 * binding (‘SCRAM-SHA-256-PLUS’)
 * @SCRAM_AUTHENTICATION_SCRAM_SHA_512: SCRAM with SHA-512 (‘SCRAM-SHA-512’)
 * @SCRAM_AUTHENTICATION_SCRAM_SHA_512_PLUS: SCRAM with SHA-512 and channel
 * binding (‘SCRAM-SHA-512-PLUS’)
 *
 * Authentication mechanisms available for use with #ScramAuthenticationClient.
 * All mechanisms are supported by both the client and server authentication
 * code, but a more limited set may be advertised by servers due to local
 * policy.
 *
 * The values assigned to these enumerated members are used on the wire, so must
 * not be changed.
 *
 * In the documentation for each member, the name in brackets is the associated
 * IANA SASL mechanism name.
 *
 *  * Reference: <ulink url="http://tools.ietf.org/html/rfc5802#section-4">RFC
 *    5802, §4</ulink>
 *  * Reference: <ulink url="http://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml">IANA
 *    SASL mechanisms</ulink>
 */
typedef enum {
	SCRAM_AUTHENTICATION_NONE = 0,  /* not a valid mechanism */
	SCRAM_AUTHENTICATION_SCRAM_SHA_1 = 1,
	SCRAM_AUTHENTICATION_SCRAM_SHA_1_PLUS = 2,
	SCRAM_AUTHENTICATION_SCRAM_SHA_256 = 3,
	SCRAM_AUTHENTICATION_SCRAM_SHA_256_PLUS = 4,
	SCRAM_AUTHENTICATION_SCRAM_SHA_512 = 5,
	SCRAM_AUTHENTICATION_SCRAM_SHA_512_PLUS = 6,
} ScramAuthenticationMechanism;

/**
 * ScramAuthenticationChannelBinding:
 * @SCRAM_CHANNEL_BINDING_UNKNOWN: channel binding status is unknown
 * @SCRAM_CHANNEL_BINDING_UNSUPPORTED: channel binding is unsupported by the
 * client
 * @SCRAM_CHANNEL_BINDING_CLIENT_ONLY: channel binding is supported by the
 * client but doesn’t appear to be supported by the server
 * @SCRAM_CHANNEL_BINDING_REQUIRED: channel binding is required by the client
 * and supported by the server
 *
 * Channel binding statuses available.
 *
 * The values assigned to these enumerated members are used on the wire, so must
 * not be changed.
 *
 * Reference: ‘gs2-cbind-flag’ in
 * <ulink url="http://tools.ietf.org/html/rfc5802#section-7">RFC 5802, §7</ulink>.
 */
typedef enum {
	SCRAM_CHANNEL_BINDING_UNKNOWN = 0,
	SCRAM_CHANNEL_BINDING_UNSUPPORTED = 'n',
	SCRAM_CHANNEL_BINDING_CLIENT_ONLY = 'y',
	SCRAM_CHANNEL_BINDING_REQUIRED = 'p',
} ScramAuthenticationChannelBinding;

/**
 * ScramAuthenticationError:
 * @SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE: the #GVariant type of a
 * message was invalid
 * @SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE: an attribute in a message had
 * an invalid value or type
 * @SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE: a required attribute was
 * missing from a message
 * @SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE: an unsupported attribute
 * was present in a message
 * @SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE: a received nonce was invalid (e.g.
 * due to being too short or being re-used)
 * @SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF: the client proof was
 * invalid (this is the most common way for authentication to fail); only
 * received on the server
 * @SCRAM_AUTHENTICATION_ERROR_INVALID_SERVER_SIGNATURE: the server signature
 * was invalid; only received on the client
 * @SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_MISMATCH: the channel bindings
 * chosen by the client and server did not match, which may indicate a man in
 * the middle attack
 * @SCRAM_AUTHENTICATION_ERROR_SERVER_SUPPORTS_CHANNEL_BINDING: the server
 * supports channel binding when the client thought it didn’t, which may
 * indicate a man in the middle attack
 * @SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_UNSUPPORTED: the client required
 * channel binding, but it was not supported by the server
 * @SCRAM_AUTHENTICATION_ERROR_INVALID_CHANNEL_BINDING: an invalid channel
 * binding attribute or value was used
 * @SCRAM_AUTHENTICATION_ERROR_UNKNOWN_USER: the specified username was invalid
 * or did not exist
 * @SCRAM_AUTHENTICATION_ERROR_FAILED: miscellaneous failure
 *
 * An authentication error on the client or server.
 */
typedef enum {
	SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE,
	SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
	SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
	SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE,
	SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
	SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF,
	SCRAM_AUTHENTICATION_ERROR_INVALID_SERVER_SIGNATURE,
	SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_MISMATCH,
	SCRAM_AUTHENTICATION_ERROR_SERVER_SUPPORTS_CHANNEL_BINDING,
	SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_UNSUPPORTED,
	SCRAM_AUTHENTICATION_ERROR_INVALID_CHANNEL_BINDING,
	SCRAM_AUTHENTICATION_ERROR_UNKNOWN_USER,
	SCRAM_AUTHENTICATION_ERROR_FAILED,
} ScramAuthenticationError;

#define SCRAM_AUTHENTICATION_ERROR (scram_authentication_error_get_quark ())
GQuark scram_authentication_error_get_quark (void) G_GNUC_CONST;


/**
 * ScramAuthenticationClient:
 *
 * The authentication state on an authentication client. All members of this
 * structure are private. Use scram_authentication_client_init() and
 * scram_authentication_client_clear() to set up and tear down this structure.
 */
typedef struct {
	/*< private >*/

	/* Static configuration. */
	ScramAuthenticationMechanism chosen_mechanism;
	ScramAuthenticationChannelBinding channel_binding;
	gchar *username_normalised;  /* owned; must be in SASLprep form */
	gchar *password;  /* owned */
	gchar *client_nonce;  /* owned */

	/* From the server. All unset until the first reply is successfully
	 * received. */
	gchar *nonce;  /* owned; concatenation of server and client nonces */
	const gchar *server_nonce;  /* unowned; pointer into @nonce */
	gchar *salt_base64;  /* owned; must be base-64 encoded */
	guint32 iter_count;
} ScramAuthenticationClient;

/**
 * ScramAuthenticationServer:
 *
 * The authentication state on an authentication server. All members of this
 * structure are private. Use scram_authentication_server_init() and
 * scram_authentication_server_clear() to set up and tear down this structure.
 */
typedef struct {
	/*< private >*/

	/* Static configuration. */
	const ScramAuthenticationMechanism *available_mechanisms;  /* unowned */
	guint n_available_mechanisms;

	ScramAuthenticationMechanism chosen_mechanism;
	gchar *server_nonce;  /* owned */
	gchar *salt_base64;  /* owned; must be base-64 encoded */
	guint32 iter_count;
	GBytes *server_key;  /* owned; must match @chosen_mechanism */
	GBytes *stored_key;  /* owned; must match @chosen_mechanism */

	/* From the client. All unset until the first message is successfully
	 * received. */
	gchar *client_nonce;  /* owned */
	gchar *username_normalised;  /* owned; must be in SASLprep form */
	ScramAuthenticationChannelBinding channel_binding;

	/* Set if an error occurs when parsing the first message. Results in
	 * an error attribute being sent in the final reply. */
	GError *error;  /* owned */
} ScramAuthenticationServer;


void
scram_authentication_client_init (ScramAuthenticationClient *client,
                                  const gchar *client_nonce,
                                  const ScramAuthenticationMechanism *supported_mechanisms,
                                  gsize n_supported_mechanisms,
                                  gboolean require_channel_binding);
void
scram_authentication_client_clear (ScramAuthenticationClient *client);

void
scram_authentication_server_init (ScramAuthenticationServer *server,
                                  const gchar *server_nonce,
                                  const ScramAuthenticationMechanism *available_mechanisms,
                                  guint n_available_mechanisms);
void
scram_authentication_server_clear (ScramAuthenticationServer *server);


ScramAuthenticationMechanism
scram_authentication_client_get_chosen_mechanism (ScramAuthenticationClient *client);
ScramAuthenticationMechanism
scram_authentication_server_get_chosen_mechanism (ScramAuthenticationServer *server);


GVariant *
scram_authentication_client_build_first_message (ScramAuthenticationClient *client,
                                                 const gchar *username,
                                                 const gchar *password,
                                                 GError **error);
gchar *
scram_authentication_server_parse_first_message (ScramAuthenticationServer *server,
                                                 GVariant *message,
                                                 GError **error);
GVariant *
scram_authentication_server_build_first_reply (ScramAuthenticationServer *server,
                                               GBytes *salt,
                                               guint32 iter_count,
                                               GBytes *server_key,
                                               GBytes *stored_key);
void
scram_authentication_client_parse_first_reply (ScramAuthenticationClient *client,
                                               GVariant *reply,
                                               GError **error);

GVariant *
scram_authentication_client_build_final_message (ScramAuthenticationClient *client);
void
scram_authentication_server_parse_final_message (ScramAuthenticationServer *server,
                                                 GVariant *message,
                                                 GError **error);
GVariant *
scram_authentication_server_build_final_reply (ScramAuthenticationServer *server);
void
scram_authentication_client_parse_final_reply (ScramAuthenticationClient *client,
                                               GVariant *reply,
                                               GError **error);

GVariant *
scram_authentication_server_build_error_message (ScramAuthenticationServer *server,
                                                 const GError *error);

GBytes *
scram_authentication_salt_password (ScramAuthenticationMechanism mechanism,
                                    const gchar *password, GBytes *salt,
                                    guint32 iter_count, GError **error);

GBytes *
scram_authentication_build_server_key (ScramAuthenticationMechanism mechanism,
                                       GBytes *salted_password);
GBytes *
scram_authentication_build_stored_key (ScramAuthenticationMechanism mechanism,
                                       GBytes *salted_password);

gchar *
scram_authentication_generate_nonce (GError **error);


#endif /* _SCRAM_AUTHENTICATION_H_ */
