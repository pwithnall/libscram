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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <gio/gio.h>

#ifdef G_OS_UNIX
#include <glib/gstdio.h>
#endif  /* G_OS_UNIX */

#include "authentication.h"

#ifdef G_OS_WIN32
#include <windows.h>
#include <Wincrypt.h>
#endif  /* G_OS_WIN32 */

/**
 * SECTION:scram-authentication
 * @short_description: Peer-to-peer challenge–response authentication
 * @title: ScramAuthentication
 * @stability: Private
 * @include: lib/authentication.h
 *
 * The authentication code provides a stand-alone implementation of one or more
 * authentication protocols, suitable for embedding in a higher layer protocol
 * using #GVariant serialisation. It consists of a <firstterm>server</firstterm>
 * and a <firstterm>client</firstterm> peer: these are names which indicate the
 * peers’ authentication relationship and stored data rather than any
 * relationship in the higher layer protocol.
 *
 * Currently, the only authentication protocol supported is SCRAM (RFC 5802),
 * with several variants using different hash functions supported. Other
 * authentication protocols may be added in future. The SCRAM implementation was
 * based on the <ulink url="http://tools.ietf.org/html/rfc5802">RFC 5802</ulink>
 * proposed standard, with
 * <ulink url="http://www.rfc-editor.org/errata_search.php?rfc=5802">errata
 * \#2651, \#2652 and \#2640</ulink> applied.
 *
 * To begin with, the client has a username and either:
 *  * a password,
 *  * a ClientKey and ServerKey, or
 *  * a SaltedPassword
 * stored locally. The server has:
 *  * a salt,
 *  * a StoredKey,
 *  * a ServerKey, and
 *  * the user iteration count
 * stored locally, indexed by the client username.
 *
 * Internally, the code is split between <firstterm>validation</firstterm> and
 * <firstterm>verification</firstterm>. Validation is a purely syntactical
 * process which is performed early on each received message, and checks that
 * required fields are present, formatted correctly, and the correct length.
 * Once that has been checked for all fields, verification is performed by
 * calculating the cryptographic proofs and comparing them to those in the
 * message.
 *
 * In the SCRAM implementation, SCRAM error values map to
 * #ScramAuthenticationError codes and vice-versa, although the mapping is not
 * perfectly reversible. SCRAM usernames come from agent device IDs, and SCRAM
 * passwords come from the secrets shared between the agent and signalling
 * server.
 *
 * Several features of SCRAM are not currently supported. SASL authentication
 * identities are not supported due to lack of demand for them. Neither client
 * or server support channel binding
 * (<ulink url="http://tools.ietf.org/html/rfc5929">RFC 5929</ulink>) at the
 * moment. If channel binding support is implemented in future, it is the
 * caller’s reponsibility to implement channel binding policy through their
 * choice of mechanisms passed to scram_authentication_server_init().
 *
 * As discussed in <ulink url="http://tools.ietf.org/html/rfc5802#section-9">RFC
 * 5802, §9</ulink>, the authentication protocol must be performed over TLS (or
 * some other strong security layer) to prevent passive eavesdropping attacks.
 * It is recommended that users of this code read §9 as it impacts design
 * decisions at the server end.
 */


/* FIXME:
 *  • Channel binding isn’t supported yet because #GTlsConnection doesn’t expose
 *    the necessary data to implement it (the output of
 *    gnutls_session_channel_binding()).
 *  • SASL authentication identities aren’t supported due to lack of demand for
 *    them.
 */


/* Security parameters. */
#define MINIMUM_NONCE_LENGTH 16 /* bytes */
#define MINIMUM_ITER_COUNT 1024 /* iterations */
#define MINIMUM_PASSWORD_LENGTH 1 /* byte */
#define MINIMUM_SALT_LENGTH 2 /* bytes */
#define MINIMUM_USERNAME_LENGTH 1 /* bytes */

/* The minimum length of a password salt, in bytes. By errata #2652, this must
 * be at least 2 bytes. By RFC 4086, it should be longer.
 *  * http://www.rfc-editor.org/errata_search.php?rfc=5802
 *  * http://tools.ietf.org/html/rfc4086
 */
#define MINIMUM_SALT_BASE64_LENGTH 16

/* The maximum size of a checksum, in bytes. This must be updated if more
 * checksum types are supported. */
#define MAXIMUM_CHECKSUM_LENGTH 64 /* bytes; for SHA-512 */

/* Path of a cryptographically secure random number generator. This may differ
 * for embedded systems, or might have to be set to /dev/urandom if the system
 * can’t generate enough entropy. */
#define DEV_RANDOM "/dev/urandom"

/*
 * Error domain.
 */
GQuark
scram_authentication_error_get_quark (void)
{
	return g_quark_from_static_string ("scram-authentication-error");
}


/*
 * General internal utility methods.
 */

/* A version of memcmp() which doesn’t bail out as soon as two bytes don’t
 * match, as this allows for a timing attack to determine which leading bytes of
 * a proof are correct. */
static int
secure_memcmp (const void *s1, const void *s2, size_t n)
{
	size_t i;
	int retval = 0;
	const int8_t *_s1 = s1, *_s2 = s2;

	for (i = 0; i < n; i++) {
		if (_s1[i] - _s2[i] < 0) {
			retval = -1;
		} else if (_s1[i] - _s2[i] > 0) {
			retval = +1;
		}
	}

	return retval;
}

/* Determine whether the given authentication @mechanism supports channel
 * binding. Only ‘-PLUS’-suffixed mechanisms support it.
 *
 * See: http://tools.ietf.org/html/rfc5802#section-4 */
static gboolean
mechanism_supports_channel_binding (ScramAuthenticationMechanism mechanism)
{
	switch (mechanism) {
	case SCRAM_AUTHENTICATION_SCRAM_SHA_1_PLUS:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_256_PLUS:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_512_PLUS:
		return TRUE;
	case SCRAM_AUTHENTICATION_SCRAM_SHA_1:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_256:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_512:
		return FALSE;
	case SCRAM_AUTHENTICATION_NONE:
	default:
		g_assert_not_reached ();
	}
}

/* Choose the most preferred authentication mechanism out of the
 * @supported_mechanisms. */
static ScramAuthenticationMechanism
choose_mechanism (const ScramAuthenticationMechanism *supported_mechanisms,
                  guint n_supported_mechanisms)
{
	guint i;
	ScramAuthenticationMechanism chosen_mechanism = SCRAM_AUTHENTICATION_NONE;

	/* For the moment, rank mechanisms based entirely on their numeric
	 * value. This means we correctly prefer SCRAM_SHA1_PLUS over
	 * SCRAM_SHA1. FIXME: Explicitly reject all -PLUS mechanisms because the
	 * client doesn’t support channel binding yet. */
	for (i = 0; i < n_supported_mechanisms; i++) {
		if (supported_mechanisms[i] > chosen_mechanism &&
		    !mechanism_supports_channel_binding (supported_mechanisms[i])) {
			chosen_mechanism = supported_mechanisms[i];
		}
	}

	return chosen_mechanism;
}

/* Determine whether the server supports channel binding at all. */
static gboolean
server_supports_channel_binding (const ScramAuthenticationMechanism *supported_mechanisms,
                                 guint n_supported_mechanisms)
{
	guint i;

	for (i = 0; i < n_supported_mechanisms; i++) {
		if (mechanism_supports_channel_binding (supported_mechanisms[i])) {
			return TRUE;
		}
	}

	return FALSE;
}

/* Get the type of hash function used by the given @mechanism. */
static GChecksumType
mechanism_get_digest_type (ScramAuthenticationMechanism mechanism)
{
	switch (mechanism) {
	case SCRAM_AUTHENTICATION_SCRAM_SHA_1:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_1_PLUS:
		return G_CHECKSUM_SHA1;
	case SCRAM_AUTHENTICATION_SCRAM_SHA_256:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_256_PLUS:
		return G_CHECKSUM_SHA256;
	case SCRAM_AUTHENTICATION_SCRAM_SHA_512:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_512_PLUS:
		return G_CHECKSUM_SHA512;
	case SCRAM_AUTHENTICATION_NONE:
	default:
		g_assert_not_reached ();
	}
}

/* Choose what level of channel binding the client will specify. This is based
 * on the mechanism chosen from those advertised by the server.
 *
 * See: http://tools.ietf.org/html/rfc5802#section-4 for an overview and
 * http://tools.ietf.org/html/rfc5802#section-6 for the procedure. */
static ScramAuthenticationChannelBinding
client_choose_channel_binding (ScramAuthenticationMechanism chosen_mechanism,
                               const ScramAuthenticationMechanism *available_mechanisms,
                               guint n_available_mechanisms,
                               gboolean client_requires_channel_binding)
{
	gboolean client_support = FALSE;  /* FIXME: never supports it */
	gboolean server_support;

	server_support = server_supports_channel_binding (available_mechanisms,
	                                                  n_available_mechanisms);

	if (client_support && !server_support) {
		/* Bullet point 2. */
		if (client_requires_channel_binding) {
			return SCRAM_CHANNEL_BINDING_REQUIRED;
		} else {
			return SCRAM_CHANNEL_BINDING_CLIENT_ONLY;
		}
	} else if (client_support && server_support) {
		/* Bullet point 3. */
		return SCRAM_CHANNEL_BINDING_REQUIRED;
	} else if (!client_support) {
		/* Bullet point 4. */
		if (client_requires_channel_binding) {
			return SCRAM_CHANNEL_BINDING_REQUIRED;
		}

		return SCRAM_CHANNEL_BINDING_UNSUPPORTED;
	}

	g_assert_not_reached ();
}


/*
 * Internal validation methods.
 */

/* Is the given byte an ASCII printable character? */
static gboolean
is_ascii_printable_char (guint8 c)
{
	return (c >= 0x20 &&  /* control chars */
	        c != 0x7f &&  /* delete */
	        c < 0x80  /* non-ASCII */);
}

/* Is the given buffer entirely full of ASCII printable characters? Set @buf_len
 * to -1 if @buf is nul-terminated. */
static gboolean
is_ascii_printable (const guint8 *buf, gssize buf_len)
{
	gsize i;

	for (i = 0;
	     (buf_len >= 0 && i < (gsize) buf_len) ||
	     (buf_len < 0 && buf[i] != '\0');
	     i++) {
		if (!is_ascii_printable_char (buf[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

/* Validate a nonce: the ‘r’ attribute from
 * http://tools.ietf.org/html/rfc5802#section-5.1
 *
 * Note: This does *not* validate uniqueness or equality with previously seen
 * nonces. */
static gboolean
validate_nonce (const gchar *nonce, GError **error)
{
	g_assert (nonce != NULL);

	if (strlen (nonce) < MINIMUM_NONCE_LENGTH ||
	    !is_ascii_printable ((const guint8 *) nonce, -1) ||
	    strchr (nonce, ',') != NULL) {  /* doesn’t contain commas */
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		             "The ‘r’ attribute must be at least %u bytes, "
		             "printable ASCII and not contain any commas.",
		             MINIMUM_NONCE_LENGTH);

		return FALSE;
	}

	return TRUE;
}

/* Validate a nonce’s uniqueness compared to previously seen nonces. */
static gboolean
validate_nonce_uniqueness (const gchar *nonce, GError **error)
{
	/* FIXME: This is not yet implemented. To do so requires persistent
	 * storage for a history of nonces seen by this peer, which is not
	 * feasible. As the nonce used for the core of the authentication
	 * operation is composed of nonces from both the server and client, and
	 * we always trust ourselves, we can be reasonably sure that the overall
	 * nonce contains at least 50% new random material. */
	return TRUE;
}

/* Validate a user salt: the ‘s’ attribute from:
 * http://tools.ietf.org/html/rfc5802#section-5.1 */
static gboolean
validate_salt_base64 (const gchar *salt_base64, GError **error)
{
	g_assert (salt_base64 != NULL);

	if (strlen (salt_base64) < MINIMUM_SALT_BASE64_LENGTH) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		             "The ‘s’ attribute must be at least %u bytes.",
		             MINIMUM_SALT_BASE64_LENGTH);

		return FALSE;
	}

	return TRUE;
}

/* Validate a user iteration count: the ‘i’ attribute from:
 * http://tools.ietf.org/html/rfc5802#section-5.1
 *
 * Note that this *does* validate the count against the @mechanism. */
static gboolean
validate_iter_count (guint32 iter_count,
                     ScramAuthenticationMechanism mechanism,
                     GError **error)
{
	guint32 min_count;

	switch (mechanism) {
	case SCRAM_AUTHENTICATION_SCRAM_SHA_1:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_1_PLUS:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_256:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_256_PLUS:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_512:
	case SCRAM_AUTHENTICATION_SCRAM_SHA_512_PLUS:
		/* Require at least 4096 iterations for SHA-1. See the final
		 * paragraph of the ‘i’ bullet point from:
		 * http://tools.ietf.org/html/rfc5802#section-6
		 * Note we extend this arbitrarily to SHA-256 and SHA-512. */
		min_count = MAX (MINIMUM_ITER_COUNT, 4096);
		break;
	case SCRAM_AUTHENTICATION_NONE:
	default:
		min_count = MINIMUM_ITER_COUNT;
	}

	if (iter_count < min_count) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		             "The ‘i’ attribute must be at least %u for the %u "
		             "authentication mechanism.", min_count, mechanism);

		return FALSE;
	}

	return TRUE;
}

/* Ensure ‘,’ and ‘=’ are correctly escaped in the string.
 *
 * Reference: final paragraph of the ‘n’ bullet in:
 * http://tools.ietf.org/html/rfc5802#section-5.1 */
static gboolean
is_properly_escaped (const gchar *str)
{
	const gchar *i;

	g_assert (str != NULL);

	for (i = str; *i != '\0'; i++) {
		if (*i == '=' &&
		    !(*(i + 1) == '2' && *(i + 2) == 'C') &&
		    !(*(i + 1) == '3' && *(i + 2) == 'D')) {
			return FALSE;
		}
	}

	return TRUE;
}

/* Validate a normalised username (i.e. as received off the wire): the ‘n’
 * attribute from: http://tools.ietf.org/html/rfc5802#section-5.1
 *
 * It must conform to the SASLprep profile (RFC 4013) of the StringPrep
 * algorithm (RFC 3454). */
static gboolean
validate_username_normalised (const gchar *username_normalised, GError **error)
{
	g_assert (username_normalised != NULL);

	if (strlen (username_normalised) < MINIMUM_USERNAME_LENGTH ||
	    !is_ascii_printable ((const guint8 *) username_normalised, -1) ||
	    !is_properly_escaped (username_normalised)) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		             "Usernames must be at least %u bytes long, "
		             "printable ASCII, and not contain badly escaped "
		             "‘=’ and ‘,’ symbols.", MINIMUM_USERNAME_LENGTH);

		return FALSE;
	}

	return TRUE;
}

/* Validate a non-normalised username (i.e. before normalising it and putting it
 * on the wire): the ‘n’ attribute from:
 * http://tools.ietf.org/html/rfc5802#section-5.1
 *
 * RFC 5802 is more permissive than this code: it permits any valid UTF-8 string
 * as a username. This code only permits ASCII. */
static gboolean
validate_username (const gchar *username, GError **error)
{
	g_assert (username != NULL);

	if (strlen (username) < MINIMUM_USERNAME_LENGTH ||
	    !is_ascii_printable ((const guint8 *) username, -1)) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		             "Usernames must be at least %u bytes long and be "
		             "printable ASCII.", MINIMUM_USERNAME_LENGTH);

		return FALSE;
	}

	return TRUE;
}

/* Validate a SASL mechanism against the given array of supported mechanisms. */
static gboolean
validate_mechanism (guchar mechanism,
                    const ScramAuthenticationMechanism *available_mechanisms,
                    guint n_available_mechanisms, GError **error)
{
	guint i;

	for (i = 0; i < n_available_mechanisms; i++) {
		if (mechanism == available_mechanisms[i]) {
			return TRUE;
		}
	}

	/* Not found. */
	g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
	             SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
	             "The mechanism %u is not supported by the server.",
	             mechanism);

	return FALSE;
}

/* Validate a non-normalised password (i.e. before normalising and hashing it
 * and putting it on the wire). */
static gboolean
validate_password (const gchar *password, GError **error)
{
	g_assert (password != NULL);

	if (strlen (password) < MINIMUM_PASSWORD_LENGTH ||
	    !is_ascii_printable ((const guint8 *) password, -1)) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		             "Passwords must be at least %u bytes long and be "
		             "printable ASCII.", MINIMUM_PASSWORD_LENGTH);

		return FALSE;
	}

	return TRUE;
}

/* Validate a salt before using it to hash a password. */
static gboolean
validate_salt (const guint8 *salt, gsize salt_len, GError **error)
{
	g_assert (salt != NULL);

	if (salt_len < MINIMUM_SALT_LENGTH) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_FAILED,
		             "The salt was shorter than the minimum allowed "
		             "length (%u).", MINIMUM_SALT_LENGTH);

		return FALSE;
	}

	return TRUE;
}

/* Validate a GS2 header: the ‘c’ attribute from:
 * http://tools.ietf.org/html/rfc5802#section-5.1
 *
 * See the final two paragraphs of http://tools.ietf.org/html/rfc5802#section-6
 * for the procedure. */
static gboolean
validate_gs2_header (const gchar *gs2_header_base64,
                     ScramAuthenticationChannelBinding channel_binding,
                     GError **error)
{
	const gchar *expected_gs2_header_base64;

	g_assert (gs2_header_base64 != NULL);

	/* Reference: ‘gs2-header’ in
	 * http://tools.ietf.org/html/rfc5802#section-7. */
	/* FIXME: For the moment we don’t support non-‘n’ channel bindings or
	 * SASL auth. identities. ‘biws’ is the base-64 encoding of ‘n,,’. */
	expected_gs2_header_base64 = "biws";

	if (strcmp (gs2_header_base64, expected_gs2_header_base64) != 0) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_MISMATCH,
		             "The client-provided channel binding (‘%s’) did "
		             "not match the binding expected by the server "
		             "(‘%s’).", gs2_header_base64,
		             expected_gs2_header_base64);

		return FALSE;
	}

	return TRUE;
}

/* Validate the client’s chosen channel binding against the valid types of
 * channel binding, and the client’s chosen authentication mechanism.
 *
 * See: http://tools.ietf.org/html/rfc5802#section-4 for an overview and
 * http://tools.ietf.org/html/rfc5802#section-6 for the procedure. */
static gboolean
validate_channel_binding (guchar channel_binding, const gchar *cb_name,
                          GVariant *cbind_data,
                          ScramAuthenticationMechanism chosen_mechanism,
                          const ScramAuthenticationMechanism *supported_mechanisms,
                          guint n_supported_mechanisms,
                          GError **error)
{
	gboolean server_support;

	/* Check the incoming byte is actually a valid channel binding. */
	if (channel_binding != SCRAM_CHANNEL_BINDING_UNSUPPORTED &&
	    channel_binding != SCRAM_CHANNEL_BINDING_CLIENT_ONLY &&
	    channel_binding != SCRAM_CHANNEL_BINDING_REQUIRED) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_CHANNEL_BINDING,
		             "The channel binding %u is not supported by the "
		             "server.",
		             channel_binding);

		return FALSE;
	}

	/* @cb_name must be set for REQUIRED bindings. */
	if ((channel_binding == SCRAM_CHANNEL_BINDING_REQUIRED) !=
	    (cb_name != NULL && *cb_name != '\0')) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_CHANNEL_BINDING,
		             "The channel binding name (‘%s’) must only be "
		             "specified if a channel binding is required.",
		             cb_name);

		return FALSE;
	}

	/* Check the binding against the chosen mechanism to verify that
	 * negotiation went OK. */
	server_support = server_supports_channel_binding (supported_mechanisms,
	                                                  n_supported_mechanisms);

	if (channel_binding == SCRAM_CHANNEL_BINDING_CLIENT_ONLY &&
	    server_support) {
		/* Bullet point 5.1. */
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_SERVER_SUPPORTS_CHANNEL_BINDING,
		             "The client incorrect believes the server does "
		             "not support channel binding. This may indicate "
		             "a downgrade attack.");

		return FALSE;
	} else if (channel_binding == SCRAM_CHANNEL_BINDING_REQUIRED &&
	           !mechanism_supports_channel_binding (chosen_mechanism)) {
		/* Bullet point 5.2. */
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_UNSUPPORTED,
		             "The channel binding %u is not appropriate for "
		             "the chosen authentication mechanism %u.",
		             channel_binding, chosen_mechanism);

		return FALSE;
	}

	return TRUE;
}

/* Validate a client proof: the ‘p’ attribute from
 * http://tools.ietf.org/html/rfc5802#section-5.1
 *
 * Note: This does *not* verify the proof. It merely checks syntax, base-64
 * decodes the client proof, and returns the decoded version (or %NULL on
 * error). The returned value must be freed with g_free(). */
static guint8 *
validate_client_proof (const gchar *client_proof_base64,
                       gsize *client_proof_len, GError **error)
{
	guint8 *client_proof = NULL;

	g_assert (client_proof_base64 != NULL);

	client_proof = g_base64_decode (client_proof_base64, client_proof_len);

	if (*client_proof_len <= 0) {
		goto error;
	}

	return client_proof;

error:
	g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
	             SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF,
	             "The client proof ‘%s’ is not the correct length.",
	             client_proof_base64);

	*client_proof_len = 0;
	g_free (client_proof);

	return NULL;
}

/* Validate a server signature: the ‘v’ attribute from
 * http://tools.ietf.org/html/rfc5802#section-5.1
 *
 * Note: This does *not* verify the signature. It merely checks syntax, base-64
 * decodes the server signature, and returns the decoded version (or %NULL on
 * error). The returned value must be freed with g_free(). */
static guint8 *
validate_server_signature (const gchar *server_signature_base64,
                           gsize *server_signature_len, GError **error)
{
	guint8 *server_signature = NULL;

	g_assert (server_signature_base64 != NULL);

	server_signature = g_base64_decode (server_signature_base64,
	                                    server_signature_len);

	if (*server_signature_len <= 0) {
		goto error;
	}

	return server_signature;

error:
	g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
	             SCRAM_AUTHENTICATION_ERROR_INVALID_SERVER_SIGNATURE,
	             "The server signature ‘%s’ is not the correct length.",
	             server_signature_base64);

	*server_signature_len = 0;
	g_free (server_signature);

	return NULL;
}

/* Validate that a received dictionary doesn’t contain unsupported extension
 * attributes.
 *
 * See the ‘m’ paragraph of: http://tools.ietf.org/html/rfc5802#section-5.1 */
static gboolean
validate_extension_attributes (GVariant *dict, GError **error)
{
	GVariant *m_value;

	m_value = g_variant_lookup_value (dict, "m", NULL);
	if (m_value != NULL) {
		/* The ‘m’ attribute (extension) is not supported.
		 * http://tools.ietf.org/html/rfc5802#section-5.1 */
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE,
		             "Extension attributes are not supported.");

		g_variant_unref (m_value);

		return FALSE;
	}

	return TRUE;
}


/* Convert a string error value to an enum value.
 *
 * See ‘server-error-value’ in: http://tools.ietf.org/html/rfc5802#section-7 */
static ScramAuthenticationError
error_value_to_code (const gchar *error_value)
{
	guint i;
	const struct {
		const gchar *error_value;
		ScramAuthenticationError error_code;
	} mappings[] = {
		{ "invalid-encoding", SCRAM_AUTHENTICATION_ERROR_FAILED },
		{ "extensions-not-supported",
		  SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE },
		{ "invalid-proof",
		  SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF },
		{ "channel-bindings-dont-match",
		  SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_MISMATCH },
		{ "server-does-support-channel-binding",
		  SCRAM_AUTHENTICATION_ERROR_SERVER_SUPPORTS_CHANNEL_BINDING },
		{ "channel-binding-not-supported",
		  SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_UNSUPPORTED },
		{ "unsupported-channel-binding-type",
		  SCRAM_AUTHENTICATION_ERROR_INVALID_CHANNEL_BINDING },
		{ "unknown-user", SCRAM_AUTHENTICATION_ERROR_UNKNOWN_USER },
		{ "invalid-username-encoding",
		  SCRAM_AUTHENTICATION_ERROR_FAILED },
		{ "no-resources", SCRAM_AUTHENTICATION_ERROR_FAILED },
		{ "other-error", SCRAM_AUTHENTICATION_ERROR_FAILED },
	};

	for (i = 0; i < G_N_ELEMENTS (mappings); i++) {
		if (strcmp (error_value, mappings[i].error_value) == 0) {
			return mappings[i].error_code;
		}
	}

	return SCRAM_AUTHENTICATION_ERROR_FAILED;
}

/* And the reverse direction. (These have to be two total functions since the
 * mapping isn’t reversible.) */
static const gchar *
error_code_to_value (ScramAuthenticationError error_code)
{
	switch (error_code) {
	case SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE:
		return "extensions-not-supported";
	case SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF:
		return "invalid-proof";
	case SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_MISMATCH:
		return "channel-bindings-dont-match";
	case SCRAM_AUTHENTICATION_ERROR_SERVER_SUPPORTS_CHANNEL_BINDING:
		return "server-does-support-channel-binding";
	case SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_UNSUPPORTED:
		return "channel-binding-not-supported";
	case SCRAM_AUTHENTICATION_ERROR_INVALID_CHANNEL_BINDING:
		return "unsupported-channel-binding-type";
	case SCRAM_AUTHENTICATION_ERROR_UNKNOWN_USER:
		return "unknown-user";
	case SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE:
	case SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE:
	case SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE:
	case SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE:
	case SCRAM_AUTHENTICATION_ERROR_INVALID_SERVER_SIGNATURE:
	case SCRAM_AUTHENTICATION_ERROR_FAILED:
	default:
		return "other-error";
	}
}

/* Validate that a received dictionary doesn’t contain an error attribute. If it
 * does, parse that attribute and set @error. If @errors_supported is %FALSE,
 * return an %SCRAM_AUTHENTICATION_UNSUPPORTED_ATTRIBUTE error instead of
 * parsing the error value.
 *
 * See the ‘e’ paragraph of: http://tools.ietf.org/html/rfc5802#section-5.1 */
static gboolean
validate_error_attributes (GVariant *dict, gboolean errors_supported,
                           GError **error)
{
	const gchar *error_value = NULL;

	if (g_variant_lookup (dict, "e", "&s", &error_value)) {
		if (errors_supported) {
			g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
			             error_value_to_code (error_value),
			             "Authentication failed on the server with "
			             "error value ‘%s’.", error_value);
		} else {
			g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
			             SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE,
			             "Error attributes are not supported on "
			             "client messages.");
		}

		return FALSE;
	}

	return TRUE;
}

/* Check that all mechanisms in the given array are valid (i.e. not NONE). */
static gboolean
validate_mechanisms (const ScramAuthenticationMechanism *mechanisms,
                     guint n_mechanisms)
{
	guint i;

	g_return_val_if_fail (mechanisms != NULL, FALSE);
	g_return_val_if_fail (n_mechanisms > 0, FALSE);

	for (i = 0; i < n_mechanisms; i++) {
		if (mechanisms[i] == SCRAM_AUTHENTICATION_NONE) {
			return FALSE;
		}
	}

	return TRUE;
}


/*
 * StringPrep helper methods. From RFC 4013.
 *
 * Note: This is not a full implementation of RFC 4013 (or its prerequisite,
 * RFC 3454). It restricts input to ASCII only, and thus can skip the Mapping,
 * Normalization, and Bidirectional Characters steps, and only has to implement
 * the Prohibited Output step.
 */

/* Returns the length of the normalised buffer stored in @out. On error, @error
 * is set and 0 is returned. @out and @buf may alias. The returned value in
 * @out is nul-terminated if @out_len is greater than @buf_len, but the nul byte
 * is not counted in the return value. */
static gsize
calculate_normalize (guint8 *out, gsize out_len,
                     const guint8 *buf, gsize buf_len, GError **error)
{
	g_assert (out != NULL);
	g_assert_cmpuint (out_len, >=, buf_len);
	g_assert (buf != NULL);
	g_assert (error == NULL || *error == NULL);

	/* Mapping, Normalization and Bidirectional Characters. */
	memmove (out, buf, MIN (out_len, buf_len));
	if (out_len > buf_len) {
		out[buf_len] = '\0';
	}

	/* Prohibited Output step. */
	if (!is_ascii_printable (buf, buf_len)) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		             "Buffer to be normalised is not printable ASCII.");

		return 0;
	}

	return buf_len;
}


/*
 * Cryptographic helper methods. From RFC 5802.
 */

/* Implement the HMAC calculation from:
 * http://tools.ietf.org/html/rfc5802#section-2.2
 *
 * @out_len must be long enough to hold a checksum of the given @digest_type.
 * The number of bytes of @out which were used is returned. */
static gsize
calculate_hmac (GChecksumType digest_type,
                guint8 *out, gsize out_len,
                const guint8 *key, gsize key_len,
                const guint8 *data, gsize data_len)
{
	GHmac *hmac;

	g_assert (out != NULL);
	g_assert (key != NULL);
	g_assert (data != NULL);
	g_assert_cmpuint (key_len, >, 0);
	g_assert_cmpuint (data_len, >, 0);
	g_assert (g_checksum_type_get_length (digest_type) != -1);
	g_assert_cmpuint (out_len, >=,
	                  g_checksum_type_get_length (digest_type));

	hmac = g_hmac_new (digest_type, key, key_len);
	g_hmac_update (hmac, data, data_len);
	g_hmac_get_digest (hmac, out, &out_len);
	g_hmac_unref (hmac);

	return out_len;
}

/* Implement the H calculation from:
 * http://tools.ietf.org/html/rfc5802#section-2.2
 *
 * @out_len must be long enough to hold a checksum of the given @digest_type.
 * The number of bytes of @out which were used is returned. */
static gsize
calculate_h (GChecksumType digest_type,
             guint8 *out, gsize out_len,
             const guint8 *data, gsize data_len)
{
	GChecksum *checksum;

	g_assert (out != NULL);
	g_assert (data != NULL);
	g_assert_cmpuint (data_len, >, 0);
	g_assert (g_checksum_type_get_length (digest_type) != -1);
	g_assert_cmpuint (out_len, >=,
	                  g_checksum_type_get_length (digest_type));

	checksum = g_checksum_new (digest_type);
	g_checksum_update (checksum, data, data_len);
	g_checksum_get_digest (checksum, out, &out_len);
	g_checksum_free (checksum);

	return out_len;
}

/* Implement the XOR calculation from:
 * http://tools.ietf.org/html/rfc5802#section-2.2
 *
 * The length of @out, @a and @b must be @len. @out, @a and @b may alias. */
static gsize
calculate_xor (guint8 *out, const guint8 *a, const guint8 *b, gsize len)
{
	gsize i;

	g_assert (out != NULL);
	g_assert (a != NULL);
	g_assert (b != NULL);

	for (i = 0; i < len; i++) {
		out[i] = a[i] ^ b[i];
	}

	return len;
}

/* Implement the Hi calculation from:
 * http://tools.ietf.org/html/rfc5802#section-2.2
 *
 * Hi(str, salt, i):
 *
 *     U1   := HMAC(str, salt + INT(1))
 *     U2   := HMAC(str, U1)
 *     ...
 *     Ui-1 := HMAC(str, Ui-2)
 *     Ui   := HMAC(str, Ui-1)
 *
 *     Hi := U1 XOR U2 XOR ... XOR Ui
 *
 *
 * Returns the number of valid bytes in @hi, which is guaranteed to be no
 * greater than @hi_len. @hi_len must be big enough for the given @digest_type.
 * The @iter_count must be at least 1. This cannot fail. @hi and @str must not
 * alias or overlap. */
static gsize
calculate_hi (GChecksumType digest_type,
              guint8 *hi, gsize hi_len,
              const guint8 *str, gsize str_len,
              const guint8 *salt, gsize salt_len,
              guint32 iter_count)
{
	GHmac *hmac;
	guint32 i;
	guint8 ui[MAXIMUM_CHECKSUM_LENGTH];
	gsize ui_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 suffix[] = { 0x00, 0x00, 0x00, 0x01 };

	g_assert (g_checksum_type_get_length (digest_type) != -1);
	g_assert (hi != NULL);
	g_assert_cmpuint (hi_len, >=, g_checksum_type_get_length (digest_type));
	g_assert (str != NULL);
	g_assert_cmpuint (str_len, >, 0);
	g_assert (salt != NULL);
	g_assert_cmpuint (salt_len, >, 0);
	g_assert_cmpuint (iter_count, >=, 1);
	g_assert (hi != str);
	g_assert_cmpuint (ui_len, >=, g_checksum_type_get_length (digest_type));

	/* Calculate U1. */
	hmac = g_hmac_new (digest_type, str, str_len);
	g_hmac_update (hmac, salt, salt_len);
	g_hmac_update (hmac, suffix, sizeof (suffix));
	g_hmac_get_digest (hmac, ui, &ui_len);
	g_hmac_unref (hmac);

	/* Initialise Hi, which will be successively XORed onto.
	 * In the loop, i is the subscript of the Ui on the left hand side of
	 * the calculation. */
	memcpy (hi, ui, MIN (ui_len, hi_len));

	g_assert_cmpuint (ui_len, <=, hi_len);

	for (i = 2; i <= iter_count; i++) {
		/* Calculate Ui for i ∈ (2, iter_count). */
		ui_len = calculate_hmac (digest_type, ui, ui_len, str, str_len,
		                         ui, ui_len);

		/* Update Hi. */
		calculate_xor (hi, hi, ui, ui_len);
	}

	return ui_len;
}

/* Implement the SaltedPassword calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * Hi(Normalize(password), salt, i)
 *
 * Returns the output in @salted_password. Returns 0 on error. */
static gsize
calculate_salted_password (GChecksumType digest_type,
                           guint8 *salted_password, gsize salted_password_len,
                           const guint8 *password, gsize password_len,
                           const guint8 *salt, gsize salt_len,
                           guint32 iter_count, GError **error)
{
	GError *child_error = NULL;
	guint8 *normalised_password;  /* owned */
	gsize normalised_password_len;

	/* Normalise the password in-place. */
	normalised_password_len = password_len;
	normalised_password = g_malloc (normalised_password_len);
	normalised_password_len = calculate_normalize (normalised_password,
	                                               normalised_password_len,
	                                               password, password_len,
	                                               &child_error);
	if (child_error != NULL) {
		g_propagate_error (error, child_error);
		g_free (normalised_password);

		return 0;
	}

	salted_password_len =
		calculate_hi (digest_type, salted_password, salted_password_len,
		              normalised_password, normalised_password_len,
		              salt, salt_len, iter_count);

	g_free (normalised_password);

	return salted_password_len;
}

/* Implement the ClientKey calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * ClientKey := HMAC(SaltedPassword, "Client Key")
 *
 * Return the length of the output stored in @client_key. */
static gsize
calculate_client_key (GChecksumType digest_type,
                      guint8 *client_key, gsize client_key_len,
                      const guint8 *salted_password, gsize salted_password_len)
{
	return calculate_hmac (digest_type,
	                       client_key, client_key_len,
	                       salted_password, salted_password_len,
	                       (const guint8 *) "Client Key",
	                       strlen ("Client Key"));
}

/* Implement the StoredKey calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * StoredKey       := H(ClientKey)
 *
 * Return the length of the output stored in @stored_key. */
static gsize
calculate_stored_key (GChecksumType digest_type,
                      guint8 *stored_key, gsize stored_key_len,
                      const guint8 *client_key, gsize client_key_len)
{
	return calculate_h (digest_type,
	                    stored_key, stored_key_len,
	                    client_key, client_key_len);
}

/* Implement the AuthMessage calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * AuthMessage := client-first-message-bare + "," +
 *                server-first-message + "," +
 *                client-final-message-without-proof
 *
 * using the message definitions from:
 * http://tools.ietf.org/html/rfc5802#section-7
 *
 * nonce           = "r=" c-nonce [s-nonce]
 *                   ;; Second part provided by server.
 * c-nonce         = printable
 * s-nonce         = printable
 * username        = "n=" saslname
 *                   ;; Usernames are prepared using SASLprep.
 * client-first-message-bare =
 *                   [reserved-mext ","]
 *                   username "," nonce ["," extensions]
 *
 * salt            = "s=" base64
 * iteration-count = "i=" posit-number
 *                   ;; A positive number.
 * server-first-message =
 *                   [reserved-mext ","] nonce "," salt ","
 *                   iteration-count ["," extensions]
 *
 * channel-binding = "c=" base64
 *                   ;; base64 encoding of cbind-input.
 * client-final-message-without-proof =
 *                   channel-binding "," nonce [","
 *                   extensions]
 *
 * Returns the constructed message as a newly allocated #GBytes. */
static GBytes *
calculate_auth_message (const gchar *username_normalised,
                        const gchar *client_nonce, const gchar *server_nonce,
                        const gchar *salt_base64, guint32 iteration_count,
                        const gchar *cbind_input_base64)
{
	gchar *str;

	/* All the inputs here are ASCII printable, so they’re all
	 * nul-terminated in memory, and hence safe to use with
	 * g_strdup_printf(), which makes things nice and easy. */
	str = g_strdup_printf (
		/* client-first-message-bare */
		"n=" "%s" ","  /* username */
		"r=" "%s" ","  /* nonce */
		/* server-first-message */
		"r=" "%s" "%s" ","  /* nonce */
		"s=" "%s" ","  /* salt */
		"i=" "%u" ","  /* iteration-count */
		/* client-final-message-without-proof */
		"c=" "%s" ","  /* channel-binding */
		"r=" "%s" "%s"  /* nonce */,
		username_normalised,
		client_nonce,
		client_nonce, server_nonce,
		salt_base64,
		iteration_count,
		cbind_input_base64,
		client_nonce, server_nonce);

	return g_bytes_new_take (str, strlen (str));
}

/* Implement the ClientSignature calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * ClientSignature := HMAC(StoredKey, AuthMessage)
 *
 * Return the length of the output stored in @client_signature. */
static gsize
calculate_client_signature (GChecksumType digest_type,
                            guint8 *client_signature,
                            gsize client_signature_len,
                            const guint8 *stored_key, gsize stored_key_len,
                            const guint8 *auth_message, gsize auth_message_len)
{
	return calculate_hmac (digest_type,
	                       client_signature, client_signature_len,
	                       stored_key, stored_key_len,
	                       auth_message, auth_message_len);
}

/* Implement the ClientProof calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * ClientProof     := ClientKey XOR ClientSignature
 *
 * Return the length of the output stored in @client_proof. */
static gsize
calculate_client_proof (guint8 *client_proof, gsize client_proof_len,
                        const guint8 *client_key, gsize client_key_len,
                        const guint8 *client_signature,
                        gsize client_signature_len)
{
	g_assert (client_proof != NULL);
	g_assert (client_key != NULL);
	g_assert (client_signature != NULL);
	g_assert_cmpuint (client_proof_len, >=, client_key_len);
	g_assert_cmpuint (client_key_len, ==, client_signature_len);

	return calculate_xor (client_proof, client_key, client_signature,
	                      client_key_len);
}

/* Implement the ServerKey calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * ServerKey := HMAC(SaltedPassword, "Server Key")
 *
 * Return the length of the output stored in @server_key. */
static gsize
calculate_server_key (GChecksumType digest_type,
                      guint8 *server_key, gsize server_key_len,
                      const guint8 *salted_password, gsize salted_password_len)
{
	return calculate_hmac (digest_type,
	                       server_key, server_key_len,
	                       salted_password, salted_password_len,
	                       (const guint8 *) "Server Key",
	                       strlen ("Server Key"));
}

/* Implement the ServerSignature calculation from:
 * http://tools.ietf.org/html/rfc5802#section-3
 *
 * ServerSignature := HMAC(ServerKey, AuthMessage)
 *
 * Return the length of the output stored in @server_signature. */
static gsize
calculate_server_signature (GChecksumType digest_type,
                            guint8 *server_signature,
                            gsize server_signature_len,
                            const guint8 *server_key, gsize server_key_len,
                            const guint8 *auth_message, gsize auth_message_len)
{
	return calculate_hmac (digest_type,
	                       server_signature, server_signature_len,
	                       server_key, server_key_len,
	                       auth_message, auth_message_len);
}


/**
 * scram_authentication_client_init:
 * @client: an #ScramAuthenticationClient
 * @client_nonce: a randomly generated nonce to use in the client
 * @supported_mechanisms: (array length=n_supported_mechanisms): array of
 * #ScramAuthenticationMechanisms giving the mechanisms supported by the server
 * @n_supported_mechanisms: number of elements in @supported_mechanisms
 * @require_channel_binding: %TRUE if the client requires channel binding,
 * %FALSE otherwise
 *
 * Initialise a previously allocated #ScramAuthenticationClient instance. Once
 * finished with, the client must be cleared using
 * scram_authentication_client_clear().
 *
 * The @client_nonce should be randomly generated using (e.g.)
 * scram_authentication_generate_nonce() or some other secure random number
 * generator.
 *
 * The @supported_mechanisms must be provided out-of-band by the authentication
 * server. @require_channel_binding determines whether the client will demand
 * channel binding in the mechanism negotiation process.
 */
void
scram_authentication_client_init (ScramAuthenticationClient *client,
                                  const gchar *client_nonce,
                                  const ScramAuthenticationMechanism *supported_mechanisms,
                                  gsize n_supported_mechanisms,
                                  gboolean require_channel_binding)
{
	g_return_if_fail (client != NULL);
	g_return_if_fail (validate_mechanisms (supported_mechanisms,
	                                       n_supported_mechanisms));

	client->chosen_mechanism = choose_mechanism (supported_mechanisms,
	                                             n_supported_mechanisms);

	client->channel_binding =
		client_choose_channel_binding (client->chosen_mechanism,
		                               supported_mechanisms,
		                               n_supported_mechanisms,
		                               require_channel_binding);

	/* FIXME: Channel binding is currently unsupported. */
	g_assert (!require_channel_binding);
	g_assert_cmpuint (client->channel_binding, ==,
	                  SCRAM_CHANNEL_BINDING_UNSUPPORTED);

	client->client_nonce = g_strdup (client_nonce);

	client->username_normalised = NULL;
	client->password = NULL;

	client->nonce = NULL;
	client->server_nonce = NULL;
	client->salt_base64 = NULL;
	client->iter_count = G_MAXUINT32;
}

/**
 * scram_authentication_client_clear:
 * @client: (transfer none): an #ScramAuthenticationClient
 *
 * Clear a previously initialised @ScramAuthenticationClient instance. This
 * frees all memory associated with the client (except @client itself, which is
 * owned by the caller).
 */
void
scram_authentication_client_clear (ScramAuthenticationClient *client)
{
	g_free (client->salt_base64);
	g_free (client->nonce);
	g_free (client->client_nonce);
	g_free (client->password);
	g_free (client->username_normalised);
}


/**
 * scram_authentication_server_init:
 * @server: an #ScramAuthenticationServer
 * @server_nonce: a randomly generated nonce to use in the server
 * @available_mechanisms: (array length=n_supported_mechanisms): array of
 * #ScramAuthenticationMechanisms giving the mechanisms supported by the server
 * @n_available_mechanisms: number of elements in @available_mechanisms
 *
 * Initialise a previously allocated #ScramAuthenticationServer instance. Once
 * finished with, the server must be cleared using
 * scram_authentication_server_clear().
 *
 * The @server_nonce should be randomly generated using (e.g.)
 * scram_authentication_generate_nonce() or some other secure random number
 * generator.
 *
 * The @available_mechanisms must be a non-empty array of
 * #ScramAuthenticationMechanisms supported by the server. All mechanisms in
 * #ScramAuthenticationMechanism are supported, but %SCRAM_AUTHENTICATION_NONE
 * must not be used. This list of mechanisms must be sent out-of-band to any
 * client which connects to the server, so that it may initiate mechanism
 * negotation.
 *
 * Note this doesn’t impose policy on channel binding: the caller must decide
 * their channel binding policy and set @available_mechanisms as appropriate;
 * e.g. by limiting it to ‘-PLUS’ mechanisms, or excluding them entirely.
 * See: <ulink url="http://tools.ietf.org/html/rfc5802#section-6">RFC 5802,
 * §6</ulink>.
 */
void
scram_authentication_server_init (ScramAuthenticationServer *server,
                                  const gchar *server_nonce,
                                  const ScramAuthenticationMechanism *available_mechanisms,
                                  guint n_available_mechanisms)
{
	g_return_if_fail (server != NULL);
	g_return_if_fail (validate_mechanisms (available_mechanisms,
	                                       n_available_mechanisms));

	server->available_mechanisms = available_mechanisms;
	server->n_available_mechanisms = n_available_mechanisms;

	/* FIXME: Channel binding is currently unsupported. */
	g_assert (!server_supports_channel_binding (available_mechanisms,
	                                            n_available_mechanisms));

	server->chosen_mechanism = SCRAM_AUTHENTICATION_NONE;
	server->server_nonce = g_strdup (server_nonce);

	server->salt_base64 = NULL;
	server->iter_count = G_MAXUINT32;
	server->server_key = NULL;
	server->stored_key = NULL;

	server->client_nonce = NULL;
	server->username_normalised = NULL;
	server->channel_binding = SCRAM_CHANNEL_BINDING_UNKNOWN;

	server->error = NULL;
}

/**
 * scram_authentication_server_clear:
 * @server: (transfer none): an #ScramAuthenticationServer
 *
 * Clear a previously initialised @ScramAuthenticationServer instance. This
 * frees all memory associated with the server (except @server itself, which is
 * owned by the caller).
 */
void
scram_authentication_server_clear (ScramAuthenticationServer *server)
{
	g_clear_error (&server->error);
	g_free (server->username_normalised);
	g_free (server->client_nonce);
	if (server->server_key != NULL) {
		g_bytes_unref (server->server_key);
	}
	if (server->stored_key != NULL) {
		g_bytes_unref (server->stored_key);
	}
	g_free (server->salt_base64);
	g_free (server->server_nonce);
}


/**
 * scram_authentication_client_get_chosen_mechanism:
 * @client: an #ScramAuthenticationClient
 *
 * Get the authentication mechanism agreed between the client and server. Before
 * scram_authentication_client_parse_first_reply() is called, this will be
 * %SCRAM_AUTHENTICATION_NONE. It is guaranteed to be a different mechanism
 * afterwards, unless authentication has failed.
 *
 * Returns: the chosen authentication mechanism
 */
ScramAuthenticationMechanism
scram_authentication_client_get_chosen_mechanism (ScramAuthenticationClient *client)
{
	g_return_val_if_fail (client != NULL, SCRAM_AUTHENTICATION_NONE);

	return client->chosen_mechanism;
}

/**
 * scram_authentication_server_get_chosen_mechanism:
 * @server: an #ScramAuthenticationServer
 *
 * Get the authentication mechanism agreed between the client and server. Before
 * scram_authentication_server_parse_first_message() is called, this will be
 * %SCRAM_AUTHENTICATION_NONE. It is guaranteed to be a different mechanism
 * afterwards, unless authentication has failed.
 *
 * Returns: the chosen authentication mechanism
 */
ScramAuthenticationMechanism
scram_authentication_server_get_chosen_mechanism (ScramAuthenticationServer *server)
{
	g_return_val_if_fail (server != NULL, SCRAM_AUTHENTICATION_NONE);

	return server->chosen_mechanism;
}


/**
 * scram_authentication_client_build_first_message:
 * @client: an #ScramAuthenticationClient
 * @username: username to authenticate with
 * @password: plaintext password associated with @username
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Build the first authentication message sent from client to server. This
 * specifies the username to connect with, plus the unhashed, unsalted password
 * to use.
 *
 * On error, %NULL is returned and @error is set. Building the message may fail
 * if the username or password can’t be validated or normalised.
 *
 * Returns: (transfer full): a floating #GVariant containing the first message;
 * free with g_variant_unref()
 */
GVariant *
scram_authentication_client_build_first_message (ScramAuthenticationClient *client,
                                                 const gchar *username,
                                                 const gchar *password,
                                                 GError **error)
{
	GVariantBuilder builder;
	guint8 *username_normalised;
	gsize username_normalised_len;

	g_return_val_if_fail (client != NULL, NULL);
	g_return_val_if_fail (username != NULL, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	/* Validate input. */
	if (!validate_username (username, error) ||
	    !validate_password (password, error)) {
		return NULL;
	}

	/* Update client state.
	 * Normalise the username according to the ‘n’ paragraph of:
	 * http://tools.ietf.org/html/rfc5802#section-5.1 */
	username_normalised_len = strlen (username) + 1  /* nul byte */;
	username_normalised = g_malloc (username_normalised_len);
	username_normalised_len = calculate_normalize (username_normalised,
	                                               username_normalised_len,
	                                               (const guint8 *) username,
	                                               strlen (username),
	                                               error);

	if (username_normalised_len == 0) {
		return NULL;
	}

	client->username_normalised = (gchar *) username_normalised;  /* tfr. */
	client->password = g_strdup (password);

	/* Build the message. */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("(y(yssay)a{sv})"));

	/* Header. */
	g_variant_builder_add (&builder, "y",
	                       (guchar) client->chosen_mechanism);

	/* Channel binding. See ‘cbind-input’ from
	 * http://tools.ietf.org/html/rfc5802#section-7 */
	g_variant_builder_open (&builder, G_VARIANT_TYPE ("(yssay)"));

	g_variant_builder_add (&builder, "y", (guchar) client->channel_binding);
	g_variant_builder_add (&builder, "s", "")  /* cb-name */;
	g_variant_builder_add (&builder, "s", "")  /* authzid */;
	g_variant_builder_add (&builder, "ay", NULL)  /* cbind-data */;

	g_variant_builder_close (&builder);

	/* Key–value pairs. */
	g_variant_builder_open (&builder, G_VARIANT_TYPE ("a{sv}"));

	g_variant_builder_add (&builder, "{sv}", "n",
	                       g_variant_new_string (client->username_normalised));
	g_variant_builder_add (&builder, "{sv}", "r",
	                       g_variant_new_string (client->client_nonce));

	g_variant_builder_close (&builder);

	return g_variant_builder_end (&builder);
}

/**
 * scram_authentication_server_parse_first_message:
 * @server: an #ScramAuthenticationServer
 * @message: the incoming message to parse
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Parse the first message received by the server from the client and extract
 * the authentication username from it.
 *
 * On error, %NULL will be returned and @error will be set. An error can occur
 * if the incoming message is badly formatted, contains an invalid username, or
 * if mechanism negotiation or channel binding fails.
 *
 * Returns: (transfer full): the username being used to authenticate, or %NULL
 * on error; free with g_free()
 */
gchar *
scram_authentication_server_parse_first_message (ScramAuthenticationServer *server,
                                                 GVariant *message,
                                                 GError **error)
{
	GVariant *dict = NULL;
	guchar chosen_mechanism;  /* actually #ScramAuthenticationMechanism */
	guchar channel_binding;  /* actually #ScramAuthenticationChannelBinding */
	const gchar *client_nonce = NULL, *username_normalised = NULL;
	const gchar *sasl_auth_identity = NULL;
	const gchar *cb_name = NULL;
	GVariant *cbind_data = NULL;  /* owned */
	GError *child_error = NULL;

	/* Check @reply type. */
	if (!g_variant_is_of_type (message,
	                           G_VARIANT_TYPE ("(y(yssay)a{sv})"))) {
		g_set_error (&child_error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE,
		             "First message from client had an invalid type.");

		goto done;
	}

	/* Parse @reply. FIXME: Channel binding isn’t implemented yet. */
	g_variant_get (message, "(y(y&s&s@ay)@a{sv})",
	               &chosen_mechanism,
	               &channel_binding,  /* gs2-cbind-flag */
	               &cb_name,  /* cb-name */
	               &sasl_auth_identity,  /* authzid */
	               &cbind_data,  /* cbind-data */
	               &dict);

	if (!validate_error_attributes (dict, FALSE, &child_error)) {
		goto done;
	}

	/* Check the mechanism before proceeding. */
	if (!validate_mechanism (chosen_mechanism, server->available_mechanisms,
	                         server->n_available_mechanisms,
	                         &child_error)) {
		goto done;
	}

	if (!g_variant_lookup (dict, "r", "&s", &client_nonce) ||
	    !g_variant_lookup (dict, "n", "&s", &username_normalised)) {
		/* Required attributes. */
		g_set_error (&child_error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		             "The ‘r’ and ‘n’ attributes are required in the "
		             "first message.");

		goto done;
	}

	if ((sasl_auth_identity != NULL && *sasl_auth_identity != '\0') ||
	    g_variant_lookup (dict, "a", "&s", NULL)) {
		/* The ‘a’ attribute (SASL authentication identity) is not
		 * supported. http://tools.ietf.org/html/rfc5802#section-5.1 */
		g_set_error (&child_error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_UNKNOWN_USER,
		             "SASL authentication identities are not "
		             "supported.");

		goto done;
	}

	if (!validate_extension_attributes (dict, &child_error)) {
		goto done;
	}

	/* Validate the values individually. */
	if (!validate_channel_binding (channel_binding, cb_name, cbind_data,
	                               chosen_mechanism,
	                               server->available_mechanisms,
	                               server->n_available_mechanisms,
	                               &child_error)) {
		goto done;
	}

	if (!validate_nonce (client_nonce, &child_error)) {
		goto done;
	}

	if (!validate_username_normalised (username_normalised, &child_error)) {
		goto done;
	}

	if (!validate_nonce_uniqueness (client_nonce, &child_error)) {
		goto done;
	}

	/* Update the server’s state. */
	server->client_nonce = g_strdup (client_nonce);
	server->username_normalised = g_strdup (username_normalised);
	server->channel_binding = channel_binding;
	server->chosen_mechanism = chosen_mechanism;

done:
	if (cbind_data != NULL) {
		g_variant_unref (cbind_data);
	}
	if (dict != NULL) {
		g_variant_unref (dict);
	}

	if (child_error != NULL) {
		g_assert (server->username_normalised == NULL);
		g_clear_error (&server->error);
		server->error = g_error_copy (child_error);
		g_propagate_error (error, child_error);
	}

	return g_strdup (server->username_normalised);
}

/* Build an error message for the server to return to the client.
 *
 * See the ‘e’ paragraph of: http://tools.ietf.org/html/rfc5802#section-5.1 */
static GVariant *
server_build_error_message (ScramAuthenticationServer *server)
{
	GVariantBuilder builder;
	const gchar *error_value;

	g_assert (server->error != NULL);
	g_assert (server->error->domain == SCRAM_AUTHENTICATION_ERROR);

	error_value = error_code_to_value (server->error->code);

	/* Build the message. */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("(a{sv})"));

	g_variant_builder_open (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add (&builder, "{sv}", "e",
	                       g_variant_new_string (error_value));
	g_variant_builder_close (&builder);

	return g_variant_builder_end (&builder);
}

/**
 * scram_authentication_server_build_first_reply:
 * @server: an #ScramAuthenticationServer
 * @salt: (transfer none): the salt used when hashing the client’s password
 * during the production of the @server_key and @stored_key
 * @iter_count: the number of hash iterations applied to the client’s password
 * during the production of the @server_key and @stored_key
 * @server_key: (transfer none): a stored server key, which is a HMAC of the
 * user’s salted password
 * @stored_key: (transfer none): a stored client key, which is a hash of a
 * different HMAC of the user’s salted password
 *
 * Build the first authentication reply sent from server to client. This
 * specifies the server’s stored data for the username provided by the client,
 * which is all derived from the client’s password.
 *
 * This function cannot fail.
 *
 * Returns: (transfer full): a floating #GVariant containing the first reply;
 * free with g_variant_unref()
 */
GVariant *
scram_authentication_server_build_first_reply (ScramAuthenticationServer *server,
                                               GBytes *salt,
                                               guint32 iter_count,
                                               GBytes *server_key,
                                               GBytes *stored_key)
{
	GVariantBuilder builder;
	gchar *nonce;

	g_return_val_if_fail (server != NULL, NULL);

	/* Propagate errors from the first message. */
	if (server->error != NULL) {
		return server_build_error_message (server);
	}

	g_return_val_if_fail (salt != NULL, NULL);
	g_return_val_if_fail (iter_count > 0, NULL);
	g_return_val_if_fail (server_key != NULL, NULL);
	g_return_val_if_fail (stored_key != NULL, NULL);

	/* Validate input. */
	if (!validate_salt (g_bytes_get_data (salt, NULL),
	                    g_bytes_get_size (salt), NULL) ||
	    !validate_iter_count (iter_count, server->chosen_mechanism, NULL)) {
		return NULL;
	}

	/* Update server state. */
	server->salt_base64 =
		g_base64_encode (g_bytes_get_data (salt, NULL),
		                 g_bytes_get_size (salt));
	server->iter_count = iter_count;
	server->server_key = g_bytes_ref (server_key);
	server->stored_key = g_bytes_ref (stored_key);

	/* Build the message. */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("(a{sv})"));

	nonce = g_strconcat (server->client_nonce, server->server_nonce, NULL);

	/* Key–value pairs. */
	g_variant_builder_open (&builder, G_VARIANT_TYPE ("a{sv}"));

	g_variant_builder_add (&builder, "{sv}", "r",
	                       g_variant_new_string (nonce));
	g_variant_builder_add (&builder, "{sv}", "s",
	                       g_variant_new_string (server->salt_base64));
	g_variant_builder_add (&builder, "{sv}", "i",
	                       g_variant_new_uint32 (server->iter_count));

	g_free (nonce);

	g_variant_builder_close (&builder);

	return g_variant_builder_end (&builder);
}

/**
 * scram_authentication_client_parse_first_reply:
 * @client: an #ScramAuthenticationClient
 * @reply: the incoming message to parse
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Parse the first reply received by the client from the server and update the
 * @client’s state with information from it.
 *
 * On error, @error will be set. An error can occur if the incoming message is
 * badly formatted, or contains an invalid nonce.
 */
void
scram_authentication_client_parse_first_reply (ScramAuthenticationClient *client,
                                               GVariant *reply,
                                               GError **error)
{
	GVariant *dict;
	const gchar *nonce = NULL, *salt_base64 = NULL;
	guint32 iter_count = G_MAXUINT32;
	const gchar *server_nonce = NULL;

	/* Check @reply type. */
	if (!g_variant_is_of_type (reply, G_VARIANT_TYPE ("(a{sv})"))) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE,
		             "First reply from server had an invalid type.");
		return;
	}

	/* Parse @reply. */
	dict = g_variant_get_child_value (reply, 0);

	if (!validate_error_attributes (dict, TRUE, error)) {
		goto done;
	}

	if (!g_variant_lookup (dict, "r", "&s", &nonce) ||
	    !g_variant_lookup (dict, "s", "&s", &salt_base64) ||
	    !g_variant_lookup (dict, "i", "u", &iter_count)) {
		/* Required attributes. */
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		             "The ‘r’, ‘s’ and ‘i’ attributes are required in "
		             "the first reply.");

		goto done;
	}

	if (!validate_extension_attributes (dict, error)) {
		goto done;
	}

	/* Validate the values individually. */
	if (!validate_nonce (nonce, error)) {
		goto done;
	}

	if (!validate_iter_count (iter_count,
	                          client->chosen_mechanism, error)) {
		goto done;
	}

	if (!validate_salt_base64 (salt_base64, error)) {
		goto done;
	}

	if (!validate_nonce_uniqueness (nonce, error)) {
		goto done;
	}

	/* Verify the nonce against the client nonce, which should form its
	 * first half. */
	if (!g_str_has_prefix (nonce, client->client_nonce) ||
	    strlen (nonce) == strlen (client->client_nonce)) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		             "The nonce received from the server (‘%s’) was "
		             "invalid, and not correctly prefixed by the "
		             "client nonce (‘%s’). This may indicate a replay "
		             "attack.", nonce, client->client_nonce);

		goto done;
	}

	/* Extract and validate the server nonce. */
	server_nonce = nonce + strlen (client->client_nonce);
	if (!validate_nonce (server_nonce, error)) {
		goto done;
	}

	/* Update client state. */
	client->nonce = g_strdup (nonce);
	client->server_nonce = client->nonce +  strlen (client->client_nonce);
	client->salt_base64 = g_strdup (salt_base64);
	client->iter_count = iter_count;

done:
	g_variant_unref (dict);
}

/* Returns a newly allocated, nul-terminated, base-64 encoded string of the
 * ClientProof calculation. */
static gchar *
client_calculate_client_proof (const ScramAuthenticationClient *client)
{
	GBytes *auth_message = NULL;
	GChecksumType digest_type;
	guint8 *salt;  /* owned */
	gsize salt_len = 0;
	guint8 salted_password[MAXIMUM_CHECKSUM_LENGTH];
	gsize salted_password_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 client_proof[MAXIMUM_CHECKSUM_LENGTH];
	gsize client_proof_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 client_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize client_key_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 stored_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize stored_key_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 client_signature[MAXIMUM_CHECKSUM_LENGTH];
	gsize client_signature_len = MAXIMUM_CHECKSUM_LENGTH;
	GError *error = NULL;

	digest_type = mechanism_get_digest_type (client->chosen_mechanism);

	salt = g_base64_decode (client->salt_base64, &salt_len);
	salted_password_len =
		calculate_salted_password (digest_type,
		                           salted_password, salted_password_len,
		                           (const guint8 *) client->password,
		                           strlen (client->password),
		                           salt, salt_len,
		                           client->iter_count, &error);
	g_assert_no_error (error);  /* should’ve been validated by now */
	g_free (salt);

	client_key_len = calculate_client_key (digest_type,
	                                       client_key, client_key_len,
	                                       salted_password,
	                                       salted_password_len);

	stored_key_len = calculate_stored_key (digest_type,
	                                       stored_key, stored_key_len,
	                                       client_key, client_key_len);

	auth_message = calculate_auth_message (client->username_normalised,
	                                       client->client_nonce,
	                                       client->server_nonce,
	                                       client->salt_base64,
	                                       client->iter_count,
	                                       "biws"  /* FIXME: channel binding support */);

	client_signature_len = calculate_client_signature (digest_type,
	                                                   client_signature,
	                                                   client_signature_len,
	                                                   stored_key,
	                                                   stored_key_len,
	                                                   g_bytes_get_data (auth_message, NULL),
	                                                   g_bytes_get_size (auth_message));

	g_bytes_unref (auth_message);

	client_proof_len = calculate_client_proof (client_proof,
	                                           client_proof_len,
	                                           client_key, client_key_len,
	                                           client_signature,
	                                           client_signature_len);

	/* Base-64 encode the ClientProof. */
	return g_base64_encode (client_proof, client_proof_len);
}

/* Build a GS2 header with channel binding data. See ‘c’ from
 * http://tools.ietf.org/html/rfc5802#section-5.1.
 * Return it base-64 encoded. */
static gchar *
build_gs2_header (void)
{
	/* FIXME: Hard-coded until channel binding is supported. */
	return g_strdup ("biws");
}

/**
 * scram_authentication_client_build_final_message:
 * @client: an #ScramAuthenticationClient
 *
 * Build the final authentication message sent from client to server. This
 * calculates the client proof used to prove knowledge of the plaintext password
 * to the server.
 *
 * This function cannot fail.
 *
 * Returns: (transfer full): a floating #GVariant containing the final message;
 * free with g_variant_unref()
 */
GVariant *
scram_authentication_client_build_final_message (ScramAuthenticationClient *client)
{
	GVariantBuilder builder;
	gchar *client_proof_base64, *gs2_header_base64;

	/* Calculate the ClientProof. */
	client_proof_base64 = client_calculate_client_proof (client);
	gs2_header_base64 = build_gs2_header ();

	/* Build the message. */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("(a{sv})"));

	/* Key–value pairs. */
	g_variant_builder_open (&builder, G_VARIANT_TYPE ("a{sv}"));

	g_variant_builder_add (&builder, "{sv}", "r",
	                       g_variant_new_string (client->nonce));
	g_variant_builder_add (&builder, "{sv}", "p",
	                       g_variant_new_string (client_proof_base64));
	g_variant_builder_add (&builder, "{sv}", "c",
	                       g_variant_new_string (gs2_header_base64));

	g_variant_builder_close (&builder);

	g_free (gs2_header_base64);
	g_free (client_proof_base64);

	return g_variant_builder_end (&builder);
}

/* Server-side function to verify that the given @client_proof is correct by
 * extracting the client key from it, calculating the stored key, and comparing
 * that to the @actual_stored_key stored on the server.
 *
 * See the procedure given in:
 * http://tools.ietf.org/html/rfc5802#section-3 */
static gboolean
server_verify_client_proof (ScramAuthenticationServer *server,
                            const guint8 *client_proof,
                            gsize client_proof_len,
                            const guint8 *actual_stored_key,
                            gsize actual_stored_key_len,
                            GError **error)
{
	GBytes *auth_message = NULL;
	GChecksumType digest_type;
	guint8 client_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize client_key_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 stored_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize stored_key_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 client_signature[MAXIMUM_CHECKSUM_LENGTH];
	gsize client_signature_len = MAXIMUM_CHECKSUM_LENGTH;

	digest_type = mechanism_get_digest_type (server->chosen_mechanism);

	auth_message = calculate_auth_message (server->username_normalised,
	                                       server->client_nonce,
	                                       server->server_nonce,
	                                       server->salt_base64,
	                                       server->iter_count,
	                                       "biws"  /* FIXME: Channel binding support */);

	client_signature_len = calculate_client_signature (digest_type,
	                                                   client_signature,
	                                                   client_signature_len,
	                                                   actual_stored_key,
	                                                   actual_stored_key_len,
	                                                   g_bytes_get_data (auth_message, NULL),
	                                                   g_bytes_get_size (auth_message));

	g_bytes_unref (auth_message);

	if (client_signature_len != client_proof_len ||
	    client_key_len < client_proof_len) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF,
		             "The client signature length (%" G_GSIZE_FORMAT
		             "), client proof length (%" G_GSIZE_FORMAT ") and "
		             "client key length (%" G_GSIZE_FORMAT ") did not "
		             "match.", client_signature_len, client_proof_len,
		             client_key_len);

		return FALSE;
	}

	client_key_len = calculate_xor (client_key, client_signature,
	                                client_proof, client_signature_len);

	stored_key_len = calculate_stored_key (digest_type,
	                                       stored_key, stored_key_len,
	                                       client_key, client_key_len);

	/* Compare the stored keys. */
	if (stored_key_len != actual_stored_key_len ||
	    secure_memcmp (stored_key, actual_stored_key, stored_key_len) != 0) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF,
		             "The client- and server-stored keys do not "
		             "match.");

		return FALSE;
	}

	return TRUE;
}

/**
 * scram_authentication_server_parse_final_message:
 * @server: an #ScramAuthenticationServer
 * @message: the incoming message to parse
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Parse the final message received by the server from the client and update the
 * @server’s state with information from it.
 *
 * On error, @error will be set. An error can occur if the incoming message is
 * badly formatted, contains an invalid nonce, or contains an invalid client
 * proof. This is the point at which most authentications will fail.
 */
void
scram_authentication_server_parse_final_message (ScramAuthenticationServer *server,
                                                 GVariant *message,
                                                 GError **error)
{
	GVariant *dict = NULL;
	const gchar *nonce = NULL, *client_proof_base64 = NULL;
	const gchar *gs2_header_base64 = NULL;
	guint8 *client_proof = NULL;  /* owned */
	gsize client_proof_len = 0;
	gchar *expected_nonce = NULL;  /* owned */
	GError *child_error = NULL;

	/* Check @reply type. */
	if (!g_variant_is_of_type (message, G_VARIANT_TYPE ("(a{sv})"))) {
		g_set_error (&child_error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE,
		             "Final message from client had an invalid type.");

		goto done;
	}

	/* Parse @reply. */
	dict = g_variant_get_child_value (message, 0);

	if (!validate_error_attributes (dict, FALSE, &child_error)) {
		goto done;
	}

	if (!g_variant_lookup (dict, "r", "&s", &nonce) ||
	    !g_variant_lookup (dict, "p", "&s", &client_proof_base64) ||
	    !g_variant_lookup (dict, "c", "&s", &gs2_header_base64)) {
		/* Required attributes. */
		g_set_error (&child_error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		             "The ‘r’, ‘p’ and ‘c’ attributes are required in "
		             "the final message.");

		goto done;
	}

	if (!validate_extension_attributes (dict, &child_error)) {
		goto done;
	}

	/* Validate the values individually. */
	if (!validate_nonce (nonce, &child_error)) {
		goto done;
	}

	if (!validate_gs2_header (gs2_header_base64, server->channel_binding,
	                          &child_error)) {
		goto done;
	}

	client_proof = validate_client_proof (client_proof_base64,
	                                      &client_proof_len, &child_error);
	if (client_proof == NULL) {
		goto done;
	}

	/* Check the nonce. */
	expected_nonce =
		g_strconcat (server->client_nonce, server->server_nonce, NULL);
	if (g_strcmp0 (nonce, expected_nonce) != 0) {
		g_set_error (&child_error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		             "The nonce received from the client (‘%s’) was "
		             "invalid, and not a correct concatenation of the "
		             "client nonce (‘%s’) and the server nonce (‘%s’). "
		             "This may indicate a replay attack.",
		             nonce, server->client_nonce, server->server_nonce);

		goto done;
	}

	/* Verify the client proof. */
	if (!server_verify_client_proof (server,
	                                 client_proof, client_proof_len,
	                                 g_bytes_get_data (server->stored_key, NULL),
	                                 g_bytes_get_size (server->stored_key),
	                                 &child_error)) {
		goto done;
	}

done:
	g_free (expected_nonce);
	g_free (client_proof);
	if (dict != NULL) {
		g_variant_unref (dict);
	}

	if (child_error != NULL) {
		g_clear_error (&server->error);
		server->error = g_error_copy (child_error);
		g_propagate_error (error, child_error);
	}
}

static gchar *
server_calculate_server_signature (const ScramAuthenticationServer *server)
{
	GBytes *auth_message = NULL;
	GChecksumType digest_type;
	guint8 server_signature[MAXIMUM_CHECKSUM_LENGTH];
	gsize server_signature_len = MAXIMUM_CHECKSUM_LENGTH;

	digest_type = mechanism_get_digest_type (server->chosen_mechanism);

	auth_message = calculate_auth_message (server->username_normalised,
	                                       server->client_nonce,
	                                       server->server_nonce,
	                                       server->salt_base64,
	                                       server->iter_count,
	                                       "biws"  /* FIXME: channel binding support */);

	server_signature_len = calculate_server_signature (digest_type,
	                                                   server_signature,
	                                                   server_signature_len,
	                                                   g_bytes_get_data (server->server_key, NULL),
	                                                   g_bytes_get_size (server->server_key),
	                                                   g_bytes_get_data (auth_message, NULL),
	                                                   g_bytes_get_size (auth_message));

	g_bytes_unref (auth_message);

	/* Base-64 encode the ServerSignature. */
	return g_base64_encode (server_signature, server_signature_len);
}

/**
 * scram_authentication_server_build_final_reply:
 * @server: an #ScramAuthenticationServer
 *
 * Build the final authentication reply sent from server to client. This
 * calculates the server signature used to prove knowledge of the server key
 * to the client.
 *
 * This function cannot fail.
 *
 * Returns: (transfer full): a floating #GVariant containing the final reply;
 * free with g_variant_unref()
 */
GVariant *
scram_authentication_server_build_final_reply (ScramAuthenticationServer *server)
{
	GVariantBuilder builder;
	gchar *server_signature_base64;

	/* Propagate errors from the final message. */
	if (server->error != NULL) {
		return server_build_error_message (server);
	}

	/* Calculate the ClientProof. */
	server_signature_base64 = server_calculate_server_signature (server);

	/* Build the message. */
	g_variant_builder_init (&builder, G_VARIANT_TYPE ("(a{sv})"));

	/* Key–value pairs. */
	g_variant_builder_open (&builder, G_VARIANT_TYPE ("a{sv}"));

	g_variant_builder_add (&builder, "{sv}", "v",
	                       g_variant_new_string (server_signature_base64));

	g_variant_builder_close (&builder);

	g_free (server_signature_base64);

	return g_variant_builder_end (&builder);
}

/* Client-side function to verify a received server signature. It does this by
 * calculating the expected server signature, given the authentication
 * information available on the client already, and comparing it to the
 * @actual_server_signature.
 *
 * See the procedure in:
 * http://tools.ietf.org/html/rfc5802#section-3 */
static gboolean
client_verify_server_signature (ScramAuthenticationClient *client,
                                const guint8 *actual_server_signature,
                                gsize actual_server_signature_len,
                                GError **error)
{
	GBytes *auth_message = NULL;
	GChecksumType digest_type;
	guint8 *salt;  /* owned */
	gsize salt_len = 0;
	guint8 salted_password[MAXIMUM_CHECKSUM_LENGTH];
	gsize salted_password_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 server_signature[MAXIMUM_CHECKSUM_LENGTH];
	gsize server_signature_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 server_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize server_key_len = MAXIMUM_CHECKSUM_LENGTH;

	digest_type = mechanism_get_digest_type (client->chosen_mechanism);

	salt = g_base64_decode (client->salt_base64, &salt_len);
	salted_password_len =
		calculate_salted_password (digest_type,
		                           salted_password, salted_password_len,
		                           (const guint8 *) client->password,
		                           strlen (client->password),
		                           salt, salt_len,
		                           client->iter_count, error);
	g_free (salt);

	server_key_len = calculate_server_key (digest_type,
	                                       server_key, server_key_len,
	                                       salted_password,
	                                       salted_password_len);

	auth_message = calculate_auth_message (client->username_normalised,
	                                       client->client_nonce,
	                                       client->server_nonce,
	                                       client->salt_base64,
	                                       client->iter_count,
	                                       "biws"  /* FIXME: channel binding support */);

	server_signature_len = calculate_server_signature (digest_type,
	                                                   server_signature,
	                                                   server_signature_len,
	                                                   server_key,
	                                                   server_key_len,
	                                                   g_bytes_get_data (auth_message, NULL),
	                                                   g_bytes_get_size (auth_message));

	g_bytes_unref (auth_message);

	/* Compare the signatures. */
	if (server_signature_len != actual_server_signature_len ||
	    secure_memcmp (server_signature, actual_server_signature,
	                   server_signature_len) != 0) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_SERVER_SIGNATURE,
		             "The server- and client-calculated server "
		             "signatures do not match.");

		return FALSE;
	}

	return TRUE;
}

/**
 * scram_authentication_client_parse_final_reply:
 * @client: an #ScramAuthenticationClient
 * @reply: the incoming message to parse
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Parse the final reply received by the client from the server and update the
 * @client’s state with information from it.
 *
 * On error, @error will be set. An error can occur if the incoming message is
 * badly formatted, contains an invalid nonce, or contains an invalid server
 * signature.
 */
void
scram_authentication_client_parse_final_reply (ScramAuthenticationClient *client,
                                               GVariant *reply,
                                               GError **error)
{
	GVariant *dict;
	const gchar *server_signature_base64 = NULL;
	guint8 *server_signature = NULL;
	gsize server_signature_len = 0;

	/* Check @reply type. */
	if (!g_variant_is_of_type (reply, G_VARIANT_TYPE ("(a{sv})"))) {
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE,
		             "Final reply from server had an invalid type.");
		return;
	}

	/* Parse @reply. */
	dict = g_variant_get_child_value (reply, 0);

	if (!validate_error_attributes (dict, TRUE, error)) {
		goto done;
	}

	if (!g_variant_lookup (dict, "v", "&s", &server_signature_base64)) {
		/* Required attributes. */
		g_set_error (error, SCRAM_AUTHENTICATION_ERROR,
		             SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		             "The ‘v’ attribute is required in the final "
		             "reply.");

		goto done;
	}

	if (!validate_extension_attributes (dict, error)) {
		goto done;
	}

	/* Validate the values individually. */
	server_signature = validate_server_signature (server_signature_base64,
	                                              &server_signature_len,
	                                              error);
	if (server_signature == NULL) {
		goto done;
	}

	/* Verify the server signature. */
	if (!client_verify_server_signature (client, server_signature,
	                                     server_signature_len, error)) {
		goto done;
	}

done:
	g_free (server_signature);
	g_variant_unref (dict);
}


/**
 * scram_authentication_server_build_error_message:
 * @server: an #ScramAuthenticationServer
 * @error: a #GError
 *
 * Set the server’s internal state to @error and return a #GVariant representing
 * an error message to be sent from server to client. This is designed to be
 * used to notify the client of out-of-band authentication errors not handled by
 * the authentication code itself.
 *
 * After calling this function, all future server method calls will return a
 * copy of the given @error.
 *
 * Returns: (transfer full): a floating #GVariant containing the error message
 * to be sent to the client; free with g_variant_unref()
 */
GVariant *
scram_authentication_server_build_error_message (ScramAuthenticationServer *server,
                                                 const GError *error)
{
	g_return_val_if_fail (server != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (error->domain == SCRAM_AUTHENTICATION_ERROR, NULL);

	g_clear_error (&server->error);
	server->error = g_error_copy (error);

	return server_build_error_message (server);
}


/**
 * scram_authentication_salt_password:
 * @mechanism: the chosen authentication mechanism
 * @password: plaintext password to be salted
 * @salt: (transfer none): salt value to use
 * @iter_count: number of times to iterate the hash function
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Calculate the hashed, salted version of the given plaintext @password, using
 * @salt as the salt value, and iterating the hash function @iter_count times.
 * The hash function used is specified by @mechanism.
 *
 * On error, %NULL will be returned and @error will be set. This function can
 * fail if the password, salt or iteration count are invalid or if the password
 * cannot be normalised due to containing non-printable-ASCII characters.
 *
 * Returns: (transfer full): salted, hashed password in binary form (not base-64
 * encoded); free with g_bytes_unref()
 */
GBytes *
scram_authentication_salt_password (ScramAuthenticationMechanism mechanism,
                                    const gchar *password, GBytes *salt,
                                    guint32 iter_count, GError **error)
{
	GChecksumType digest_type;
	guint8 salted_password[MAXIMUM_CHECKSUM_LENGTH];
	gsize salted_password_len = MAXIMUM_CHECKSUM_LENGTH;

	g_return_val_if_fail (mechanism != SCRAM_AUTHENTICATION_NONE, NULL);
	g_return_val_if_fail (password != NULL, NULL);
	g_return_val_if_fail (salt != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	if (!validate_password (password, error) ||
	    !validate_salt (g_bytes_get_data (salt, NULL),
	                    g_bytes_get_size (salt), error) ||
	    !validate_iter_count (iter_count, mechanism, error)) {
		return NULL;
	}

	digest_type = mechanism_get_digest_type (mechanism);

	salted_password_len =
		calculate_salted_password (digest_type,
		                           salted_password, salted_password_len,
		                           (const guint8 *) password,
		                           strlen (password),
		                           (guint8 *) g_bytes_get_data (salt, NULL),
		                           g_bytes_get_size (salt),
		                           iter_count, error);

	if (salted_password_len == 0) {
		return NULL;
	}

	return g_bytes_new (salted_password, salted_password_len);
}


/**
 * scram_authentication_build_server_key:
 * @mechanism: the chosen authentication mechanism
 * @salted_password: (transfer none): a hashed, salted password to use
 *
 * Build a server key from the given @salted_password. The server key is a HMAC
 * of the salted password, suitable for storage on a server. The HMAC function
 * is determined by the @mechanism.
 *
 * The @salted_password may be calculated using
 * scram_authentication_salt_password().
 *
 * This function cannot fail.
 *
 * Returns: (transfer full): server key in binary form (not base-64 encoded);
 * free with g_bytes_unref()
 */
GBytes *
scram_authentication_build_server_key (ScramAuthenticationMechanism mechanism,
                                       GBytes *salted_password)
{
	GChecksumType digest_type;
	guint8 server_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize server_key_len = MAXIMUM_CHECKSUM_LENGTH;

	g_return_val_if_fail (mechanism != SCRAM_AUTHENTICATION_NONE, NULL);
	g_return_val_if_fail (salted_password != NULL, NULL);

	digest_type = mechanism_get_digest_type (mechanism);

	server_key_len = calculate_server_key (digest_type,
	                                       server_key, server_key_len,
	                                       g_bytes_get_data (salted_password, NULL),
	                                       g_bytes_get_size (salted_password));

	return g_bytes_new (server_key, server_key_len);
}

/**
 * scram_authentication_build_stored_key:
 * @mechanism: the chosen authentication mechanism
 * @salted_password: (transfer none): a hashed, salted password to use
 *
 * Build a store key from the given @salted_password. The stored key is a hash
 * of a HMAC of the salted password, suitable for storage on a server. The hash
 * and HMAC function are determined by the @mechanism.
 *
 * The @salted_password may be calculated using
 * scram_authentication_salt_password().
 *
 * This function cannot fail.
 *
 * Returns: (transfer full): stored key in binary form (not base-64 encoded);
 * free with g_bytes_unref()
 */
GBytes *
scram_authentication_build_stored_key (ScramAuthenticationMechanism mechanism,
                                       GBytes *salted_password)
{
	GChecksumType digest_type;
	guint8 client_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize client_key_len = MAXIMUM_CHECKSUM_LENGTH;
	guint8 stored_key[MAXIMUM_CHECKSUM_LENGTH];
	gsize stored_key_len = MAXIMUM_CHECKSUM_LENGTH;

	g_return_val_if_fail (mechanism != SCRAM_AUTHENTICATION_NONE, NULL);
	g_return_val_if_fail (salted_password != NULL, NULL);

	digest_type = mechanism_get_digest_type (mechanism);

	client_key_len = calculate_client_key (digest_type,
	                                       client_key, client_key_len,
	                                       g_bytes_get_data (salted_password, NULL),
	                                       g_bytes_get_size (salted_password));

	stored_key_len = calculate_stored_key (digest_type,
	                                       stored_key, stored_key_len,
	                                       client_key, client_key_len);

	return g_bytes_new (stored_key, stored_key_len);
}


/**
 * scram_authentication_generate_nonce:
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Generate a cryptographically secure random nonce in the format required by
 * the authentication code. It will be a sequence of printable ASCII characters,
 * excluding commas. The returned nonce will be nul-terminated, and must be
 * freed using g_free().
 *
 * On error, @error is set and %NULL is returned. Errors can occur if I/O fails,
 * or if `/dev/urandom` cannot be read.
 *
 * Returns: (transfer full): a newly allocated printable nonce, or %NULL on
 * error; free with g_free()
 */
gchar *
scram_authentication_generate_nonce (GError **error)
{
	gsize nonce_len = 4 * MINIMUM_NONCE_LENGTH;  /* arbitrary */
	guint8 nonce[nonce_len];
	gchar *nonce_base64;

	/* Reference: the ‘r’ paragraph of
	 * http://tools.ietf.org/html/rfc5802#section-5.1 */

#if defined(G_OS_UNIX)
{
	int stream_fd;
	ssize_t len;
	uint8_t *buf;
	size_t remaining;

	stream_fd = g_open (DEV_RANDOM, O_RDONLY, 0);

	if (stream_fd == -1) {
		return NULL;
	}

	buf = nonce;
	remaining = nonce_len;

	do {
		len = read (stream_fd, buf, remaining);

		if (len < 0) {
			/* Error. */
			g_set_error (error, G_IO_ERROR,
			             g_io_error_from_errno (errno),
			             "Error reading from ‘%s’.", DEV_RANDOM);

			g_close (stream_fd, NULL);

			return NULL;
		} else if (len == 0) {
			/* EOF. */
			g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
			             "Unexpectedly received EOF from "
			             "‘%s’.", DEV_RANDOM);

			g_close (stream_fd, NULL);

			return NULL;
		}

		buf += len;
		remaining -= len;
	} while (remaining > 0);

	g_close (stream_fd, NULL);
}
#elif defined(G_OS_WIN32)
{
	HCRYPTPROV provider;

	if (!CryptAcquireContext (&provider, NULL, NULL, PROV_RSA_FULL,
	                          CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		DWORD error_number = GetLastError ();
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "Failed to acquire a cryptographic context (error "
		             "code %" G_GUINT32_FORMAT ").",
		             (guint32) error_number);

		return NULL;
	}

	/* Reference:
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa379942%28v=vs.85%29.aspx */
	if (!CryptGenRandom (provider, nonce_len, nonce)) {
		DWORD error_number = GetLastError ();
		g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
		             "Failed to generate random data (error code %"
		             G_GUINT32_FORMAT ").", (guint32) error_number);

		CryptReleaseContext (provider, 0);

		return NULL;
	}

	CryptReleaseContext (provider, 0);
}
#else /* if !G_OS_UNIX && !G_OS_WIN32 */
	#error "Not implemented yet."
#endif /* !G_OS_UNIX */

	/* Base-64 encode it to make it printable (and without commas), without
	 * losing entropy. */
	nonce_base64 = g_base64_encode (nonce, nonce_len);

	return nonce_base64;
}
