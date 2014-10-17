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

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "authentication.h"


static void
authentication_client_init_clear (void)
{
	ScramAuthenticationClient client;
	ScramAuthenticationMechanism mechanisms[] = {
		SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	};

	scram_authentication_client_init (&client, "some-nonce",
	                                  mechanisms, G_N_ELEMENTS (mechanisms),
	                                  FALSE);
	scram_authentication_client_clear (&client);
}

static void
authentication_server_init_clear (void)
{
	ScramAuthenticationServer server;
	ScramAuthenticationMechanism mechanisms[] = {
		SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	};

	scram_authentication_server_init (&server, "some-nonce",
	                                  mechanisms, G_N_ELEMENTS (mechanisms));
	scram_authentication_server_clear (&server);
}

static void
authentication_client_choose_mechanism (void)
{
	ScramAuthenticationClient client;
	ScramAuthenticationMechanism mechanisms[] = {
		SCRAM_AUTHENTICATION_SCRAM_SHA_1,
		SCRAM_AUTHENTICATION_SCRAM_SHA_1_PLUS,
	};

	scram_authentication_client_init (&client, "some-client-nonce",
	                                  mechanisms, G_N_ELEMENTS (mechanisms),
	                                  FALSE);

	/* Check that SCRAM-SHA1 is chosen because the client doesn’t support
	 * channel binding at the moment (FIXME). */
	g_assert_cmpuint (scram_authentication_client_get_chosen_mechanism (&client),
	                  ==, SCRAM_AUTHENTICATION_SCRAM_SHA_1);

	scram_authentication_client_clear (&client);
}

static void
assert_variants_equal (GVariant *v, const gchar *expected_type,
                       const gchar *expected_value)
{
	gchar *p;
	GVariant *expected_v;

	/* Debug output. */
	p = g_variant_print (v, TRUE);
	g_test_message ("Variant: %s", p);

	/* Check the variant matches. */
	expected_v =
		g_variant_parse (G_VARIANT_TYPE (expected_type),
		                 expected_value, NULL, NULL, NULL);
	g_assert (expected_v != NULL);
	g_assert (g_variant_equal (expected_v, v));

	g_variant_unref (expected_v);
	g_free (p);
}

/* Test the two messages are correctly built and parsed by the client and
 * server.
 *
 * Use the example data from:
 * http://tools.ietf.org/html/rfc5802#section-5 */
static void
authentication_success (void)
{
	ScramAuthenticationClient client;
	ScramAuthenticationServer server;
	GVariant *first_message, *first_reply;  /* owned */
	GVariant *final_message, *final_reply;  /* owned */
	GError *error = NULL;
	gchar *server_username;
	GBytes *salted_password;  /* owned */
	GBytes *server_key;  /* owned */
	GBytes *stored_key;  /* owned */
	GBytes *user_salt_bytes;  /* owned */

	/* Client-only data. */
	const gchar *client_nonce = "fyko+d2lbbFgONRv9qkxdawL";

	/* Server-only data. */
	const gchar *server_nonce = "3rfcNHYJY1ZVvWVs7j";

	/* Shared authentication data known by both peers. */
	const gchar *username = "user";
	const gchar *password = "pencil";
	guint32 user_iter_count = 4096;
	const guint8 user_salt[] = {
		0x41, 0x25, 0xc2, 0x47, 0xe4, 0x3a,
		0xb1, 0xe9, 0x3c, 0x6d, 0xff, 0x76,
	};
	ScramAuthenticationMechanism mechanisms[] = {
		SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	};

	user_salt_bytes = g_bytes_new_static (user_salt,
	                                      G_N_ELEMENTS (user_salt));
	salted_password = scram_authentication_salt_password (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	                                                      password,
	                                                      user_salt_bytes,
	                                                      user_iter_count,
	                                                      &error);
	g_assert_no_error (error);

	server_key = scram_authentication_build_server_key (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	                                                    salted_password);
	stored_key = scram_authentication_build_stored_key (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	                                                    salted_password);

	/* Init. */
	scram_authentication_client_init (&client, client_nonce,
	                                  mechanisms, G_N_ELEMENTS (mechanisms),
	                                  FALSE);
	scram_authentication_server_init (&server, server_nonce,
	                                  mechanisms, G_N_ELEMENTS (mechanisms));

	/* Build and parse the first message. */
	first_message =
		scram_authentication_client_build_first_message (&client,
		                                                 username,
		                                                 password,
		                                                 &error);
	g_assert_no_error (error);
	g_assert (first_message != NULL);
	assert_variants_equal (first_message, "(y(yssay)a{sv})",
	                       "(byte 0x01, (byte 0x6e, '', '', @ay []), "
	                        "{'n': <'user'>, "
	                         "'r': <'fyko+d2lbbFgONRv9qkxdawL'>})");

	server_username =
		scram_authentication_server_parse_first_message (&server,
		                                                 first_message,
		                                                 &error);
	g_assert_no_error (error);
	g_assert_cmpstr (server_username, ==, username);
	g_free (server_username);

	/* Build and parse the first reply. */
	first_reply =
		scram_authentication_server_build_first_reply (&server,
		                                               user_salt_bytes,
		                                               user_iter_count,
		                                               server_key,
		                                               stored_key);
	g_assert (first_reply != NULL);
	assert_variants_equal (first_reply, "(a{sv})",
	                       "({'r': <'fyko+d2lbbFgONRv9qkxdawL"
	                                "3rfcNHYJY1ZVvWVs7j'>, "
	                         "'s': <'QSXCR+Q6sek8bf92'>, "
	                         "'i': <uint32 4096>},)");

	scram_authentication_client_parse_first_reply (&client,
	                                               first_reply,
	                                               &error);
	g_assert_no_error (error);

	/* Build and parse the final message. */
	final_message = scram_authentication_client_build_final_message (&client);
	g_assert (final_message != NULL);
	assert_variants_equal (final_message, "(a{sv})",
	                       "({'r': <'fyko+d2lbbFgONRv9qkxdawL"
	                                "3rfcNHYJY1ZVvWVs7j'>, "
	                         "'p': <'v0X8v3Bz2T0CJGbJQyF0X+HI4Ts='>, "
	                         "'c': <'biws'>},)");

	scram_authentication_server_parse_final_message (&server, final_message,
	                                                 &error);
	g_assert_no_error (error);

	/* Build and parse the final reply. */
	final_reply = scram_authentication_server_build_final_reply (&server);
	g_assert (final_reply != NULL);
	assert_variants_equal (final_reply, "(a{sv})",
	                       "({'v': <'rmF9pqV8S7suAoZWja4dJRkFsKQ='>},)");

	scram_authentication_client_parse_final_reply (&client, final_reply,
	                                               &error);
	g_assert_no_error (error);

	g_variant_unref (final_reply);
	g_variant_unref (final_message);
	g_variant_unref (first_reply);
	g_variant_unref (first_message);

	/* Tidy up. */
	scram_authentication_server_clear (&server);
	scram_authentication_client_clear (&client);

	g_bytes_unref (user_salt_bytes);
	g_bytes_unref (stored_key);
	g_bytes_unref (server_key);
	g_bytes_unref (salted_password);
}


/* Check that salting a password works correctly. */
static void
authentication_salt_password (void)
{
	guint i;
	const struct {
		ScramAuthenticationMechanism mechanism;
		const gchar *password;
		const gchar *salt;
		guint32 iter_count;
		const gchar *expected_salted_password;  /* NULL for error */
	} vectors[] = {
		/* Successful saltings. Generated using the following Python:
		 * >>> from passlib.hash import scram
		 * >>> scram.derive_digest("pencil",
		 *                         b'\x41\x25\xc2\x47\xe4\x3a…',
		 *                         4096, "sha-1")
		 */
		{ SCRAM_AUTHENTICATION_SCRAM_SHA_1, "pencil",
		  "\x41\x25\xc2\x47\xe4\x3a\xb1\xe9\x3c\x6d\xff\x76", 4096,
		  "\x1d\x96\xee:R\x9bZ_\x9eG\xc0\x1f\"\x9a,\xb8\xa6\xe1_}" },
		{ SCRAM_AUTHENTICATION_SCRAM_SHA_1_PLUS, "pencil",
		  "\x41\x25\xc2\x47\xe4\x3a\xb1\xe9\x3c\x6d\xff\x76", 4096,
		  "\x1d\x96\xee:R\x9bZ_\x9eG\xc0\x1f\"\x9a,\xb8\xa6\xe1_}" },
		{ SCRAM_AUTHENTICATION_SCRAM_SHA_1, "pencil",
		  "\x41\x25\xc2\x47\xe4\x3a\xb1\xe9\x3c\x6d\xff\x76", 8192,
		  "\xb8\x0f\xb0T\x90\x8f\xbf\xa7\x91G\xf4\x17\xd4\x90ku\xf5"
		  "\xd5\xdc\x96" },
		/* Iteration count too low for mechanism. */
		{ SCRAM_AUTHENTICATION_SCRAM_SHA_1, "pencil", "something", 1024,
		  NULL },
		/* Invalid password. */
		{ SCRAM_AUTHENTICATION_SCRAM_SHA_1, "", "something", 4096, NULL },
		{ SCRAM_AUTHENTICATION_SCRAM_SHA_1, "Unicode! 🐵", "something",
		  4096, NULL },
		/* Salt too short. */
		{ SCRAM_AUTHENTICATION_SCRAM_SHA_1, "pencil", "h", 4096, NULL },
	};

	for (i = 0; i < G_N_ELEMENTS (vectors); i++) {
		GBytes *salted_password, *salt;
		GBytes *expected_salted_password;
		GError *error = NULL;

		g_test_message ("Vector %u of %lu.", i, G_N_ELEMENTS (vectors));

		salt = g_bytes_new_static (vectors[i].salt,
		                           strlen (vectors[i].salt));

		salted_password =
			scram_authentication_salt_password (vectors[i].mechanism,
			                                    vectors[i].password,
			                                    salt,
			                                    vectors[i].iter_count,
			                                    &error);

		if (vectors[i].expected_salted_password != NULL) {
			g_assert_no_error (error);
			g_assert (salted_password != NULL);
		} else {
			g_assert (error != NULL);
			g_assert (salted_password == NULL);
			g_clear_error (&error);
		}

		/* Check the output. */
		if (vectors[i].expected_salted_password != NULL) {
			expected_salted_password =
				g_bytes_new_static (vectors[i].expected_salted_password,
				                    strlen (vectors[i].expected_salted_password));
			g_assert (g_bytes_equal (salted_password,
			                         expected_salted_password));
			g_bytes_unref (expected_salted_password);
		}

		g_bytes_unref (salted_password);
		g_bytes_unref (salt);
	}
}


/* Test various error handling paths triggered by a malformed input #GVariant
 * to scram_authentication_server_parse_first_message(). */
static void
authentication_first_message_parse_error (void)
{
	ScramAuthenticationServer server;
	guint i;
	ScramAuthenticationMechanism mechanism = SCRAM_AUTHENTICATION_SCRAM_SHA_1;
	GBytes *user_salt_bytes, *server_key, *stored_key;  /* all owned */
	guint32 user_iter_count = 4096;
	const guint8 user_salt[] = {
		0x41, 0x25, 0xc2, 0x47, 0xe4, 0x3a,
		0xb1, 0xe9, 0x3c, 0x6d, 0xff, 0x76,
	};
	const gchar *password = "pencil";
	GBytes *salted_password;  /* owned */
	GError *error = NULL;
	const struct {
		const gchar *type;
		const gchar *message;
		ScramAuthenticationError expected_error_code;
		const gchar *expected_error_value;
	} vectors[] = {
		/* 0. Invalid type. */
		{ "(u(yssay)a{sv})",
		  "(uint32 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE,
		   "other-error" },
		/* 1. Invalid mechanism. */
		{ "(y(yssay)a{sv})",
		  "(byte 0xff, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		   "other-error" },
		/* 2. Unsupported mechanism. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x02, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		   "other-error" },
		/* 3. Invalid channel binding. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0xff, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_CHANNEL_BINDING,
		   "unsupported-channel-binding-type" },
		/* 4. Unsupported channel binding. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x70, 'tls-unique', '', @ay []), "
		   "{'n': <'user'>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_UNSUPPORTED,
		   "channel-binding-not-supported" },
		/* 5. Unsupported SASL auth. identity. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', 'sasl-auth-identity', @ay []), "
		   "{'n': <'user'>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_UNKNOWN_USER,
		   "unknown-user" },
		/* 6. Missing ‘n’ attribute. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		   "other-error" },
		/* 7. Missing ‘r’ attribute. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>})",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		   "other-error" },
		/* 8. Invalid user name. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <''>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		   "other-error" },
		/* 9. Invalid user name. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'Cow! 🐮'>, 'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		   "other-error" },
		/* 10. Invalid user name. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'Contains = not followed by 3C'>, "
		    "'r': <'some-server-nonce'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE,
		   "other-error" },
		/* 11. Unsupported extension attribute. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'some-server-nonce'>, "
		    "'m': <'something'>})",
		   SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE,
		   "extensions-not-supported" },
		/* 12. Invalid nonce. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <''>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 13. Invalid nonce. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'Non-ASCII cat! 🐱'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 14. Invalid nonce. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'This, contains commas'>})",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 15. Invalid nonce. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'n': <'user'>, 'r': <'a'>})",  /* too short */
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 16. Unexpected ‘e’ attribute. */
		{ "(y(yssay)a{sv})",
		  "(byte 0x01, "
		   "(byte 0x6e, '', '', @ay []), "
		   "{'e': <'other-error'>})",
		   SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE,
		   "extensions-not-supported" },

		/* FIXME: When channel binding is implemented, more tests need
		 * adding for those attributes. */
	};

	/* Set up a server. */
	scram_authentication_server_init (&server,
	                                  "some-server-nonce",
	                                  &mechanism, 1);

	/* Set up gubbins for building the first reply. */
	user_salt_bytes = g_bytes_new_static (user_salt, sizeof (user_salt));
	salted_password =
		scram_authentication_salt_password (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
		                                    password,
		                                    user_salt_bytes,
		                                    user_iter_count,
		                                    &error);
	g_assert_no_error (error);

	server_key =
		scram_authentication_build_server_key (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
		                                       salted_password);
	stored_key =
		scram_authentication_build_stored_key (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
		                                       salted_password);

	for (i = 0; i < G_N_ELEMENTS (vectors); i++) {
		gchar *expected_first_reply;
		GVariant *v, *first_reply;
		gchar *username;

		g_test_message ("Vector %u of %lu.", i, G_N_ELEMENTS (vectors));

		v = g_variant_parse (G_VARIANT_TYPE (vectors[i].type),
		                     vectors[i].message, NULL, NULL, &error);
		g_assert_no_error (error);

		/* Try parsing the message. */
		username =
			scram_authentication_server_parse_first_message (&server,
			                                                 v,
			                                                 &error);
		g_assert_error (error, SCRAM_AUTHENTICATION_ERROR,
		                (gint) vectors[i].expected_error_code);
		g_assert (username == NULL);

		g_clear_error (&error);
		g_variant_unref (v);

		/* Check that the server returns an error in its next
		 * message. */
		first_reply =
			scram_authentication_server_build_first_reply (&server,
			                                               user_salt_bytes,
			                                               user_iter_count,
			                                               server_key,
			                                               stored_key);
		expected_first_reply =
			g_strdup_printf ("({'e': <'%s'>},)",
			                 vectors[i].expected_error_value);
		assert_variants_equal (first_reply, "(a{sv})",
		                       expected_first_reply);
		g_free (expected_first_reply);
		g_variant_unref (first_reply);
	}

	g_bytes_unref (stored_key);
	g_bytes_unref (server_key);
	g_bytes_unref (salted_password);
	g_bytes_unref (user_salt_bytes);

	scram_authentication_server_clear (&server);
}

/* Test that overly-short usernames are validated. */
static void
authentication_first_message_short_username (void)
{
	ScramAuthenticationClient client;
	ScramAuthenticationMechanism mechanism = SCRAM_AUTHENTICATION_SCRAM_SHA_1;
	GVariant *first_message;  /* owned */
	const gchar *password = "pencil";
	GError *error = NULL;

	scram_authentication_client_init (&client, "some-client-nonce",
	                                  &mechanism, 1, FALSE);

	first_message =
		scram_authentication_client_build_first_message (&client,
		                                                 ""  /* short */,
		                                                 password,
		                                                 &error);
	g_assert_error (error, SCRAM_AUTHENTICATION_ERROR,
	                SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE);
	g_assert (first_message == NULL);

	g_clear_error (&error);
	scram_authentication_client_clear (&client);
}

/* Test various error handling paths triggered by a malformed input #GVariant
 * to scram_authentication_client_parse_first_reply(). */
static void
authentication_first_reply_parse_error (void)
{
	ScramAuthenticationClient client;
	guint i;
	ScramAuthenticationMechanism mechanism = SCRAM_AUTHENTICATION_SCRAM_SHA_1;
	GVariant *first_message;
	const gchar *password = "pencil";
	GError *error = NULL;
	const struct {
		const gchar *type;
		const gchar *message;
		ScramAuthenticationError expected_error_code;
	} vectors[] = {
		/* 0. Invalid type. */
		{ "(a{ss})",
		  "({'r': 'some-client-nonce-some-server-nonce', "
		    "'s': 'QSXCR+Q6sek8bf92', 'i': '4096'},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE },
		/* 1. Missing ‘r’ attribute. */
		{ "(a{sv})",
		  "({'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE },
		/* 2. Missing ‘s’ attribute. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE },
		/* 3. Missing ‘i’ attribute. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'s': <'QSXCR+Q6sek8bf92'>},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE },
		/* 4. Unsupported extension attribute. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 4096>, "
		    "'m': <'some extension'>},)",
		   SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE },
		/* 5. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <''>, "
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE },
		/* 6. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-commas,,'>, "
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE },
		/* 7. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-🐵-nonce'>, "
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE },
		/* 8. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce'>, "
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE },
		/* 9. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-x'>, "  /* server too short */
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE },
		/* 10. Invalid salt. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'s': <''>, 'i': <uint32 4096>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE },
		/* 11. Invalid iteration count. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <'4096'>},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE },
		/* 12. Invalid iteration count. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'s': <'QSXCR+Q6sek8bf92'>, 'i': <uint32 1024>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_ATTRIBUTE },
		/* 13. Server-side error. */
		{ "(a{sv})",
		  "({'e': <'other-error'>},)",
		   SCRAM_AUTHENTICATION_ERROR_FAILED },
	};

	/* Set up a client and create the first message to set state. */
	scram_authentication_client_init (&client,
	                                  "some-client-nonce",
	                                  &mechanism, 1, FALSE);
	first_message =
		scram_authentication_client_build_first_message (&client, "user",
		                                                 password,
		                                                 &error);
	g_assert_no_error (error);
	g_assert (first_message != NULL);
	g_variant_unref (first_message);

	/* Run the tests. */
	for (i = 0; i < G_N_ELEMENTS (vectors); i++) {
		GVariant *v;

		g_test_message ("Vector %u of %lu.", i, G_N_ELEMENTS (vectors));

		v = g_variant_parse (G_VARIANT_TYPE (vectors[i].type),
		                     vectors[i].message, NULL, NULL, &error);
		g_assert_no_error (error);

		/* Try parsing the message. */
		scram_authentication_client_parse_first_reply (&client, v,
		                                               &error);
		g_assert_error (error, SCRAM_AUTHENTICATION_ERROR,
		                (gint) vectors[i].expected_error_code);

		g_clear_error (&error);
		g_variant_unref (v);
	}

	scram_authentication_client_clear (&client);
}

/* Test various error handling paths triggered by a malformed input #GVariant
 * to scram_authentication_server_parse_final_message(). */
static void
authentication_final_message_parse_error (void)
{
	ScramAuthenticationServer server;
	guint i;
	ScramAuthenticationMechanism mechanism = SCRAM_AUTHENTICATION_SCRAM_SHA_1;
	GVariant *first_message, *first_reply;
	gchar *username;
	GBytes *user_salt_bytes, *server_key, *stored_key;  /* all owned */
	guint32 user_iter_count = 4096;
	const guint8 user_salt[] = {
		0x41, 0x25, 0xc2, 0x47, 0xe4, 0x3a,
		0xb1, 0xe9, 0x3c, 0x6d, 0xff, 0x76,
	};
	const gchar *password = "pencil";
	GBytes *salted_password;  /* owned */
	GError *error = NULL;
	const struct {
		const gchar *type;
		const gchar *message;
		ScramAuthenticationError expected_error_code;
		const gchar *expected_error_value;
	} vectors[] = {
		/* 0. Invalid type. */
		{ "(a{ss})",
		  "({'r': 'some-client-nonce-some-server-nonce', "
		    "'p': 'JpT1/KC+KD4IQ4JbeMoYFQaKRZg=', "
		    "'c': 'biws'},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE,
		   "other-error" },
		/* 1. Missing ‘r’ attribute. */
		{ "(a{sv})",
		  "({'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		   "other-error" },
		/* 2. Missing ‘p’ attribute. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		   "other-error" },
		/* 3. Missing ‘c’ attribute. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE,
		   "other-error" },
		/* 4. Unsupported extension attribute. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <'biws'>, "
		    "'m': <'some extension'>},)",
		   SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE,
		   "extensions-not-supported" },
		/* 5. Invalid nonce */
		{ "(a{sv})",
		  "({'r': <''>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 6. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce'>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 7. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <'something-completely-wrong'>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 8. Invalid nonce. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-x'>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_NONCE,
		   "other-error" },
		/* 9. Invalid proof. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'p': <''>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF,
		   "invalid-proof" },
		/* 10. Invalid proof, wrong length. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'p': <'this-proof-isnt-valid---definitely-wrong-length'>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF,
		   "invalid-proof" },
		/* 11. Invalid proof, correct length (once decoded). */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'p': <'MDEyMzQ1Njc4OTAxMjM0NTY3ODk='>, "
		    "'c': <'biws'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_CLIENT_PROOF,
		   "invalid-proof" },
		/* 12. Invalid channel binding. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <''>},)",
		   SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_MISMATCH,
		   "channel-bindings-dont-match" },
		/* 13. Channel binding changed from first message. */
		{ "(a{sv})",
		  "({'r': <'some-client-nonce-some-server-nonce'>, "
		    "'p': <'JpT1/KC+KD4IQ4JbeMoYFQaKRZg='>, "
		    "'c': <'cD10bHMtdW5pcXVlLCw='>},)",
		   SCRAM_AUTHENTICATION_ERROR_CHANNEL_BINDING_MISMATCH,
		   "channel-bindings-dont-match" },
		/* 14. Unexpected ‘e’ attribute. */
		{ "(a{sv})",
		  "({'e': <'other-error'>},)",
		   SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE,
		   "extensions-not-supported" },
	};

	/* Set up a server, parse the first message and build the first reply
	 * to set internal state. */
	scram_authentication_server_init (&server,
	                                  "-some-server-nonce",
	                                  &mechanism, 1);

	first_message = g_variant_parse (G_VARIANT_TYPE ("(y(yssay)a{sv})"),
	                                 "(byte 0x01, "
	                                  "(byte 0x6e, '', '', @ay []), "
	                                  "{'n': <'user'>, "
	                                   "'r': <'some-client-nonce'>})",
	                                 NULL, NULL, &error);
	g_assert_no_error (error);

	username =
		scram_authentication_server_parse_first_message (&server,
		                                                 first_message,
		                                                 &error);
	g_assert_no_error (error);
	g_assert (username != NULL);
	g_free (username);

	g_variant_unref (first_message);

	user_salt_bytes = g_bytes_new_static (user_salt, sizeof (user_salt));
	salted_password = scram_authentication_salt_password (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	                                                      password,
	                                                      user_salt_bytes,
	                                                      user_iter_count,
	                                                      &error);
	g_assert_no_error (error);

	server_key = scram_authentication_build_server_key (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	                                                    salted_password);
	stored_key = scram_authentication_build_stored_key (SCRAM_AUTHENTICATION_SCRAM_SHA_1,
	                                                    salted_password);

	first_reply =
		scram_authentication_server_build_first_reply (&server,
		                                               user_salt_bytes,
		                                               user_iter_count,
		                                               server_key,
		                                               stored_key);
	g_assert (first_reply != NULL);
	g_variant_unref (first_reply);

	g_bytes_unref (stored_key);
	g_bytes_unref (server_key);
	g_bytes_unref (salted_password);
	g_bytes_unref (user_salt_bytes);

	/* Run the tests. */
	for (i = 0; i < G_N_ELEMENTS (vectors); i++) {
		GVariant *v, *final_reply;
		gchar *expected_final_reply;

		g_test_message ("Vector %u of %lu.", i, G_N_ELEMENTS (vectors));

		v = g_variant_parse (G_VARIANT_TYPE (vectors[i].type),
		                     vectors[i].message, NULL, NULL, &error);
		g_assert_no_error (error);

		/* Try parsing the message. */
		scram_authentication_server_parse_final_message (&server, v,
		                                                 &error);
		g_assert_error (error, SCRAM_AUTHENTICATION_ERROR,
		                (gint) vectors[i].expected_error_code);

		g_clear_error (&error);
		g_variant_unref (v);

		/* Check that the server returns an error in its next
		 * message. */
		final_reply =
			scram_authentication_server_build_final_reply (&server);
		expected_final_reply =
			g_strdup_printf ("({'e': <'%s'>},)",
			                 vectors[i].expected_error_value);
		assert_variants_equal (final_reply, "(a{sv})",
		                       expected_final_reply);
		g_free (expected_final_reply);
		g_variant_unref (final_reply);
	}

	scram_authentication_server_clear (&server);
}

/* Test various error handling paths triggered by a malformed input #GVariant
 * to scram_authentication_client_parse_final_reply(). */
static void
authentication_final_reply_parse_error (void)
{
	ScramAuthenticationClient client;
	guint i;
	ScramAuthenticationMechanism mechanism = SCRAM_AUTHENTICATION_SCRAM_SHA_1;
	GVariant *first_message, *first_reply, *final_message;
	const gchar *username = "user";
	const gchar *password = "pencil";
	GError *error = NULL;
	const struct {
		const gchar *type;
		const gchar *message;
		ScramAuthenticationError expected_error_code;
	} vectors[] = {
		/* 0. Invalid type. */
		{ "(a{ss})",
		  "({'v': 'dRCD40g9a8rF7RWqLnqc/GOjZUQ='},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_MESSAGE_TYPE },
		/* 1. Missing ‘v’ attribute. */
		{ "(a{sv})",
		  "({},)",
		   SCRAM_AUTHENTICATION_ERROR_MISSING_ATTRIBUTE },
		/* 2. Unsupported extension attribute. */
		{ "(a{sv})",
		  "({'v': <'dRCD40g9a8rF7RWqLnqc/GOjZUQ='>, "
		    "'m': <'some extension'>},)",
		   SCRAM_AUTHENTICATION_ERROR_UNSUPPORTED_ATTRIBUTE },
		/* 3. Invalid server signature. */
		{ "(a{sv})",
		  "({'v': <''>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_SERVER_SIGNATURE },
		/* 4. Invalid server signature. */
		{ "(a{sv})",
		  "({'v': <'this-definitely-isnt-valid'>},)",
		   SCRAM_AUTHENTICATION_ERROR_INVALID_SERVER_SIGNATURE },
		/* 5. Server-side error. */
		{ "(a{sv})",
		  "({'e': <'other-error'>},)",
		   SCRAM_AUTHENTICATION_ERROR_FAILED },
	};

	/* Set up a client, build the first message, parse the first reply and
	 * build the final reply to set internal state. */
	scram_authentication_client_init (&client,
	                                "some-client-nonce",
	                                &mechanism, 1, FALSE);

	first_message =
		scram_authentication_client_build_first_message (&client,
		                                                 username,
		                                                 password,
		                                                 &error);
	g_assert_no_error (error);
	g_assert (first_message != NULL);
	g_variant_unref (first_message);

	first_reply = g_variant_parse (G_VARIANT_TYPE ("(a{sv})"),
	                                 "({'r': <'some-client-nonce"
	                                          "-some-server-nonce'>, "
	                                   "'s': <'QSXCR+Q6sek8bf92'>, "
	                                   "'i': <uint32 4096>},)",
	                                 NULL, NULL, &error);
	g_assert_no_error (error);

	scram_authentication_client_parse_first_reply (&client, first_reply,
	                                               &error);
	g_assert_no_error (error);

	g_variant_unref (first_reply);

	final_message = scram_authentication_client_build_final_message (&client);
	g_assert (final_message != NULL);
	g_variant_unref (final_message);

	/* Run the tests. */
	for (i = 0; i < G_N_ELEMENTS (vectors); i++) {
		GVariant *v;

		g_test_message ("Vector %u of %lu.", i, G_N_ELEMENTS (vectors));

		v = g_variant_parse (G_VARIANT_TYPE (vectors[i].type),
		                     vectors[i].message, NULL, NULL, &error);
		g_assert_no_error (error);

		/* Try parsing the message. */
		scram_authentication_client_parse_final_reply (&client, v,
		                                               &error);
		g_assert_error (error, SCRAM_AUTHENTICATION_ERROR,
		                (gint) vectors[i].expected_error_code);

		g_clear_error (&error);
		g_variant_unref (v);
	}

	scram_authentication_client_clear (&client);
}


/* Test that scram_authentication_generate_nonce() returns different values each
 * time. I’m not implementing a full-blown statistical randomness test though.
 * That would be silly. */
static void
authentication_generate_nonce (void)
{
	guint i, j;
	gchar *nonces[30];
	GError *error = NULL;

	/* Generate lots of nonces. */
	for (i = 0; i < G_N_ELEMENTS (nonces); i++) {
		nonces[i] = scram_authentication_generate_nonce (&error);
		g_assert_no_error (error);
	}

	/* Check they’re all unique. */
	for (i = 0; i < G_N_ELEMENTS (nonces); i++) {
		g_assert (nonces[i] != NULL);
		g_assert_cmpstr (nonces[i], !=, "");
		g_assert_cmpuint (strlen (nonces[i]), >=, 16);

		for (j = i + 1; j < G_N_ELEMENTS (nonces); j++) {
			g_assert_cmpuint (g_strcmp0 (nonces[i], nonces[j]),
			                  !=, 0);
		}
	}

	/* Tidy up. */
	for (i = 0; i < G_N_ELEMENTS (nonces); i++) {
		g_free (nonces[i]);
	}
}

/* Test that building a stand-alone error message is successful. */
static void
authentication_server_build_error_message (void)
{
	ScramAuthenticationServer server;
	GVariant *m;
	GError *error = NULL;
	ScramAuthenticationMechanism mechanism = SCRAM_AUTHENTICATION_SCRAM_SHA_1;

	scram_authentication_server_init (&server, "some-server-nonce",
	                                  &mechanism, 1);

	g_set_error (&error, SCRAM_AUTHENTICATION_ERROR,
	             SCRAM_AUTHENTICATION_ERROR_FAILED,
	             "Some error message.");
	m = scram_authentication_server_build_error_message (&server, error);

	assert_variants_equal (m, "(a{sv})", "({'e': <'other-error'>},)");

	g_variant_unref (m);
	g_error_free (error);

	scram_authentication_server_clear (&server);
}


int
main (int argc, char **argv)
{
	g_setenv ("GSETTINGS_BACKEND", "memory", TRUE);

	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/scram/authentication/client/init-clear",
	                 authentication_client_init_clear);
	g_test_add_func ("/scram/authentication/server/init-clear",
	                 authentication_server_init_clear);

	g_test_add_func ("/scram/authentication/client/choose-mechanism",
	                 authentication_client_choose_mechanism);

	g_test_add_func ("/scram/authentication/success",
	                 authentication_success);

	g_test_add_func ("/scram/authentication/salt-password",
	                 authentication_salt_password);

	g_test_add_func ("/scram/authentication/first-message/parse-error",
	                 authentication_first_message_parse_error);
	g_test_add_func ("/scram/authentication/first-message/short-username",
	                 authentication_first_message_short_username);
	g_test_add_func ("/scram/authentication/first-reply/parse-error",
	                 authentication_first_reply_parse_error);
	g_test_add_func ("/scram/authentication/final-message/parse-error",
	                 authentication_final_message_parse_error);
	g_test_add_func ("/scram/authentication/final-reply/parse-error",
	                 authentication_final_reply_parse_error);

	g_test_add_func ("/scram/authentication/generate-nonce",
	                 authentication_generate_nonce);

	g_test_add_func ("/scram/authentication/server/build-error-message",
	                 authentication_server_build_error_message);

	g_test_run ();

	return 0;
}
