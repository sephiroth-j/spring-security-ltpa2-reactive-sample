/*
 * Copyright 2019 Ronny "Sephiroth" Perinke <sephiroth@sephiroth-j.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package hello;

import de.sephirothj.spring.security.ltpa2.Ltpa2Token;
import de.sephirothj.spring.security.ltpa2.Ltpa2Utils;
import de.sephirothj.spring.security.ltpa2.LtpaKeyUtils;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.time.LocalDateTime;
import javax.crypto.SecretKey;
import lombok.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

@ExtendWith(SpringExtension.class)
@SpringBootTest
class ApplicationTests
{
	@Autowired
	private ApplicationContext context;

	private WebTestClient webTestClient;

	@BeforeEach
	void setup()
	{
		webTestClient = WebTestClient.bindToApplicationContext(context)
			.apply(springSecurity())
			.configureClient()
			.build();
	}

	@Test
	void accessUnsecuredResourceThenOk()
	{
		webTestClient.get().uri("/")
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void accessSecuredResourceUnauthenticatedShouldBeForbidden()
	{
		webTestClient.get().uri("/hello")
			.exchange()
			.expectStatus().isUnauthorized();
	}

	@Test
	void accessSecuredResourceWithInvalidAuthenticationShouldBeForbidden() throws Exception
	{
		webTestClient.get().uri("/hello")
			.header(HttpHeaders.AUTHORIZATION, "sadfdas")
			.exchange()
			.expectStatus().isUnauthorized();
	}

	@Test
	void accessSecuredResourceWithAuthenticationThenOk() throws Exception
	{
		Ltpa2Token token = createTestToken();

		webTestClient.get().uri("/hello")
			.header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(encryptToken(token)))
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void accessSecuredResourceWithCookieThenOk() throws Exception
	{
		Ltpa2Token token = createTestToken();

		webTestClient.get().uri("/hello")
			.cookie("LtpaToken2", encryptToken(token))
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void accessSecuredMethodWithAuthenticationThenOk() throws Exception
	{
		Ltpa2Token token = createTestToken();

		webTestClient.get().uri("/secured-method")
			.header(HttpHeaders.AUTHORIZATION, "LtpaToken2 ".concat(encryptToken(token)))
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	void accessSecuredMethodWithCookieThenOk() throws Exception
	{
		Ltpa2Token token = createTestToken();

		webTestClient.get().uri("/secured-method")
			.cookie("LtpaToken2", encryptToken(token))
			.exchange()
			.expectStatus().isOk();
	}

	@Test
	@WithMockUser(roles = "DEVELOPERS")
	void accessSecuredResourceAuthenticatedThenOk() throws Exception
	{
		webTestClient.get().uri("/hello")
			.exchange()
			.expectStatus().isOk();
	}

	private Ltpa2Token createTestToken()
	{
		Ltpa2Token token = new Ltpa2Token();
		token.setUser("user:LdapRegistry/CN=fae6d87c-c642-45a6-9f09-915c7fd8b08c,OU=user,DC=foo,DC=bar");
		token.setExpire(LocalDateTime.now().plusMinutes(1));
		return token;
	}

	private String encryptToken(@NonNull Ltpa2Token token) throws GeneralSecurityException
	{
		SecretKey sharedKey = LtpaKeyUtils.decryptSharedKey(Constants.ENCRYPTED_SHARED_KEY, Constants.ENCRYPTION_PASSWORD);
		PrivateKey privateKey = LtpaKeyUtils.decryptPrivateKey(Constants.ENCRYPTED_PRIVATE_KEY, Constants.ENCRYPTION_PASSWORD);

		return Ltpa2Utils.encryptToken(token, privateKey, sharedKey);
	}
}
