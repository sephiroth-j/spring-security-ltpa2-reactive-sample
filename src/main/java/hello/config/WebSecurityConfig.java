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
package hello.config;

import de.sephirothj.spring.security.ltpa2.reactive.Ltpa2AuthConverter;
import de.sephirothj.spring.security.ltpa2.reactive.Ltpa2AuthManager;
import de.sephirothj.spring.security.ltpa2.LtpaKeyUtils;
import hello.auth.MyLdapUserDetailsManager;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.ldap.DefaultLdapUsernameToDnMapper;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@EnableCaching
public class WebSecurityConfig
{

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(final ServerHttpSecurity http, final ReactiveUserDetailsService userDetailsService, AuthenticationWebFilter ltpa2AuthenticationWebFilter)
	{
		http
			.csrf().disable()
			.httpBasic().disable()
			.authorizeExchange()
			.pathMatchers(
				"/",
				"/home"
			).permitAll()
			.pathMatchers("/hello").hasRole("DEVELOPERS")
			// all other require any authentication
			.anyExchange().authenticated()
			.and()
			// apply ltpa2 authentication filter
			.addFilterAt(ltpa2AuthenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);
		return http.build();
	}

	@Bean
	AuthenticationWebFilter x509AuthenticationWebFilter(ReactiveUserDetailsService userDetailsService) throws GeneralSecurityException
	{
		final Ltpa2AuthConverter converter = new Ltpa2AuthConverter();
		converter.setSharedKey(sharedKey());
		converter.setSignerKey(signerKey());

		final AuthenticationWebFilter webfilter = new AuthenticationWebFilter(new Ltpa2AuthManager(userDetailsService));
		webfilter.setServerAuthenticationConverter(converter);
		return webfilter;
	}

	@Bean
	public ReactiveUserDetailsService userDetailsService()
	{
		final DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource("ldap://127.0.0.1:33389/dc=foo,dc=bar");
		contextSource.afterPropertiesSet();

		MyLdapUserDetailsManager manager = new MyLdapUserDetailsManager(contextSource);
		manager.setUsernameMapper(new DefaultLdapUsernameToDnMapper("ou=user", "cn"));
		manager.setGroupSearchBase("ou=groups");

		return manager;
	}

	private SecretKey sharedKey() throws GeneralSecurityException
	{
		String testKey = "JvywHhxC+EhtUdeusbo31E5IUOEPmbMxMnKTTOB39fo=";
		String testKeyPass = "test123";
		return LtpaKeyUtils.decryptSharedKey(testKey, testKeyPass);
	}

	private PublicKey signerKey() throws GeneralSecurityException
	{
		String testSignerKey = "AOECPMDAs0o7MzQIgxZhAXJZ2BaDE3mqRZAbkbQO38CgUIgeAPEA3iWIYp+p/Ai0J4//UOml20an+AuCnDGzcFCaf3S3EAiR4cK59vl/u8TIswPIg2akh4J7qL3E/qRxN9WD945tS3h0YhJZSq7rC22wytLsxbFuKpEuYfm1i5spAQAB";
		return LtpaKeyUtils.decodePublicKey(testSignerKey);
	}
}
