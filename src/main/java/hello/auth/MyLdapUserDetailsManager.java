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
package hello.auth;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.NonNull;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.ldap.core.ContextSource;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsManager;
import reactor.core.publisher.Mono;

/**
 * Example of a {@link LdapUserDetailsManager} that alters the username given in the LTPA2 token in order to map it to the LDAP scheme
 *
 * @author Sephiroth
 */
public class MyLdapUserDetailsManager extends LdapUserDetailsManager implements ReactiveUserDetailsService
{
	protected static final Pattern UUID_EXTRACTION_PATTERN = Pattern.compile(".+=([a-f\\-0-9]{36}),.+", Pattern.CASE_INSENSITIVE);

	public MyLdapUserDetailsManager(ContextSource contextSource)
	{
		super(contextSource);
	}

	@Override
	public UserDetails loadUserByUsername(String username)
	{
		return super.loadUserByUsername(extractUuid(username));
	}

	/**
	 * extract the UUID from the DN-String
	 *
	 * @param username
	 * @return the UUID or {@code username} if no UUID was found
	 */
	protected static String extractUuid(@NonNull final String username)
	{
		Matcher matcher = UUID_EXTRACTION_PATTERN.matcher(username);
		return matcher.matches() ? matcher.group(1) : username;
	}

	@Cacheable(cacheNames = "ldapUser", sync = true)
	@Override
	public Mono<UserDetails> findByUsername(String username)
	{
		// simple but no good wrapper and for demo purpose only! use something like ReactiveAuthenticationManagerAdapter for production
		return Mono.justOrEmpty(loadUserByUsername(username));
	}
}
