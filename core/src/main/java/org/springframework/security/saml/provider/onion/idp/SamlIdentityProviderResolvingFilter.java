/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.springframework.security.saml.provider.onion.idp;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.saml.provider.onion.HostedProvider.PROVIDER_ATTRIBUTE;

public class SamlIdentityProviderResolvingFilter extends OncePerRequestFilter {

	private final AntPathRequestMatcher idpMatcher;
	private final HostedIdentityProviderResolver idpResolver;

	public SamlIdentityProviderResolvingFilter(AntPathRequestMatcher idpMatcher,
											   HostedIdentityProviderResolver idpResolver) {
		this.idpMatcher = idpMatcher;
		this.idpResolver = idpResolver;
	}


	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		if (idpMatcher.matches(request)) {
			HostedIdentityProvider idp = idpResolver.resolve(request);
			request.setAttribute(PROVIDER_ATTRIBUTE, idp);
		}
		filterChain.doFilter(request, response);
	}
}
