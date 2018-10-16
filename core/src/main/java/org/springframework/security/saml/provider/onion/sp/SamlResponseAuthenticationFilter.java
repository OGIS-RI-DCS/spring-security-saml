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

package org.springframework.security.saml.provider.onion.sp;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.SamlValidator;
import org.springframework.security.saml.provider.onion.SamlWebMessage;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.spi.DefaultSamlAuthentication;
import org.springframework.security.saml.validation.ValidationException;
import org.springframework.security.saml.validation.ValidationResult;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.springframework.security.saml.provider.onion.HostedProvider.PROVIDER_ATTRIBUTE;

public class SamlResponseAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static Log
		logger = LogFactory.getLog(SamlResponseAuthenticationFilter.class);

	private final SamlTransformer transformer;
	private final SamlValidator validator;

	private SamlResponseAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher,
											 SamlTransformer transformer,
											 SamlValidator validator) {
		super(requiresAuthenticationRequestMatcher);
		this.transformer = transformer;
		this.validator = validator;
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return getSamlResponseData(request) != null;
	}

	private Response getSamlResponseData(HttpServletRequest request) {
		SamlWebMessage message = (SamlWebMessage) request.getAttribute(SamlWebMessage.MESSAGE_ATTRIBUTE);
		return
			message == null ? null :
				message.getSamlResponse() == null ? null :
				message.getSamlResponse() instanceof Response ? (Response)message.getSamlResponse() : null;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
		throws AuthenticationException, IOException, ServletException {

		ServiceProvider provider = (ServiceProvider) request.getAttribute(PROVIDER_ATTRIBUTE);
		Assert.notNull(provider, "This filter should be configured after ");

		Response r = getSamlResponseData(request);
		if (r == null) {
			throw new AuthenticationCredentialsNotFoundException("SAMLResponse parameter missing or invalid.");
		}
		IdentityProviderMetadata remote = provider.getRemoteProvider(r.getOriginEntityId());
		if (remote == null) {
			throw new AuthenticationCredentialsNotFoundException("Source of SAMLResponse parameter is not recognized.");
		}

		if (logger.isTraceEnabled()) {
			logger.trace("Received SAMLResponse XML:" + r.getOriginalXML());
		}

		try {
			validator.validate(r, null);
		} catch (ValidationException x) {
			ValidationResult validationResult = x.getErrors();
			if (validationResult.hasErrors()) {
				throw new InsufficientAuthenticationException(
					validationResult.toString()
				);
			}
			else {
				throw new InsufficientAuthenticationException(x.getMessage());
			}
		}

		Authentication authentication = new DefaultSamlAuthentication(
			true,
			r.getAssertions().get(0),
			remote.getEntityId(),
			provider.getMetadata().getEntityId(),
			request.getParameter("RelayState")
		);

		return getAuthenticationManager().authenticate(authentication);

	}

}
