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
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.onion.SamlProcessingFilter;
import org.springframework.security.saml.provider.onion.SamlWebMessage;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.NameIdPolicy;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.spi.SamlHelper;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.joda.time.DateTime;

import static org.springframework.util.StringUtils.hasText;

public class SamlAuthenticationRequestFilter extends SamlProcessingFilter<ServiceProvider> {

	private final AntPathRequestMatcher matcher;
	private final Clock clock;
	private SamlHelper helper = new SamlHelper();
	private String postTemplate = "/templates/saml2-post-binding.vm";

	public SamlAuthenticationRequestFilter(SamlTransformer transformer,
										   AntPathRequestMatcher matcher,
										   Clock clock) {
		super(transformer);
		this.matcher = matcher;
		this.clock = clock;
	}

	@Override
	protected void doSamlFilter(SamlWebMessage message,
								ServiceProvider provider,
								HttpServletRequest request,
								HttpServletResponse response,
								FilterChain filterChain) throws ServletException, IOException {
		String idpIdentifier = message.getMessageParameters().getFirst("idp");
		if (matcher.matches(request)) {
			if (hasText(idpIdentifier)) {
				IdentityProviderMetadata idp = provider.getRemoteProvider(idpIdentifier);
				if (idp != null) {
					AuthenticationRequest authenticationRequest = authenticationRequest(provider, idp);
					Endpoint ep = helper.getPreferredEndpoint(
						idp.getIdentityProvider().getSingleSignOnService(),
						Binding.POST,
						-1
					);
					if (ep == null) {
						throw new SamlException("Unable to find single sign on endpoint for remote provider.");
					}
					sendAuthenticationRequest(
						provider,
						message,
						request,
						response,
						authenticationRequest,
						ep
					);
					return;
				}
			}
			throw new SamlException("Missing or invalid `idp` parameter in request.");
		}
		else {
			filterChain.doFilter(request, response);
		}
	}


	protected AuthenticationRequest authenticationRequest(ServiceProvider provider, IdentityProviderMetadata idp) {
		ServiceProviderMetadata sp = provider.getMetadata();
		AuthenticationRequest request = new AuthenticationRequest()
			// Some service providers will not accept first character if 0..9
			// Azure AD IdP for example.
			.setId("_" + UUID.randomUUID().toString().substring(1))
			.setIssueInstant(new DateTime(clock.millis()))
			.setForceAuth(Boolean.FALSE)
			.setPassive(Boolean.FALSE)
			.setBinding(Binding.POST)
			.setAssertionConsumerService(
				helper.getPreferredEndpoint(
					sp.getServiceProvider().getAssertionConsumerService(),
					Binding.POST,
					-1
				)
			)
			.setIssuer(new Issuer().setValue(sp.getEntityId()))
			.setDestination(idp.getIdentityProvider().getSingleSignOnService().get(0));
		if (sp.getServiceProvider().isAuthnRequestsSigned()) {
			request.setSigningKey(sp.getSigningKey(), sp.getAlgorithm(), sp.getDigest());
		}
		if (idp.getDefaultNameId() != null) {
			request.setNameIdPolicy(new NameIdPolicy(
				idp.getDefaultNameId(),
				sp.getEntityAlias(),
				true
			));
		}
		else if (idp.getIdentityProvider().getNameIds().size() > 0) {
			request.setNameIdPolicy(new NameIdPolicy(
				idp.getIdentityProvider().getNameIds().get(0),
				sp.getEntityAlias(),
				true
			));
		}
		return request;
	}

	protected void sendAuthenticationRequest(ServiceProvider provider,
											 SamlWebMessage message,
											 HttpServletRequest request,
											 HttpServletResponse response,
											 AuthenticationRequest authenticationRequest,
											 Endpoint location) throws IOException {
		getCacheHeaderWriter().writeHeaders(request, response);
		String relayState = message.getRelayState();
		String xml = getTransformer().toXml(authenticationRequest);
		if (location.getBinding().equals(Binding.REDIRECT)) {
			String encoded = getTransformer().samlEncode(xml, true);
			UriComponentsBuilder url = UriComponentsBuilder.fromUriString(location.getLocation());
			url.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.UTF_8.name()));
			if (hasText(relayState)) {
				url.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.UTF_8.name()));
			}
			String redirect = url.build(true).toUriString();
			response.sendRedirect(redirect);
		}
		else if (location.getBinding().equals(Binding.POST)) {
			String encoded = getTransformer().samlEncode(xml, false);
			Map<String, Object> model = new HashMap<>();
			model.put("action", location.getLocation());
			model.put("SAMLRequest", encoded);
			if (hasText(relayState)) {
				model.put("RelayState", relayState);
			}
			processHtml(
				request,
				response,
				getPostTemplate(),
				model
			);
		}
		else {
			processHtml(
				request,
				response,
				getErrorTemplate(),
				Collections.singletonMap("message", "Unsupported binding:" + location.getBinding().toString())
			);
		}
	}

	public AntPathRequestMatcher getMatcher() {
		return matcher;
	}

	public Clock getClock() {
		return clock;
	}

	public SamlHelper getHelper() {
		return helper;
	}

	public SamlAuthenticationRequestFilter setHelper(SamlHelper helper) {
		this.helper = helper;
		return this;
	}

	public String getPostTemplate() {
		return postTemplate;
	}

	public SamlAuthenticationRequestFilter setPostTemplate(String postTemplate) {
		this.postTemplate = postTemplate;
		return this;
	}
}
