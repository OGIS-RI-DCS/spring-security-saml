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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlMetadataException;
import org.springframework.security.saml.SamlProviderNotFoundException;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.registration.AbstractHostedProviderConfiguration;
import org.springframework.security.saml.provider.registration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.provider.registration.SamlServerConfiguration;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.metadata.SsoProvider;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static java.util.Optional.ofNullable;
import static org.springframework.security.saml.saml2.metadata.Binding.REDIRECT;
import static org.springframework.util.StringUtils.hasText;

public class DefaultServiceProviderResolver implements HostedServiceProviderResolver {

	private final SamlMetadataCache cache;
	private final SamlTransformer transformer;
	private static Log logger = LogFactory.getLog(DefaultServiceProviderResolver.class);
	private boolean includeStandardPortsInUrl = false;

	public DefaultServiceProviderResolver(SamlMetadataCache cache,
										  SamlTransformer transformer) {
		this.cache = cache;
		this.transformer = transformer;
	}

	public void setIncludeStandardPortsInUrl(boolean includeStandardPortsInUrl) {
		this.includeStandardPortsInUrl = includeStandardPortsInUrl;
	}

	@Override
	public HostedServiceProvider resolve(HttpServletRequest request) {
		SamlServerConfiguration configuration = getConfiguration(request);
		HostedServiceProviderConfiguration spConfig = configuration.getServiceProvider();
		String basePath = spConfig.getBasePath();
		if (!hasText(basePath)) {
			basePath = getBasePath(request);
		}

		List<SimpleKey> keys = new LinkedList<>(ofNullable(spConfig.getKeys()).orElse(Collections.emptyList()));
		SimpleKey activeKey = keys.size() > 0 ? keys.get(0) : null;
		SimpleKey signingKey = spConfig.isSignMetadata() ? activeKey : null;

		String prefix = hasText(spConfig.getPrefix()) ? spConfig.getPrefix() : "saml/sp/";
		String aliasPath = getAliasPath(spConfig);
		ServiceProviderMetadata metadata =
			serviceProviderMetadata(
				basePath,
				signingKey,
				keys,
				prefix,
				aliasPath,
				spConfig.getDefaultSigningAlgorithm(),
				spConfig.getDefaultDigest()
			);
		if (!spConfig.getNameIds().isEmpty()) {
			metadata.getServiceProvider().setNameIds(spConfig.getNameIds());
		}

		if (!spConfig.isSingleLogoutEnabled()) {
			metadata.getServiceProvider().setSingleLogoutService(Collections.emptyList());
		}
		if (hasText(spConfig.getEntityId())) {
			metadata.setEntityId(spConfig.getEntityId());
		}
		if (hasText(spConfig.getAlias())) {
			metadata.setEntityAlias(spConfig.getAlias());
		}
		metadata.getServiceProvider().setWantAssertionsSigned(spConfig.isWantAssertionsSigned());
		metadata.getServiceProvider().setAuthnRequestsSigned(spConfig.isSignRequests());

		Map<ExternalIdentityProviderConfiguration, IdentityProviderMetadata> identityProviders = new HashMap<>();
		spConfig.getProviders().forEach(
			p -> identityProviders.put(p,getIdentityProvider(p))
		);

		return new ServiceProvider(
			spConfig,
			metadata,
			identityProviders
		);
	}

	private String getBasePath(HttpServletRequest request) {
		boolean includePort = true;
		if (443 == request.getServerPort() && "https".equals(request.getScheme())) {
			includePort = isIncludeStandardPortsInUrl();
		}
		else if (80 == request.getServerPort() && "http".equals(request.getScheme())) {
			includePort = isIncludeStandardPortsInUrl();
		}
		return request.getScheme() +
			"://" +
			request.getServerName() +
			(includePort ? (":" + request.getServerPort()) : "") +
			request.getContextPath();
	}

	private boolean isIncludeStandardPortsInUrl() {
		return includeStandardPortsInUrl;
	}

	private IdentityProviderMetadata getIdentityProvider(ExternalIdentityProviderConfiguration p) {
		return resolve(p.getMetadata(), p.isSkipSslValidation());
	}

	protected SamlServerConfiguration getConfiguration(HttpServletRequest request) {
		return null;
	}

	private String getAliasPath(AbstractHostedProviderConfiguration configuration) {
		try {
			return hasText(configuration.getAlias()) ?
				UriUtils.encode(configuration.getAlias(), StandardCharsets.ISO_8859_1.name()) :
				UriUtils.encode(configuration.getEntityId(), StandardCharsets.ISO_8859_1.name());
		} catch (UnsupportedEncodingException e) {
			throw new SamlException(e);
		}
	}

	private ServiceProviderMetadata serviceProviderMetadata(String baseUrl,
															SimpleKey signingKey,
															List<SimpleKey> keys,
															String prefix,
															String aliasPath,
															AlgorithmMethod signAlgorithm,
															DigestMethod signDigest) {

		return new ServiceProviderMetadata()
			.setEntityId(baseUrl)
			.setId(UUID.randomUUID().toString())
			.setSigningKey(signingKey, signAlgorithm, signDigest)
			.setProviders(
				asList(
					new org.springframework.security.saml.saml2.metadata.ServiceProvider()
						.setKeys(keys)
						.setWantAssertionsSigned(true)
						.setAuthnRequestsSigned(signingKey != null)
						.setAssertionConsumerService(
							asList(
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, Binding.POST, 0, true),
								getEndpoint(baseUrl, prefix + "SSO/alias/" + aliasPath, REDIRECT, 1, false)
							)
						)
						.setNameIds(asList(NameId.PERSISTENT, NameId.EMAIL))
						.setKeys(keys)
						.setSingleLogoutService(
							asList(
								getEndpoint(baseUrl, prefix + "logout/alias/" + aliasPath, REDIRECT, 0, true)
							)
						)
				)
			);
	}

	private Endpoint getEndpoint(String baseUrl, String path, Binding binding, int index, boolean isDefault) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl);
		builder.pathSegment(path);
		return getEndpoint(builder.build().toUriString(), binding, index, isDefault);
	}

	private Endpoint getEndpoint(String url, Binding binding, int index, boolean isDefault) {
		return
			new Endpoint()
				.setIndex(index)
				.setBinding(binding)
				.setLocation(url)
				.setDefault(isDefault)
				.setIndex(index);
	}

	private IdentityProviderMetadata resolve(String metadata, boolean skipSslValidation) {
		IdentityProviderMetadata result;
		if (isUri(metadata)) {
			try {
				byte[] data = cache.getMetadata(metadata, skipSslValidation);
				result = transformMetadata(new String(data, StandardCharsets.UTF_8));
			} catch (SamlException x) {
				throw x;
			} catch (Exception x) {
				String message = format("Unable to fetch metadata from: %s with message: %s", metadata, x.getMessage());
				if (logger.isDebugEnabled()) {
					logger.debug(message, x);
				}
				else {
					logger.info(message);
				}
				throw new SamlMetadataException("Unable to successfully get metadata from:" + metadata, x);
			}
		}
		else {
			result = transformMetadata(metadata);
		}
		return throwIfNull(
			result,
			"metadata",
			metadata
		);
	}

	private IdentityProviderMetadata throwIfNull(IdentityProviderMetadata metadata, String key, String value) {
		if (metadata == null) {
			String message = "Provider for key '%s' with value '%s' not found.";
			throw new SamlProviderNotFoundException(
				String.format(message, key, value)
			);
		}
		else {
			return metadata;
		}
	}

	private IdentityProviderMetadata transformMetadata(String data) {
		Metadata metadata = (Metadata)transformer.fromXml(data, null, null);
		IdentityProviderMetadata result;
		if (metadata instanceof IdentityProviderMetadata) {
			result =  (IdentityProviderMetadata)metadata;
		} else {
			List<SsoProvider> providers = metadata.getSsoProviders();
			providers = providers.stream().filter(p -> p instanceof IdentityProvider).collect(Collectors.toList());
			result = new IdentityProviderMetadata(metadata);
			result.setProviders(providers);
		}
		return result;
	}

	private boolean isUri(String uri) {
		boolean isUri = false;
		try {
			new URI(uri);
			isUri = true;
		} catch (URISyntaxException e) {
		}
		return isUri;
	}
}
