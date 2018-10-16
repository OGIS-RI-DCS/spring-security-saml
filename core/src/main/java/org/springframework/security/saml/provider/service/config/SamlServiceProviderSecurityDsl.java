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

package org.springframework.security.saml.provider.service.config;

import java.time.Clock;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.onion.sp.DefaultServiceProviderResolver;
import org.springframework.security.saml.provider.onion.sp.SamlAuthenticationRequestFilter;
import org.springframework.security.saml.provider.onion.sp.SamlServiceProviderResolvingFilter;
import org.springframework.security.saml.provider.onion.sp.ServiceProviderMetadataFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static org.springframework.security.saml.util.StringUtils.stripSlashes;

public class SamlServiceProviderSecurityDsl
	extends AbstractHttpConfigurer<SamlServiceProviderSecurityDsl, HttpSecurity> {

	private static Log logger = LogFactory.getLog(SamlServiceProviderSecurityDsl.class);

	private SamlConfigurationRepository samlConfigurationRepository;
	private String prefix = "/saml/sp";

	@Override
	public void init(HttpSecurity builder) throws Exception {
		super.init(builder);
		String filterChainPattern = "/" + stripSlashes(prefix) + "/**";
		logger.info("Configuring SAML SP on pattern:" + filterChainPattern);
		builder
			.antMatcher(filterChainPattern)
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/**").permitAll();
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		Assert.notNull(samlConfigurationRepository, "SamlConfigurationRepository must be set.");

		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		SamlTransformer transformer = context.getBean(SamlTransformer.class);
		SamlMetadataCache cache = context.getBean(SamlMetadataCache.class);
		Clock clock = context.getBean(Clock.class);

		DefaultServiceProviderResolver resolver = context.getBean(DefaultServiceProviderResolver.class);

		SamlServiceProviderResolvingFilter resolvingFilter = new SamlServiceProviderResolvingFilter(
			new AntPathRequestMatcher("/" + stripSlashes(prefix) + "/**"),
			resolver
		);
		ServiceProviderMetadataFilter metadataFilter = new ServiceProviderMetadataFilter(transformer);
		SamlAuthenticationRequestFilter authenticationRequestFilter = new SamlAuthenticationRequestFilter(
			transformer,
			new AntPathRequestMatcher("/" + stripSlashes(prefix) + "/discovery/**"),
			clock
		);
		http
			.addFilterAfter(
				resolvingFilter,
				BasicAuthenticationFilter.class
			)
			.addFilterAfter(
				metadataFilter,
				resolvingFilter.getClass()
			)
			.addFilterAfter(
				authenticationRequestFilter,
				metadataFilter.getClass()
			)
		;

	}

	public static SamlServiceProviderSecurityDsl serviceProvider() {
		return new SamlServiceProviderSecurityDsl();
	}

	public SamlServiceProviderSecurityDsl configurationRepository(SamlConfigurationRepository samlConfigurationRepository) {
		this.samlConfigurationRepository = samlConfigurationRepository;
		return this;
	}

	public SamlServiceProviderSecurityDsl prefix(String prefix) {
		this.prefix = prefix;
		return this;
	}
}
