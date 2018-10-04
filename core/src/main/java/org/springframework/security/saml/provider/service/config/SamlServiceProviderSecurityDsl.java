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

import java.util.LinkedList;
import java.util.List;
import javax.servlet.Filter;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.Assert;

public class SamlServiceProviderSecurityDsl
	extends AbstractHttpConfigurer<SamlServiceProviderSecurityDsl, HttpSecurity> {

	private boolean useStandardFilterConfiguration = true;
	private List<Filter> filters = new LinkedList<>();
	private SamlConfigurationRepository samlConfigurationRepository;


	@Override
	public void configure(HttpSecurity http) throws Exception {
		Assert.notNull(samlConfigurationRepository, "SamlConfigurationRepository must be set.");

		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		ThreadLocalSamlConfigurationRepository repository =
			new ThreadLocalSamlConfigurationRepository(samlConfigurationRepository);


		if (useStandardFilterConfiguration) {
			SamlServiceProviderServerBeanConfiguration spBeanConfig =
				context.getBean(SamlServiceProviderServerBeanConfiguration.class);
			Filter samlConfigurationFilter = spBeanConfig.samlConfigurationFilter();
			Filter metadataFilter = spBeanConfig.spMetadataFilter();
			Filter spAuthenticationRequestFilter = spBeanConfig.spAuthenticationRequestFilter();
			Filter spAuthenticationResponseFilter = spBeanConfig.spAuthenticationResponseFilter();
			Filter spSamlLogoutFilter = spBeanConfig.spSamlLogoutFilter();
			Filter spSelectIdentityProviderFilter = spBeanConfig.spSelectIdentityProviderFilter();
			http
				.addFilterAfter(
					samlConfigurationFilter,
					BasicAuthenticationFilter.class
				)
				.addFilterAfter(
					metadataFilter,
					samlConfigurationFilter.getClass()
				)
				.addFilterAfter(
					spAuthenticationRequestFilter,
					metadataFilter.getClass()
				)
				.addFilterAfter(
					spAuthenticationResponseFilter,
					spAuthenticationRequestFilter.getClass()
				)
				.addFilterAfter(
					spSamlLogoutFilter,
					spAuthenticationResponseFilter.getClass()
				)
				.addFilterAfter(
					spSelectIdentityProviderFilter,
					spSamlLogoutFilter.getClass()
				);
		}
	}



	public SamlServiceProviderSecurityDsl useStandardFilters() {
		return useStandardFilters(true);
	}

	public SamlServiceProviderSecurityDsl useStandardFilters(boolean enable) {
		this.useStandardFilterConfiguration = enable;
		return this;
	}

	public SamlServiceProviderSecurityDsl filters(List<Filter> filters) {
		this.filters.clear();
		this.filters.addAll(filters);
		return this;
	}

	public static SamlServiceProviderSecurityDsl serviceProvider() {
		return new SamlServiceProviderSecurityDsl();
	}

	public void configurationRepository(SamlConfigurationRepository samlConfigurationRepository) {
		this.samlConfigurationRepository = samlConfigurationRepository;
	}
}
