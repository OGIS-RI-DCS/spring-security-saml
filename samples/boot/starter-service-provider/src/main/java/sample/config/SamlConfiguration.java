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

package sample.config;

import java.time.Clock;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml.SamlMetadataCache;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.onion.sp.DefaultServiceProviderResolver;
import org.springframework.security.saml.provider.registration.SamlServerConfiguration;
import org.springframework.security.saml.spi.DefaultMetadataCache;
import org.springframework.security.saml.spi.DefaultSamlTransformer;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.security.saml.spi.opensaml.OpenSamlImplementation;
import org.springframework.security.saml.util.RestOperationsUtils;

@Configuration
public class SamlConfiguration {
	@Bean
	public Clock time() {
		return Clock.systemUTC();
	}

	@Bean
	SpringSecuritySaml<OpenSamlImplementation> saml() {
		return new OpenSamlImplementation(time());
	}

	@Bean
	public SamlConfigurationRepository configurationRepository() {
		return new StaticSpConfigurationRepository(null, true, true);
	}

	@Bean
	public DefaultServiceProviderResolver serviceProviderResolver() {
		return new DefaultServiceProviderResolver(cache(), transformer()) {
			@Override
			protected SamlServerConfiguration getConfiguration(HttpServletRequest request) {
				return configurationRepository().getDefaultServerConfiguration();
			}
		};
	}

	@Bean
	public SamlMetadataCache cache() {
		RestOperationsUtils restOperations = new RestOperationsUtils(4000, 4000);
		return new DefaultMetadataCache(
			Clock.systemUTC(),
			restOperations.get(false),
			restOperations.get(true)
		);
	}

	@Bean
	public SamlTransformer transformer() {
		return new DefaultSamlTransformer(saml());
	}
}
