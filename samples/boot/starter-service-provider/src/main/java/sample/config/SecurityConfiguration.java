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

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl;

import static org.springframework.security.saml.provider.service.config.SamlServiceProviderSecurityDsl.serviceProvider;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration {


	@Configuration
	@Order(1)
	public class SamlSecurity extends WebSecurityConfigurerAdapter {

		private final SamlConfigurationRepository repository;

		public SamlSecurity(SamlConfigurationRepository repository) {
			this.repository = repository;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			SamlServiceProviderSecurityDsl configurer = serviceProvider();
			configurer
				.prefix("saml/sp")
				.configurationRepository(repository);
			http.apply(configurer);
		}
	}

	@Configuration
	@Order(2)
	public class AppSecurity extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.antMatcher("/**")
				.authorizeRequests()
				.antMatchers("/**").authenticated()
				.and()
				.formLogin().loginPage("/saml/sp/select")
			;
		}
	}

}
