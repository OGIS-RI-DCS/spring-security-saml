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

package org.springframework.security.saml.web;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.provider.config.ThreadLocalSamlConfigurationRepository;
import org.springframework.security.saml.provider.registration.SamlServerConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;

public class ThreadLocalSamlConfigurationFilter extends OncePerRequestFilter {

	private final ThreadLocalSamlConfigurationRepository repository;
	private boolean includeStandardPortsInUrl = false;

	public ThreadLocalSamlConfigurationFilter(ThreadLocalSamlConfigurationRepository repository) {
		this.repository = repository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
		throws ServletException, IOException {
		SamlServerConfiguration configuration = getConfiguration(request);
		//allow for dynamic host paths
		try {
			repository.setServerConfiguration(configuration);
			filterChain.doFilter(request, response);
		} finally {
			repository.reset();
		}
	}

	protected SamlServerConfiguration getConfiguration(HttpServletRequest request) {
		return repository.getServerConfiguration(request);
	}

	protected String getBasePath(HttpServletRequest request) {
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

	public boolean isIncludeStandardPortsInUrl() {
		return includeStandardPortsInUrl;
	}

	public ThreadLocalSamlConfigurationFilter setIncludeStandardPortsInUrl(boolean includeStandardPortsInUrl) {
		this.includeStandardPortsInUrl = includeStandardPortsInUrl;
		return this;
	}
}
