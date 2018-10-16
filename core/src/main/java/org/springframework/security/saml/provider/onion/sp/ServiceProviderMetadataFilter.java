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
import java.net.URLEncoder;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.provider.onion.HostedProvider;
import org.springframework.security.saml.provider.onion.SamlProcessingFilter;
import org.springframework.security.saml.provider.onion.SamlWebMessage;
import org.springframework.security.saml.saml2.metadata.Metadata;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;

public class ServiceProviderMetadataFilter extends SamlProcessingFilter {

	private final RequestMatcher requestMatcher;
	private final String filename;
	private final SamlTransformer transformer;

	public ServiceProviderMetadataFilter(RequestMatcher requestMatcher,
										 String filename,
										 SamlTransformer transformer) {
		super(transformer);
		this.requestMatcher = requestMatcher;
		this.filename = filename;
		this.transformer = transformer;
	}

	public ServiceProviderMetadataFilter(SamlTransformer transformer) {
		this(new AntPathRequestMatcher("/saml/sp/metadata"), "saml-sp-metadata.xml", transformer);
	}

	@Override
	protected void doSamlFilter(SamlWebMessage message,
								HostedProvider provider,
								HttpServletRequest request,
								HttpServletResponse response,
								FilterChain filterChain) throws ServletException, IOException {
		if (getRequestMatcher().matches(request)) {
			Metadata metadata = provider.getMetadata();
			String xml = transformer.toXml(metadata);
			getCacheHeaderWriter().writeHeaders(request, response);
			response.setContentType(TEXT_XML_VALUE);
			String safeFilename = URLEncoder.encode(getFilename(), "ISO-8859-1");
			response.addHeader(CONTENT_DISPOSITION, "attachment; filename=\"" + safeFilename + "\"" + ";");
			response.getWriter().write(xml);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

	public RequestMatcher getRequestMatcher() {
		return requestMatcher;
	}

	public String getFilename() {
		return filename;
	}
}
