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

package org.springframework.security.saml.provider.onion;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.SamlTemplateEngine;
import org.springframework.security.saml.SamlTransformer;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.spi.opensaml.OpenSamlVelocityEngine;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.filter.OncePerRequestFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.util.StringUtils.hasText;

public abstract class SamlProcessingFilter<T extends HostedProvider> extends OncePerRequestFilter {

	private static Log logger = LogFactory.getLog(SamlProcessingFilter.class);

	private String errorTemplate = "/templates/spi/generic-error.vm";
	private SamlTemplateEngine samlTemplateEngine = new OpenSamlVelocityEngine();
	private HeaderWriter cacheHeaderWriter = new CacheControlHeadersWriter();

	private final SamlTransformer transformer;

	protected SamlProcessingFilter(SamlTransformer transformer) {
		this.transformer = transformer;
	}

	@Override
	protected final void doFilterInternal(HttpServletRequest request,
										  HttpServletResponse response,
										  FilterChain filterChain)
		throws ServletException, IOException {

		T provider = getProvider(request);
		if (provider == null) {
			filterChain.doFilter(request, response);
		}
		else {
			SamlWebMessage message = getMessage(request, provider);
			doSamlFilter(message, provider, request, response, filterChain);
		}

	}

	private T getProvider(HttpServletRequest request) {
		return (T) request.getAttribute(HostedProvider.PROVIDER_ATTRIBUTE);
	}

	private SamlWebMessage getMessage(HttpServletRequest request, T provider) {
		SamlWebMessage result = (SamlWebMessage) request.getAttribute(SamlWebMessage.MESSAGE_ATTRIBUTE);
		if (result == null) {
			Saml2Object samlRequest = decode(request, provider, "SAMLRequest");
			Saml2Object samlResponse = decode(request, provider, "SAMLResponse");
			result = new DefaultSamlWebMessage(
				samlRequest,
				samlResponse,
				request.getParameter("RelayState"),
				new LinkedMultiValueMap<>(getMultiValueMap(request.getParameterMap()))
			);
			request.setAttribute(SamlWebMessage.MESSAGE_ATTRIBUTE, result);
		}
		return result;
	}

	private MultiValueMap<String, String> getMultiValueMap(Map<String, String[]> parameterMap) {
		LinkedMultiValueMap<String,String> result = new LinkedMultiValueMap<>();
		parameterMap.entrySet().stream().forEach(
			e -> result.put(e.getKey(), asList(e.getValue()))
		);
		return result;
	}

	private Saml2Object decode(HttpServletRequest request, T provider, String parameter) {
		String p = request.getParameter(parameter);
		if (hasText(p)) {
			String xml = transformer.samlDecode(p, "GET".equalsIgnoreCase(request.getMethod()));
			return transformer.fromXml(xml, null, provider.getConfiguration().getKeys());
		}
		return null;
	}

	protected abstract void doSamlFilter(SamlWebMessage message,
										 T provider,
										 HttpServletRequest request,
										 HttpServletResponse response,
										 FilterChain filterChain) throws ServletException, IOException;

	public String getErrorTemplate() {
		return errorTemplate;
	}

	public SamlProcessingFilter setErrorTemplate(String errorTemplate) {
		this.errorTemplate = errorTemplate;
		return this;
	}

	public HeaderWriter getCacheHeaderWriter() {
		return cacheHeaderWriter;
	}

	protected void processHtml(HttpServletRequest request,
							   HttpServletResponse response,
							   String html,
							   Map<String, Object> model) {
		cacheHeaderWriter.writeHeaders(request, response);
		response.setContentType(TEXT_HTML_VALUE);
		response.setCharacterEncoding(UTF_8.name());
		StringWriter out = new StringWriter();
		getSamlTemplateEngine().process(
			request,
			html,
			model,
			out
		);
		try {
			response.getWriter().write(out.toString());
		} catch (IOException e) {
			throw new SamlException(e);
		}
	}

	public SamlTemplateEngine getSamlTemplateEngine() {
		return samlTemplateEngine;
	}

	public SamlProcessingFilter setSamlTemplateEngine(SamlTemplateEngine samlTemplateEngine) {
		this.samlTemplateEngine = samlTemplateEngine;
		return this;
	}

	public SamlTransformer getTransformer() {
		return transformer;
	}
}
