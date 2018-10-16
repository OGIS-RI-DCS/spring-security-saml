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

import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.util.MultiValueMap;

public class DefaultSamlWebMessage implements SamlWebMessage {
	private final Saml2Object samlRequest;
	private final Saml2Object samlResponse;
	private final String relayState;
	private final MultiValueMap<String, String> parameters;

	public DefaultSamlWebMessage(Saml2Object samlRequest,
								 Saml2Object samlResponse,
								 String relayState,
								 MultiValueMap<String, String> parameters) {
		this.samlRequest = samlRequest;
		this.samlResponse = samlResponse;
		this.relayState = relayState;
		this.parameters = parameters;
	}


	@Override
	public Saml2Object getSamlRequest() {
		return samlRequest;
	}

	@Override
	public Saml2Object getSamlResponse() {
		return samlResponse;
	}

	@Override
	public String getRelayState() {
		return relayState;
	}

	@Override
	public MultiValueMap<String, String> getMessageParameters() {
		return parameters;
	}
}
