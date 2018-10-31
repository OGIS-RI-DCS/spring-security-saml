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

package sample.proof_of_concept.onelogin;

import java.io.IOException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.exception.SettingsException;
import com.onelogin.saml2.exception.ValidationError;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.settings.Saml2Settings;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class OneLoginResponse extends SamlResponse {
	/**
	 * Constructor to have a Response object full builded and ready to validate
	 * the saml response
	 *
	 * @param settings Saml2Settings object. Setting data
	 * @param request  the HttpRequest object to be processed (Contains GET and POST parameters, request URL, ...).
	 */
	public OneLoginResponse(Saml2Settings settings, HttpRequest request)
		throws XPathExpressionException, ParserConfigurationException, SAXException, IOException, SettingsException,
			   ValidationError {
		super(settings, request);
	}

	@Override
	public Document getSAMLResponseDocument() {
		return super.getSAMLResponseDocument();
	}
}
