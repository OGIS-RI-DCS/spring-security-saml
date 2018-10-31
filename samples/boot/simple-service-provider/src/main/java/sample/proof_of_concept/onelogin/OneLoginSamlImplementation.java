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

import java.io.StringReader;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.time.Clock;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;

import org.springframework.security.saml.SamlException;
import org.springframework.security.saml.saml2.Saml2Object;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AudienceRestriction;
import org.springframework.security.saml.saml2.authentication.AuthenticationRequest;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.authentication.Conditions;
import org.springframework.security.saml.saml2.authentication.Issuer;
import org.springframework.security.saml.saml2.authentication.LogoutRequest;
import org.springframework.security.saml.saml2.authentication.LogoutResponse;
import org.springframework.security.saml.saml2.authentication.NameIdPrincipal;
import org.springframework.security.saml.saml2.authentication.Response;
import org.springframework.security.saml.saml2.authentication.Status;
import org.springframework.security.saml.saml2.authentication.StatusCode;
import org.springframework.security.saml.saml2.authentication.Subject;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmation;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationData;
import org.springframework.security.saml.saml2.authentication.SubjectConfirmationMethod;
import org.springframework.security.saml.saml2.key.KeyType;
import org.springframework.security.saml.saml2.key.SimpleKey;
import org.springframework.security.saml.saml2.metadata.Binding;
import org.springframework.security.saml.saml2.metadata.Endpoint;
import org.springframework.security.saml.saml2.metadata.IdentityProvider;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.metadata.ServiceProviderMetadata;
import org.springframework.security.saml.saml2.signature.Signature;
import org.springframework.security.saml.spi.SpringSecuritySaml;
import org.springframework.util.ReflectionUtils;

import com.onelogin.saml2.authn.AuthnRequest;
import com.onelogin.saml2.authn.SamlResponse;
import com.onelogin.saml2.http.HttpRequest;
import com.onelogin.saml2.settings.IdPMetadataParser;
import com.onelogin.saml2.settings.Metadata;
import com.onelogin.saml2.settings.Saml2Settings;
import com.onelogin.saml2.settings.SettingsBuilder;
import com.onelogin.saml2.util.Constants;
import com.onelogin.saml2.util.Util;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.joda.time.DateTime;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import static com.onelogin.saml2.settings.SettingsBuilder.IDP_ENTITYID_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.IDP_X509CERT_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.SECURITY_AUTHREQUEST_SIGNED;
import static com.onelogin.saml2.settings.SettingsBuilder.SECURITY_WANT_ASSERTIONS_SIGNED;
import static com.onelogin.saml2.settings.SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.SP_NAMEIDFORMAT_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.SP_PRIVATEKEY_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY;
import static com.onelogin.saml2.settings.SettingsBuilder.SP_X509CERT_PROPERTY_KEY;
import static java.util.Arrays.asList;
import static org.springframework.util.StringUtils.hasText;

public class OneLoginSamlImplementation extends SpringSecuritySaml<OneLoginSamlImplementation> {

	public OneLoginSamlImplementation(Clock time) {
		super(time);
	}

	@Override
	protected void bootstrap() {

	}

	@Override
	public long toMillis(Duration duration) {
		long now = System.currentTimeMillis();
		Date d = new Date(now);
		long millis = duration.getTimeInMillis(d);
		return Math.abs(millis - now);
	}

	@Override
	public Duration toDuration(long millis) {
		try {
			return DatatypeFactory.newInstance().newDuration(millis);
		} catch (DatatypeConfigurationException e) {
			throw new SamlException(e);
		}
	}

	@Override
	public String toXml(Saml2Object saml2Object) {
		String result = null;
		if (saml2Object instanceof AuthenticationRequest) {
			result = internalToXml((AuthenticationRequest) saml2Object);
		}
		else if (saml2Object instanceof Assertion) {
			result = internalToXml((Assertion) saml2Object);
		}
		else if (saml2Object instanceof ServiceProviderMetadata) {
			result = internalToXml((ServiceProviderMetadata) saml2Object);
		}
		else if (saml2Object instanceof Response) {
			result = internalToXml((Response) saml2Object);
		}
		else if (saml2Object instanceof LogoutRequest) {
			result = internalToXml((LogoutRequest) saml2Object);
		}
		else if (saml2Object instanceof LogoutResponse) {
			result = internalToXml((LogoutResponse) saml2Object);
		}
		if (result != null) {
			return result;
		}
		throw new SamlException("To xml transformation not supported for: " +
			saml2Object != null ?
			saml2Object.getClass().getName() :
			"null"
		);
	}

	private String internalToXml(LogoutResponse saml2Object) {
		throw new UnsupportedOperationException();
	}

	private String internalToXml(LogoutRequest saml2Object) {
		throw new UnsupportedOperationException();
	}

	private String internalToXml(Response saml2Object) {
		return null;
	}

	private String internalToXml(ServiceProviderMetadata metadata) {
		Saml2Settings settings = getSaml2Settings(
			metadata.getEntityId(),
			metadata.getServiceProvider().getAssertionConsumerService().get(0),
			metadata.getServiceProvider().getSingleLogoutService().get(0),
			metadata.getServiceProvider().getNameIds().get(0),
			metadata.getServiceProvider().getKeys().get(0),
			metadata.getServiceProvider().isAuthnRequestsSigned(),
			metadata.getServiceProvider().isWantAssertionsSigned(),
			null,
			null,
			null,
			null
		);
		Metadata m;
		try {
			m = new Metadata(settings);
			return m.getMetadataString();
		} catch (CertificateEncodingException e) {
			throw new SamlException(e);
		}
	}

	private Saml2Settings getSaml2Settings(String spEntityId,
										   Endpoint spAcsEndpoint,
										   Endpoint spSingleLogoutEndpoint,
										   NameId spNameId,
										   SimpleKey spKey,
										   boolean authnRequestsSigned,
										   boolean wantAssertionsSigned,
										   String idpEntityId,
										   Endpoint idpSSOEndpoint,
										   Endpoint idpSingleLogoutEndpoint,
										   String idpCertificate) {
		final Map<String, Object> data = new HashMap<>();
		if (hasText(spEntityId)) {
			data.put(SettingsBuilder.SP_ENTITYID_PROPERTY_KEY, spEntityId);
		}
		if (spAcsEndpoint != null) {
			data.put(SP_ASSERTION_CONSUMER_SERVICE_URL_PROPERTY_KEY, spAcsEndpoint.getLocation());
			data.put(SP_ASSERTION_CONSUMER_SERVICE_BINDING_PROPERTY_KEY, spAcsEndpoint.getBinding().toString());
		}
		if (spSingleLogoutEndpoint != null) {
			data.put(SP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, spSingleLogoutEndpoint.getLocation());
			data.put(SP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, spSingleLogoutEndpoint.getBinding().toString());
		}
		if (spNameId != null) {
			data.put(SP_NAMEIDFORMAT_PROPERTY_KEY, spNameId.toString());
		}
		if (spKey != null) {
			data.put(SP_X509CERT_PROPERTY_KEY, spKey.getCertificate());
			data.put(SP_PRIVATEKEY_PROPERTY_KEY, spKey.getPrivateKey());
		}
		data.put(SECURITY_AUTHREQUEST_SIGNED, authnRequestsSigned);
		data.put(SECURITY_WANT_ASSERTIONS_SIGNED, wantAssertionsSigned);

		if (hasText(idpEntityId)) {
			data.put(IDP_ENTITYID_PROPERTY_KEY, idpEntityId);
		}
		if (idpSSOEndpoint != null) {
			data.put(IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY, idpSSOEndpoint.getLocation());
			data.put(IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY, idpSSOEndpoint.getBinding().toString());
		}
		;
		if (idpSingleLogoutEndpoint != null) {
			data.put(IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY, idpSingleLogoutEndpoint.getLocation());
			data.put(IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY, idpSingleLogoutEndpoint.getBinding().toString());
		}
		if (hasText(idpCertificate)) {
			data.put(IDP_X509CERT_PROPERTY_KEY, idpCertificate);
		}

		final String keyPassphrase = spKey.getPassphrase();
		return new SettingsBuilder() {
			@Override
			protected PrivateKey loadPrivateKeyFromProp(String propertyKey) {
				try {
					String keyValue = (String) data.get(propertyKey);
					PEMParser pemParser = new PEMParser(new StringReader(keyValue));
					Object object = pemParser.readObject();
					PEMDecryptorProvider decProv =
						new JcePEMDecryptorProviderBuilder().build(keyPassphrase.toCharArray());
					JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
					KeyPair kp = null;
					if (object instanceof PEMEncryptedKeyPair) {
						kp = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
					}
					return kp.getPrivate();
				} catch (Exception e) {
					throw new SamlException(e);
				}
			}
		}.fromValues(data).build();
	}

	private String internalToXml(Assertion saml2Object) {
		return null;
	}

	private String internalToXml(AuthenticationRequest authnRequest) {
		Saml2Settings settings = getSaml2Settings(authnRequest);
		AuthnRequest request = new AuthnRequest(settings);
		return request.getAuthnRequestXml();
	}

	private Saml2Settings getSaml2Settings(AuthenticationRequest authnRequest) {
		return getSaml2Settings(
			authnRequest.getIssuer().getValue(),
			null,
			null,
			authnRequest.getNameIdPolicy().getFormat(),
			authnRequest.getSigningKey(),
			authnRequest.getSigningKey() != null,
			true,
			authnRequest.getDestinationEntityId(),
			authnRequest.getDestination(),
			null,
			null
		);
	}

	@Override
	public Saml2Object resolve(String xml, List<SimpleKey> verificationKeys, List<SimpleKey> localKeys) {
		if (xml.contains("Response") && xml.contains("SAML:2.0:assertion")) {
			Saml2Settings settings = getSaml2Settings(
				null,
				null,
				null,
				null,
				localKeys.isEmpty() ? null : localKeys.get(0),
				true,
				true,
				null,
				null,
				null,
				null
			);
			try {
				OneLoginResponse response = new OneLoginResponse(
					settings,
					new HttpRequest(
						"dummy URL",
						Collections.singletonMap("SAMLResponse", asList(Util.base64encoder(xml))),
						null
					)
				);

				String method = Util.query(
					response.getSAMLResponseDocument(),
					"/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation"
				).item(0).getAttributes().getNamedItem("Method").getTextContent();

				String recipient =
					Util.query(
						response.getSAMLResponseDocument(),
						"/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData"
					).item(0).getAttributes().getNamedItem("Recipient").getTextContent();

				Field field = SamlResponse.class.getDeclaredField("encrypted");
				field.setAccessible(true);
				Boolean encrypted =
					(Boolean) ReflectionUtils.getField(field, response);

				//throws on failure
				response.checkStatus();

				DateTime authInstant = DateTime.now();
				return new Response()
					.setIssueInstant(authInstant)
					.setStatus(
						new Status()
							.setCode(StatusCode.SUCCESS)
					)
					.setIssuer(
						response.getIssuers().isEmpty() ? null :
							new Issuer()
								.setValue(response.getIssuers().get(0))
								.setNameQualifier(response.getNameIdData().get("SPNameQualifier"))
					)
					.setAssertions(
						asList(
							new Assertion(encrypted != null ? encrypted.booleanValue() : false)
								.setId(response.getAssertionId())
								.setIssuer(response.getIssuers().isEmpty() ? "" : response.getIssuers().get(0))

								.setAuthenticationStatements(
									asList(
										new AuthenticationStatement()
											.setSessionIndex(response.getSessionIndex())
											.setSessionNotOnOrAfter(response.getSessionNotOnOrAfter())
											.setAuthInstant(authInstant)
									)
								)
								.setConditions(
									new Conditions()
										.addCriteria(
											new AudienceRestriction()
												.setAudiences(response.getAudiences())
										)
								)
								.setSubject(
									new Subject()
										.setConfirmations(
											asList(
												new SubjectConfirmation()
													.setConfirmationData(
														new SubjectConfirmationData()
															.setNotOnOrAfter(
																response.getAssertionNotOnOrAfter().get(0).toDateTime()
															)
															.setRecipient(recipient)

													)
													.setMethod(SubjectConfirmationMethod.fromUrn(method))
													.setFormat(NameId.fromUrn(response.getNameIdFormat()))

											)
										)
										.setPrincipal(
											new NameIdPrincipal()
												.setValue(response.getNameIdData().get("Value"))
												.setFormat(NameId.fromUrn(response.getNameIdFormat()))
												.setSpNameQualifier(response.getNameIdData().get("SPNameQualifier"))
										)
								)
						)

					)
					.setOriginalXML(response.getSAMLResponseXml())
					;
			} catch (Exception e) {
				throw new SamlException(e);
			}
		}
		else if (xml.contains("EntityDescriptor") && xml.contains("IDPSSODescriptor")) {
			try {
				Document xmlDocument = Util.parseXML(new InputSource(new StringReader(xml)));
				Map<String, Object> map = IdPMetadataParser.parseXML(
					xmlDocument,
					null,
					null,
					Constants.BINDING_HTTP_POST,
					Constants.BINDING_HTTP_REDIRECT
				);
				return new IdentityProviderMetadata()
					.setEntityId((String) map.get(IDP_ENTITYID_PROPERTY_KEY))
					.setProviders(
						asList(
							new IdentityProvider()
								.setSingleSignOnService(
									asList(
										new Endpoint()
											.setLocation((String) map.get(IDP_SINGLE_SIGN_ON_SERVICE_URL_PROPERTY_KEY))
											.setBinding(Binding.fromUrn((String) map.get(
												IDP_SINGLE_SIGN_ON_SERVICE_BINDING_PROPERTY_KEY)))
									)
								)
								.setSingleLogoutService(
									asList(
										new Endpoint()
											.setLocation((String) map.get(IDP_SINGLE_LOGOUT_SERVICE_URL_PROPERTY_KEY))
											.setBinding(Binding.fromUrn((String) map.get(
												IDP_SINGLE_LOGOUT_SERVICE_BINDING_PROPERTY_KEY)))
									)
								)
								.setKeys(
									asList(
										new SimpleKey(
											"idp key",
											null,
											(String) map.get(IDP_X509CERT_PROPERTY_KEY),
											null,
											KeyType.SIGNING
										)
									)
								)
								.setNameIds(
									asList(
										NameId.fromUrn((String) map.get(SP_NAMEIDFORMAT_PROPERTY_KEY))
									)
								)

						)
					);
			} catch (Exception e) {
				throw new SamlException(e);

			}
		}
		return null;
	}

	@Override
	public Saml2Object resolve(byte[] xml, List<SimpleKey> trustedKeys, List<SimpleKey> localKeys) {
		return resolve(new String(xml, StandardCharsets.UTF_8), trustedKeys, localKeys);
	}

	@Override
	public Signature validateSignature(Saml2Object saml2Object, List<SimpleKey> trustedKeys) {
		return null;
	}
}
