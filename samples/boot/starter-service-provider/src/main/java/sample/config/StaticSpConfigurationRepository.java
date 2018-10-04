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

import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml.key.KeyType;
import org.springframework.security.saml.key.SimpleKey;
import org.springframework.security.saml.provider.config.NetworkConfiguration;
import org.springframework.security.saml.provider.config.SamlConfigurationRepository;
import org.springframework.security.saml.provider.registration.SamlServerConfiguration;
import org.springframework.security.saml.provider.registration.ExternalIdentityProviderConfiguration;
import org.springframework.security.saml.provider.registration.HostedServiceProviderConfiguration;
import org.springframework.security.saml.saml2.metadata.NameId;
import org.springframework.security.saml.saml2.signature.AlgorithmMethod;
import org.springframework.security.saml.saml2.signature.DigestMethod;

import static java.util.Arrays.asList;

public class StaticSpConfigurationRepository implements SamlConfigurationRepository<HttpServletRequest> {
	@Override
	public SamlServerConfiguration getServerConfiguration(HttpServletRequest request) {
		return getDefaultServerConfiguration();
	}

	@Override
	public SamlServerConfiguration getDefaultServerConfiguration() {
		return new SamlServerConfiguration(
			getServiceProvider(),
			null,
			new NetworkConfiguration(8000, 4000)
		);
	}

	private HostedServiceProviderConfiguration getServiceProvider() {
		return new HostedServiceProviderConfiguration(
			"/saml/sp",
			null,
			"sample-sp",
			null,
			true,
			null,
			getSamlKeys(),
			AlgorithmMethod.RSA_SHA256,
			DigestMethod.SHA256,
			asList(NameId.PERSISTENT, NameId.EMAIL),
			true,
			asList(getRemoteIdp()),
			true,
			true
		);
	}

	private ExternalIdentityProviderConfiguration getRemoteIdp() {
		return new ExternalIdentityProviderConfiguration(
			"simplesamlphp",
			"http://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php",
			"Simple SAML PHP IDP",
			true,
			false,
			NameId.EMAIL,
			0
		);
	}

	private List<SimpleKey> getSamlKeys() {
		SimpleKey signing = new SimpleKey(
			"sp-key",
			"-----BEGIN RSA PRIVATE KEY-----\n" +
				"Proc-Type: 4,ENCRYPTED\n" +
				"DEK-Info: DES-EDE3-CBC,7C8510E4CED17A9F\n" +
				"\n" +
				"SRYezKuY+AgM+gdiklVDBQ1ljeCFKnW3c5BM9sEyEOfkQm0zZx6fLr0afup0ToE4\n" +
				"iJGLxKw8swAnUAIjYda9wxqIEBb9mILyuRPevyfzmio2lE9KnARDEYRBqbwD9Lpd\n" +
				"vwZKNGHHJbZAgcUNfhXiYakmx0cUyp8HeO3Vqa/0XMiI/HAdlJ/ruYeT4e2DSrz9\n" +
				"ORZA2S5OvNpRQeCVf26l6ODKXnkDL0t5fDVY4lAhaiyhZtoT0sADlPIERBw73kHm\n" +
				"fGCTniY9qT0DT+R5Rqukk42mN2ij/cAr+kdV5colBi1fuN6d9gawCiH4zSb3LzHQ\n" +
				"9ccSlz6iQV1Ty2cRuTkB3zWC6Oy4q0BRlXnVRFOnOfYJztO6c2hD3Q9NxkDAbcgR\n" +
				"YWJWHpd0/HI8GyBpOG7hAS1l6aoleH30QCDOo7N2rFrTAaPC6g84oZOFSqkqvx4R\n" +
				"KTbWRwgJsqVxM6GqV6H9x1LNn2CpBizdGnp8VvnIiYcEvItMJbT1C1yeIUPoDDU2\n" +
				"Ct0Jofw/dquXStHWftPFjpIqB+5Ou//HQ2VNzjbyThNWVGtjnEKwSiHacQLS1sB3\n" +
				"iqFtSN/VCpdOcRujEBba+x5vlc8XCV1qr6x1PbvfPZVjyFdSM6JQidr0uEeDGDW3\n" +
				"TuYC1YgURN8zh0QF2lJIMX3xgbhr8HHNXv60ulcjeqYmna6VCS8AKJQgRTr4DGWt\n" +
				"Afv9BFV943Yp3nHwPC7nYC4FvMxOn4qW4KrHRJl57zcY6VDL4J030CfmvLjqUbuT\n" +
				"LYiQp/YgFlmoE4bcGuCiaRfUJZCwooPK2dQMoIvMZeVl9ExUGdXVMg==\n" +
				"-----END RSA PRIVATE KEY-----",
			"-----BEGIN CERTIFICATE-----\n" +
				"MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
				"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
				"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
				"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
				"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
				"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
				"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
				"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
				"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
				"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
				"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
				"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
				"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B\n" +
				"-----END CERTIFICATE-----",
			"sppassword",
			KeyType.SIGNING
		);
		SimpleKey encryption = new SimpleKey(
			"sp-encryption",
			signing.getPrivateKey(),
			signing.getCertificate(),
			signing.getPassphrase(),
			KeyType.ENCRYPTION
		);
		return asList(signing, encryption);
	}


}
