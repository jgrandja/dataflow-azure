/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.web;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import sample.config.ServicesConfig;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Joe Grandja
 */
abstract class AbstractFlowController {
	private final WebClient webClient;
	private final ServicesConfig servicesConfig;

	protected AbstractFlowController(WebClient webClient, ServicesConfig servicesConfig) {
		this.webClient = webClient;
		this.servicesConfig = servicesConfig;
	}

	protected ServiceCallResponse callService(String serviceId, String path,
												OAuth2AuthorizedClient authorizedClient) {

		ServicesConfig.ServiceConfig serviceConfig = this.servicesConfig.getConfig(serviceId);
		URI uri = UriComponentsBuilder.fromUriString(serviceConfig.getUri())
				.path(path)
				.build()
				.toUri();

		return this.webClient
				.get()
				.uri(uri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(ServiceCallResponse.class)
				.block();
	}

	protected ServiceCallResponse fromDataFlowWeb(OAuth2AuthenticationToken oauth2Authentication,
												  HttpServletRequest request,
												  ServiceCallResponse... serviceCallResponses) {

		OidcUser oidcUser = (OidcUser) oauth2Authentication.getPrincipal();

		ServiceCallResponse serviceCallResponse = new ServiceCallResponse();
		serviceCallResponse.setServiceName(ServicesConfig.DATA_FLOW_WEB);
		serviceCallResponse.setServiceUri(request.getRequestURL().toString());
		serviceCallResponse.setJti("(opaque to client)");
		serviceCallResponse.setSub(oidcUser.getSubject());
		serviceCallResponse.setAud(oidcUser.getAudience());
		serviceCallResponse.setAuthorities(oauth2Authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).sorted().collect(Collectors.toList()));
		if (serviceCallResponses != null) {
			serviceCallResponse.setServiceCallResponses(Arrays.asList(serviceCallResponses));
		}

		return serviceCallResponse;
	}
}