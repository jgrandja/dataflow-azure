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
package sample;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

/**
 * @author Joe Grandja
 */
@SpringBootApplication
public class DataFlowShellApplication {
	private static final Authentication DEFAULT_PRINCIPAL = createAuthentication("dataflow-shell-principal");

	public static void main(String[] args) {
		SpringApplication.run(DataFlowShellApplication.class, args);
	}

	@Bean
	CommandLineRunner requestUsingRestTemplate(RestTemplate restTemplate) {
		return args -> {
			URI url = URI.create("http://localhost:9000/dataflow-api/view");
			RequestEntity<Void> request = RequestEntity.get(url).build();
			ResponseEntity<String> response = restTemplate.exchange(request, String.class);
			System.out.println(response.getBody());
		};
	}

	@Bean
	RestTemplate restTemplate(ClientHttpRequestInterceptor bearerTokenResolvingInterceptor) {
		RestTemplate restTemplate = new RestTemplate();
		restTemplate.getInterceptors().add(bearerTokenResolvingInterceptor);
		return restTemplate;
	}

	@Bean
	ClientHttpRequestInterceptor bearerTokenResolvingInterceptor(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
		OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("dataflow-shell")
				.principal(DEFAULT_PRINCIPAL)
				.attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "user1@springsec.onmicrosoft.com")
				.attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "Password7799")
				.build();
		OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest).block();

		return (request, body, execution) -> {
			request.getHeaders().setBearerAuth(authorizedClient.getAccessToken().getTokenValue());
			return execution.execute(request, body);
		};
	}

	@Bean
	CommandLineRunner requestUsingWebClient(WebClient webClient) {
		return args -> {
			String body = webClient.get()
					.uri("http://localhost:9000/dataflow-api/view")
					.attributes(clientRegistrationId("dataflow-shell"))
					.retrieve()
					.bodyToMono(String.class)
					.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(DEFAULT_PRINCIPAL))
					.block();
			System.out.println(body);
		};
	}

	@Bean
	WebClient webClient(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
		ServerOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
				new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		return WebClient.builder()
				.filter(oauth2Client)
				.build();
	}

	@Bean
	ReactiveOAuth2AuthorizedClientManager authorizedClientManager(ReactiveClientRegistrationRepository clientRegistrationRepository,
																  ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
				ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
						.password()
						.refreshToken()
						.build();
		AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager =
				new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
						clientRegistrationRepository, authorizedClientService);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		// Set custom contextAttributesMapper
		authorizedClientManager.setContextAttributesMapper(authorizeRequest -> {
			Map<String, Object> contextAttributes = new HashMap<>();
			contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, "user1@springsec.onmicrosoft.com");
			contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, "Password7799");
			return Mono.just(contextAttributes);
		});

		return authorizedClientManager;
	}

	private static Authentication createAuthentication(final String principalName) {
		return new AbstractAuthenticationToken(null) {
			@Override
			public Object getCredentials() {
				return "";
			}

			@Override
			public Object getPrincipal() {
				return principalName;
			}
		};
	}
}