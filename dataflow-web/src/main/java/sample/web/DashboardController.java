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

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;
import sample.config.ServicesConfig;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * @author Joe Grandja
 */
@Controller
@RequestMapping("/dashboard")
public class DashboardController extends AbstractFlowController {

	public DashboardController(WebClient webClient, ServicesConfig servicesConfig) {
		super(webClient, servicesConfig);
	}

	@GetMapping
	public String dashboard(@RegisteredOAuth2AuthorizedClient("dataflow-web") OAuth2AuthorizedClient dataFlowWeb,
							OAuth2AuthenticationToken oauth2Authentication,
							HttpServletRequest request,
							Map<String, Object> model) {

		ServiceCallResponse viewResponse = callService(ServicesConfig.DATA_FLOW_SERVER, "/view", dataFlowWeb);
		model.put("dataFlowServerCall", fromDataFlowWeb(oauth2Authentication, request, viewResponse));
		return "index";
	}
}