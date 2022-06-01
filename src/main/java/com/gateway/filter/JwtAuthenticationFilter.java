package com.gateway.filter;

import java.util.List;
import java.util.function.Predicate;

import org.apache.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

import com.gateway.exception.JwtTokenMalformedException;
import com.gateway.exception.JwtTokenMissingException;

import io.jsonwebtoken.Claims;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<Object> {

	@Autowired
	private JwtUtil jwtUtil;
	
	@Value("${noauth.endpoints}")
	private String[] noAuthEndpoints;

	@Override
	public GatewayFilter apply(Object config) {
		return (exchange, chain) -> {
			ServerHttpRequest request = (ServerHttpRequest) exchange.getRequest();

			final List<String> apiEndpoints = List.of(noAuthEndpoints);

			Predicate<ServerHttpRequest> isApiSecured = r -> apiEndpoints.stream()
					.noneMatch(uri -> r.getURI().getPath().contains(uri));
			if (isApiSecured.test(request)) {
				if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
					ServerHttpResponse response = exchange.getResponse();
					response.setStatusCode(HttpStatus.UNAUTHORIZED);

					return response.setComplete();
				}

				final String token = request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0);

				try {
					jwtUtil.validateToken(token);
				} catch (JwtTokenMalformedException | JwtTokenMissingException e) {
					ServerHttpResponse response = exchange.getResponse();
					response.setStatusCode(HttpStatus.BAD_REQUEST);

					return response.setComplete();
				}

				Claims claims = jwtUtil.getClaims(token);
				exchange.getRequest().mutate().header("id", String.valueOf(claims.get("id"))).build();
			}

			return chain.filter(exchange);
		};
	}
}