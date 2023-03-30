package com.springboot.admin.helper;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import static com.springboot.admin.constant.JWTUtil.EXPIRE_ACCESS_TOKEN;
import static com.springboot.admin.constant.JWTUtil.EXPIRE_REFRESH_TOKEN;

import static com.springboot.admin.constant.JWTUtil.ISSUER;
import static com.springboot.admin.constant.JWTUtil.SECRET;
import static com.springboot.admin.constant.JWTUtil.BEARER_PREFIX;

@Component
public class JWTHelper {
	
	Algorithm algorithm = Algorithm.HMAC256(SECRET);

	public String generateAccessToken(String email, List<String> roles) {
		return JWT.create()
				  .withSubject(email)
				  .withExpiresAt(new Date(System.currentTimeMillis()+ EXPIRE_ACCESS_TOKEN))
				  .withIssuer(ISSUER)
				  .withClaim("roles", roles)
				  .sign(algorithm);
	}
	
	public String generateRefreshToken(String email) {
		return JWT.create()
				  .withSubject(email)
				  .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRE_REFRESH_TOKEN))
				  .withIssuer(ISSUER)
				  .sign(algorithm);
	}
	
	public String extractTokenFromHeaderIfExists(String authorizationHeader) {
		if(authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
			return authorizationHeader.substring(BEARER_PREFIX.length());
		}
		return null;
	}
	
	public Map<String, String> getTokensMap(String jwtAccessToken, String jwtRefreshToken){
		Map<String, String> idTokens = new HashMap<>();
		idTokens.put("accessToken", jwtAccessToken);
		idTokens.put("refreshToken", jwtRefreshToken);
		return idTokens;
	}
}
