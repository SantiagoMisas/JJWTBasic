package com.jwt.JWTTraining;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class JwtTrainingApplication {

	public static final int EXPIRATION_IN_MINUTES = 1;
	public static final String SECRET_KEY = "ENCRIPTAR LA CLAVE ALAFANUMERICA";

	public static void main(String[] args) {
		SpringApplication.run(JwtTrainingApplication.class, args);

		Map<String, Object> extraClaims = buildExtraClaims();

		String jwt = buildJws(extraClaims);

		System.out.println(jwt);

		try{
			//Thread.sleep(60*1000);
			Claims payload=verifyJws(jwt);
			System.out.println(payload.getSubject());
		}catch (JwtException e){
			System.out.println(e.getMessage());
		}
	}

	private static Claims verifyJws(String jwt) {
		return Jwts.parser()
				.verifyWith(generateKey())
				.build()
				.parseSignedClaims(jwt)
				.getPayload();
	}

	private static String buildJws(Map<String, Object> extraClaims) {
		Date issueAt=new Date(System.currentTimeMillis());
		Date expiration=new Date(issueAt.getTime()+(EXPIRATION_IN_MINUTES *60*1000));

		String jwt= Jwts.builder()

				.header()
				.type("JWT")
				.and()

				.subject("SMP")
				.expiration(expiration)
				.issuedAt(issueAt)
				.claims(extraClaims)
				.signWith(generateKey(), Jwts.SIG.HS256)

				.compact();
		return jwt;
	}

	private static Map<String, Object> buildExtraClaims() {
		Map<String, Object> extraClaims=new HashMap<>();
		extraClaims.put("name", "santiago");
		return extraClaims;
	}

	private static SecretKey generateKey() {
		return Keys.hmacShaKeyFor(SECRET_KEY.getBytes());

	}

}
