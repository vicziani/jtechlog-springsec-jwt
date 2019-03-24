package jtechlog.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class JwtCookieStore {

    private static final String COOKIE_NAME = "token";

    private static final int EXPIRATION =  30 * 60 * 1000;

    private byte[] secret;

    public JwtCookieStore(byte[] secret) {
        this.secret = secret;
    }

    public void storeToken(HttpServletResponse response, Authentication auth) {
        String token = generateToken(auth);
        storeTokenInCookie(response, token);
    }

    private void storeTokenInCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setMaxAge(EXPIRATION);
        cookie.setPath("/api");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    private String generateToken(Authentication auth) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                    .setSubject(auth.getName())
                    .claim("authorities", auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                    .setIssuedAt(new Date(now))
                    .setExpiration(new Date(now + EXPIRATION))
                    .signWith(SignatureAlgorithm.HS512, secret)
                    .compact();
    }

    public Optional<Authentication> retrieveToken(HttpServletRequest request) {
        Optional<Cookie> cookie = findCookie(request);
        if (cookie.isEmpty()) {
            return Optional.empty();
        }
        String token = cookie.get().getValue();

        Claims claims = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();

        String username = claims.getSubject();
        if (username != null) {
            @SuppressWarnings("unchecked")
            List<String> authorities = (List<String>) claims.get("authorities");

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    username, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

            return Optional.of(auth);
        }
        return Optional.empty();
    }

    private Optional<Cookie> findCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(COOKIE_NAME))
                .findAny();
    }


}
