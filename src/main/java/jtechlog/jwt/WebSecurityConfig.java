package jtechlog.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(SecurityProperties.class)
public class WebSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    private static void handleException(HttpServletRequest req, HttpServletResponse rsp, AuthenticationException e)
            throws IOException {
        PrintWriter writer = rsp.getWriter();
        writer.println(new ObjectMapper().writeValueAsString(new AuthorizationResponse("error", "Unauthorized")));
        rsp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(authProvider);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, SecurityProperties securityProperties) throws Exception {
        String secret = securityProperties.getJwtSecret();
        JwtCookieStore jwtCookieStore = new JwtCookieStore(secret.getBytes());
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(configurer ->
                        configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 1
                .exceptionHandling(configurer ->
                        configurer.authenticationEntryPoint(WebSecurityConfig::handleException)) // 2
                .addFilter(
                        new JwtUsernameAndPasswordAuthenticationFilter(jwtCookieStore, authenticationManager())) // 3
                .addFilterAfter(
                        new JwtTokenAuthenticationFilter(jwtCookieStore), UsernamePasswordAuthenticationFilter.class) // 4
                .authorizeHttpRequests(auth ->
                        auth
                                .anyRequest().authenticated()
                ) // 5
        ;
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                new User("user", "user", List.of(new SimpleGrantedAuthority("ROLE_USER"))));
    }

}
