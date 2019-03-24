package jtechlog.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String SECRET_PROPERTY_NAME = "security.jwt.secret";

    @Autowired
    private Environment environment;

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

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        String secret = environment.getProperty(SECRET_PROPERTY_NAME);
        JwtCookieStore jwtCookieStore = new JwtCookieStore(secret.getBytes());
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().authenticationEntryPoint(WebSecurityConfig::handleException)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(jwtCookieStore, authenticationManager()))
                .addFilterAfter(new JwtTokenAuthenticationFilter(jwtCookieStore), UsernamePasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, "/api/auth").permitAll()
                .antMatchers("/**").hasRole("USER")
                .anyRequest().authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user")
                .password("user")
                .authorities("ROLE_USER");
    }

}
