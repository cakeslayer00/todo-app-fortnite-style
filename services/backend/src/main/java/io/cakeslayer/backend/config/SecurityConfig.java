package io.cakeslayer.backend.config;

import io.cakeslayer.backend.entity.RefreshToken;
import io.cakeslayer.backend.filter.JwtAuthenticationFilter;
import io.cakeslayer.backend.repository.RefreshTokenRepository;
import io.cakeslayer.backend.repository.UserRepository;
import io.cakeslayer.backend.security.jwt.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.security.config.Customizer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.time.Instant;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String USER_NOT_FOUND_MESSAGE = "User not found with username: %s";

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   UserRepository userRepository,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   RefreshTokenRepository refreshTokenRepository,
                                                   JwtService jwtService) {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .userDetailsService(userDetailsService(userRepository))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logoutConfigurer -> {
                    logoutConfigurer
                            .addLogoutHandler(onLogoutRefreshTokenRevokeHandler(refreshTokenRepository, jwtService));
                })
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    private static LogoutHandler onLogoutRefreshTokenRevokeHandler(
            RefreshTokenRepository refreshTokenRepository,
            JwtService jwtService) {
        return (request, _, _) -> {
            String token;

            String authorization = request.getHeader("Authorization");
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                return;
            }
            token = authorization.substring("Bearer ".length());

            String username = jwtService.extractSubject(token);

            List<RefreshToken> tokens = refreshTokenRepository.findAllByUser_Username(username);
            tokens.forEach(rt -> rt.setRevokedAt(Instant.now()));
            refreshTokenRepository.saveAll(tokens);
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) {
        return config.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(USER_NOT_FOUND_MESSAGE.formatted(username)));
    }
}