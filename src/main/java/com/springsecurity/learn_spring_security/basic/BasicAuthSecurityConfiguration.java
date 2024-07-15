package com.springsecurity.learn_spring_security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
//@EnableMethodSecurity(jsr250Enabled = true)
public class BasicAuthSecurityConfiguration {

    /**
     * Security configuration
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                auth -> {
                    auth
                            //Allows requests to a specific resource with a specific role
                            .requestMatchers("/hello-world").hasRole("ADMIN")
                            .anyRequest().authenticated();
                });

        http.sessionManagement(
                session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.httpBasic(Customizer.withDefaults());

        http.csrf(AbstractHttpConfigurer::disable);

        //Enables frames to see H2 console
        http.headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
        );

        return http.build();
    }

//    /**
//     * Creates in memory users
//     * @return
//     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        var user = User.withUsername("spring")
//                .password("{noop}security")
//                .roles(Roles.USER.toString())
//                .build();
//
//        var admin = User.withUsername("admin")
//                .password("{noop}security")
//                .roles(Roles.ADMIN.toString())
//                .build();
//
//        return new InMemoryUserDetailsManager(user, admin);
//    }

    /**
     * Creates the schema (users and authorities tables) at the startup of the application
     * @return
     */
    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }

    /**
     * Creates and stores users in memory database
     * @param dataSource
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        var user = User.withUsername("spring")
                //.password("{noop}security")
                .password("security")
                .passwordEncoder(password -> passwordEncoder().encode(password))
                .roles(Roles.USER.toString())
                .build();

        var admin = User.withUsername("admin")
                //.password("{noop}security")
                .password("admin")
                .passwordEncoder(password -> passwordEncoder().encode(password))
                .roles(Roles.ADMIN.toString(), Roles.USER.toString())
                .build();

        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    /**
     * Hashes passwords
     * @return
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
