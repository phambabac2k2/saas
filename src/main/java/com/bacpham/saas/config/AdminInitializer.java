package com.bacpham.saas.config;

import com.bacpham.saas.entities.User;
import com.bacpham.saas.entities.UserRole;
import com.bacpham.saas.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class AdminInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Value("${spring.admin.username}")
    private String adminUsername;

    @Value("${spring.admin.password}")
    private String adminPassword;

    @Value("${spring.admin.email}")
    private String adminEmail;
    @Override
    public void run(String... args) {
        if (userRepository.findByRole(UserRole.ROLE_PLATFORM_ADMIN).isEmpty()) {
            User admin = User.builder()
                    .username(adminUsername)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .firstName("Platform")
                    .lastName("Admin")
                    .role(UserRole.ROLE_PLATFORM_ADMIN)
                    .tenant(null)
                    .enabled(true)
                    .createdBy("SYSTEM")
                    .createdAt(LocalDateTime.now())
                    .build();

            userRepository.save(admin);
        }
    }
}