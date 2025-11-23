package com.isoplatform.api.auth.repository;

import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TestEntityManager entityManager;

    private String uniqueId() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    @Test
    void shouldFindUserByEmail() {
        // Given - Use unique email/username with UUID to avoid conflicts
        String id = uniqueId();
        String email = "email-test-" + id + "@example.com";
        String username = "emailuser-" + id;

        User user = User.builder()
                .email(email)
                .username(username)
                .password("encodedPassword")
                .name("Test User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId(email)
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        Optional<User> found = userRepository.findByEmail(email);

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo(email);
    }

    @Test
    void shouldFindUserByUsername() {
        // Given - Use unique email/username with UUID to avoid conflicts
        String id = uniqueId();
        String email = "username-test-" + id + "@example.com";
        String username = "usernameuser-" + id;

        User user = User.builder()
                .email(email)
                .username(username)
                .password("encodedPassword")
                .name("Test User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId(email)
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        Optional<User> found = userRepository.findByUsername(username);

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo(username);
    }

    @Test
    void shouldReturnTrueWhenEmailExists() {
        // Given - Use unique values
        String id = uniqueId();
        String email = "exists-" + id + "@example.com";
        String username = "existinguser-" + id;

        User user = User.builder()
                .email(email)
                .username(username)
                .password("encodedPassword")
                .name("Existing User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId(email)
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        boolean exists = userRepository.existsByEmail(email);

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void shouldReturnFalseWhenEmailDoesNotExist() {
        // Given - Use unique non-existent email
        String nonExistentEmail = "nonexistent-" + uniqueId() + "@example.com";

        // When
        boolean exists = userRepository.existsByEmail(nonExistentEmail);

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void shouldReturnTrueWhenUsernameExists() {
        // Given - Use unique values
        String id = uniqueId();
        String email = "user-" + id + "@example.com";
        String username = "existingusername-" + id;

        User user = User.builder()
                .email(email)
                .username(username)
                .password("encodedPassword")
                .name("Test User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId(email)
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        boolean exists = userRepository.existsByUsername(username);

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void shouldReturnFalseWhenUsernameDoesNotExist() {
        // Given - Use unique non-existent username
        String nonExistentUsername = "nonexistentusername-" + uniqueId();

        // When
        boolean exists = userRepository.existsByUsername(nonExistentUsername);

        // Then
        assertThat(exists).isFalse();
    }
}
