package com.isoplatform.api.auth.repository;

import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    void shouldFindUserByEmail() {
        // Given
        User user = User.builder()
                .email("test@example.com")
                .username("testuser")
                .password("encodedPassword")
                .name("Test User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId("test@example.com")
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        Optional<User> found = userRepository.findByEmail("test@example.com");

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void shouldFindUserByUsername() {
        // Given
        User user = User.builder()
                .email("test@example.com")
                .username("testuser")
                .password("encodedPassword")
                .name("Test User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId("test@example.com")
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        Optional<User> found = userRepository.findByUsername("testuser");

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getUsername()).isEqualTo("testuser");
    }

    @Test
    void shouldReturnTrueWhenEmailExists() {
        // Given
        User user = User.builder()
                .email("exists@example.com")
                .username("existinguser")
                .password("encodedPassword")
                .name("Existing User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId("exists@example.com")
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        boolean exists = userRepository.existsByEmail("exists@example.com");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void shouldReturnFalseWhenEmailDoesNotExist() {
        // Given
        // No user persisted

        // When
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    void shouldReturnTrueWhenUsernameExists() {
        // Given
        User user = User.builder()
                .email("user@example.com")
                .username("existingusername")
                .password("encodedPassword")
                .name("Test User")
                .role(Role.USER)
                .provider("LOCAL")
                .providerId("user@example.com")
                .company("SELF")
                .isActive(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        entityManager.persist(user);
        entityManager.flush();

        // When
        boolean exists = userRepository.existsByUsername("existingusername");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    void shouldReturnFalseWhenUsernameDoesNotExist() {
        // Given
        // No user persisted

        // When
        boolean exists = userRepository.existsByUsername("nonexistentusername");

        // Then
        assertThat(exists).isFalse();
    }
}
