package com.lpd.SpringSecurity.repository;

import com.lpd.SpringSecurity.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.yaml.snakeyaml.events.Event;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
