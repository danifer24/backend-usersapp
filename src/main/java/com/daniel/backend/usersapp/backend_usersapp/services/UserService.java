package com.daniel.backend.usersapp.backend_usersapp.services;

import java.util.List;
import java.util.Optional;

import com.daniel.backend.usersapp.backend_usersapp.models.entities.User;

public interface UserService {

    List<User> findAll();

    Optional<User> findById(Long id);

    User save(User user);

    void remove(Long id);
}
