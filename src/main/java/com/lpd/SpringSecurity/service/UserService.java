package com.lpd.SpringSecurity.service;

import com.lpd.SpringSecurity.domain.Role;
import com.lpd.SpringSecurity.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers(); //Trong thực tế không lấy hết tất cả 50000 user
}
