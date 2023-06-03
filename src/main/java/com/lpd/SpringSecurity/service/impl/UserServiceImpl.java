package com.lpd.SpringSecurity.service.impl;

import com.lpd.SpringSecurity.domain.Role;
import com.lpd.SpringSecurity.domain.User;
import com.lpd.SpringSecurity.repository.RoleRepository;
import com.lpd.SpringSecurity.repository.UserRepository;
import com.lpd.SpringSecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
/*
* 1/@RequiredArgsConstructor là hàm khởi tạo đối số bắt buộc (Dependency Injection).
* Nó sẽ đưa đối số userRepository, roleRepository vào hàm khởi tạo đó.
* Vì các biến trên là biến final nên phải được khởi tạo trong Constructor.
* 2/Từ khóa final:
* Từ khóa final trong Java được sử dụng để hạn chế thao tác của người dùng.
* Các trường hợp sử dụng:
* - Biến final: khi một biến được khai báo với từ khoá final, nó chỉ chứa một giá trị duy nhất trong toàn bộ chương trình (hay dễ hiểu hơn gọi là biến hằng).
* - Phương thức final: khi một phương thức được khai báo với từ khoá final, các class con kế thừa sẽ không thể ghi đè (override) phương thức này.
* - Lớp final: khi từ khoá final sử dụng cho một lớp, lớp này sẽ không thể được kế thừa.
* - Biến static final trống: Một biến final mà không được khởi tạo tại thời điểm khai báo được gọi là biến final trống.
* Từ khóa final có thể được áp dụng với các biến, một biến final mà không có giá trị nào được gọi là biến final trống hoặc biến final không được khởi tạo.
* Nó chỉ có thể được khởi tạo trong constructor. Biến final trống cũng có thể là static mà sẽ chỉ được khởi tạo trong khối static.
* 3/@Transactional sẽ rollback lại các thao tác trước đó khi có exception RuntimeException và Error khi thêm/sửa dữ liệu.
* 4/@Slf4j để xem những gì đang diễn ra trong log
* 5/Một class đại diện cho String authority là SimpleGrantedAuthority và chỉ cần đưa roleName vào.
* Vì nó extends GrantedAuthority nên vẫn có thể là kiểu GrantedAuthority
* */

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found in the database: {}", username);
        }

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>(); //Tạo bộ sưu tập của SimpleGrantedAuthority
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName()))); //Đưa các role của user vào Collection

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
        //Trả về user của spring security đang mong đợi, nó sẽ dùng thông tin user này để so sánh hoặc làm mọi thứ.
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new user {} to the database", user.getName());

        //Mã hóa mật khẩu của User và đặt làm mật khẩu của User
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role {} to the database", role.getName());
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role {} to user {}", roleName, username);
        User user = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user {}", username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Fetching all user");
        return userRepository.findAll();
    }
}
