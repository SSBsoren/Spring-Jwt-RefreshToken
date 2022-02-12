package com.sagen.demosecurity.controllers;

import com.sagen.demosecurity.config.AbstractResponse;
import com.sagen.demosecurity.config.StatusResp;
import com.sagen.demosecurity.exception.TokenRefreshException;
import com.sagen.demosecurity.jwtrequest.LoginReq;
import com.sagen.demosecurity.jwtrequest.RefreshTokenRequest;
import com.sagen.demosecurity.jwtrequest.SignupRequest;
import com.sagen.demosecurity.jwtresponse.SignupResponse;
import com.sagen.demosecurity.jwtresponse.TokenRefreshResponse;
import com.sagen.demosecurity.models.ERole;
import com.sagen.demosecurity.models.RefreshToken;
import com.sagen.demosecurity.models.Role;
import com.sagen.demosecurity.models.User;
import com.sagen.demosecurity.respository.RoleRepository;
import com.sagen.demosecurity.respository.UserRepository;
import com.sagen.demosecurity.services.RefreshTokenService;
import com.sagen.demosecurity.services.impl.UserDetailsImpl;
import com.sagen.demosecurity.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


@RestController
@RequestMapping(value = "/api")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;


    @PostMapping("/signup")
    public ResponseEntity<? extends AbstractResponse> registerUser(@RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new StatusResp("Error : Username is already taken!", "failed"));
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new StatusResp("Error : Email is already in use!", "failed"));
        }

        User user = new User(signupRequest.getUsername(), encoder.encode(signupRequest.getPassword()), signupRequest.getEmail());

        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();


        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error : Role is not found"));
            roles.add(userRole);

        } else {
            strRoles.forEach(role -> {

                if (role.equalsIgnoreCase("admin")) {
                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(adminRole);
                } else {
                    Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                    roles.add(userRole);
                }
            });
        }
        user.setRoles(roles);
        userRepository.save(user);
        return new ResponseEntity<>(new StatusResp("User registered successfully", "success"), HttpStatus.OK);
    }


    @PostMapping("/login")
    public ResponseEntity<? extends AbstractResponse> authenticateUser(@RequestBody LoginReq loginReq) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(loginReq.getUsername(), loginReq.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item ->
                        item.getAuthority())
                .collect(Collectors.toList());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        return new ResponseEntity<>(new SignupResponse(
                jwt,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles),
                HttpStatus.OK);
    }


    @

            PostMapping("/refreshToken")
    public ResponseEntity<?> refreshToke(@RequestBody RefreshTokenRequest request) {
        String reqRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(reqRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String token = jwtUtils.generateTokenFromUsername(user.getUsername());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, reqRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(reqRefreshToken, "Refresh token is not in database!"));
    }
}
