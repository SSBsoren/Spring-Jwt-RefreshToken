package com.sagen.demosecurity.services;

import com.sagen.demosecurity.exception.TokenRefreshException;
import com.sagen.demosecurity.models.RefreshToken;
import com.sagen.demosecurity.respository.RefreshTokenRepository;
import com.sagen.demosecurity.respository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Value("${sagen.jwtRefreshExpirationMs}")
    public Long refreshTokenDurationMs;

    @Autowired
    UserRepository userRepository;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    public RefreshToken createRefreshToken(Long id) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userRepository.findById(id).get());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        refreshToken = refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    public Optional<RefreshToken> findByToken(String reqRefreshToken) {
        return refreshTokenRepository.findByToken(reqRefreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken refreshToken) {
        if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenRefreshException(refreshToken.getToken(), "Refresh token was expired. Please make a new sign in request");

        }
        return refreshToken;
    }
}
