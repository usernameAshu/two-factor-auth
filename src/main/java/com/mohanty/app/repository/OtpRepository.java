package com.mohanty.app.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mohanty.app.entity.Otp;

public interface OtpRepository extends JpaRepository<Otp, Integer> {
	
	Optional<Otp> findOtpByUsername(String username);
}
