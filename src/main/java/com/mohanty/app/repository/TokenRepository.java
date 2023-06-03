/**
 * 
 */
package com.mohanty.app.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mohanty.app.entity.Token;

/**
 * @author 002L2N744
 *
 */
public interface TokenRepository extends JpaRepository<Token, Integer> {

	Optional<Token> findTokenByUserName(String userName);
}
