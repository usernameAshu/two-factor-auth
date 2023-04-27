package com.mohanty.app.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.mohanty.app.entity.Authorities;

@Repository
public interface AuthoritiesRepository extends JpaRepository<Authorities, String> {

}
