package com.mohanty.app.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name ="token")
@Getter
@Setter
public class Token {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name = "id")
	private int tokenId ;
	
	@Column(name = "username")
	private String userName ;
	
	@Column(name = "auth_token")
	private String authToken ;
}
