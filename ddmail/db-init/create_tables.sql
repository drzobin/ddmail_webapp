--CREATE DATABASE mail;
--CREATE USER 'mail'@'localhost' IDENTIFIED BY 'password';
--GRANT ALL PRIVILEGES ON mail.* TO 'mail'@'localhost';
--FLUSH PRIVILEGES;

--USE mail;

CREATE TABLE IF NOT EXISTS accounts (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	account varchar(100) NOT NULL UNIQUE,
	payment_token varchar(12) NOT NULL UNIQUE,
	funds_in_sek int NOT NULL DEFAULT 0,
	is_enabled boolean NOT NULL DEFAULT  0,
	is_gratis boolean NOT NULL DEFAULT  0,
	total_storage_space_g int NOT NULL DEFAULT 1,
	created DATETIME NOT NULL,
	last_time_disabled DATETIME DEFAULT NULL,
	PRIMARY KEY (id) );

CREATE TABLE IF NOT EXISTS users (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	account_id int NOT NULL,
	user varchar(100) UNIQUE NOT NULL,
	password_hash varchar(200) NOT NULL,
	password_key_hash varchar(200) NOT NULL,
	FOREIGN KEY (account_id)
    REFERENCES accounts(id)
    ON DELETE RESTRICT
	ON UPDATE CASCADE,
	PRIMARY KEY (id) );


CREATE TABLE IF NOT EXISTS authenticateds (
    id INT AUTO_INCREMENT,
    cookie VARCHAR(255) NOT NULL,
    user_id int NOT NULL,
    valid_to DATETIME,
	FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE RESTRICT
	ON UPDATE CASCADE,
	PRIMARY KEY (id) );

CREATE TABLE IF NOT EXISTS account_domains (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	account_id int NOT NULL,
	domain varchar(191) NOT NULL UNIQUE,
	FOREIGN KEY (account_id)
    REFERENCES accounts(id)
    ON DELETE RESTRICT
	ON UPDATE CASCADE,
	PRIMARY KEY (id) );

CREATE TABLE IF NOT EXISTS global_domains (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	domain varchar(191) NOT NULL UNIQUE,
	is_enabled boolean NOT NULL DEFAULT 1,
	PRIMARY KEY (id) );

CREATE TABLE IF NOT EXISTS openpgp_public_keys (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	account_id int NOT NULL,
	fingerprint varchar(40) UNIQUE NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
        ON DELETE RESTRICT
	ON UPDATE CASCADE,
    PRIMARY KEY (id) );

CREATE TABLE IF NOT EXISTS emails (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	account_id int NOT NULL,
	account_domain_id int NULL,
	global_domain_id int NULL,
	openpgp_public_key_id int NULL,
	email varchar(191) NOT NULL UNIQUE,
	password_hash varchar(2096) NOT NULL,
	storage_space_mb int NOT NULL DEFAULT 0,
	FOREIGN KEY (account_id) REFERENCES accounts(id)
		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	FOREIGN KEY (account_domain_id) REFERENCES account_domains(id)
    		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	FOREIGN KEY (global_domain_id) REFERENCES global_domains(id)
    		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	FOREIGN KEY (openpgp_public_key_id) REFERENCES openpgp_public_keys(id)
    		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	PRIMARY KEY (id) );

CREATE TABLE IF NOT EXISTS aliases (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	account_id int NOT NULL,
	src_account_domain_id int NULL,
	src_global_domain_id int NULL,
	src_email varchar(191) NOT NULL UNIQUE,
	dst_email_id int NOT NULL,
	FOREIGN KEY (account_id) REFERENCES accounts(id)
    		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	FOREIGN KEY (src_account_domain_id) REFERENCES account_domains(id)
    		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	FOREIGN KEY (src_global_domain_id) REFERENCES global_domains(id)
    		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	FOREIGN KEY (dst_email_id) REFERENCES emails(id)
    		ON DELETE RESTRICT
		ON UPDATE CASCADE,
	PRIMARY KEY (id) );

CREATE TABLE IF NOT EXISTS transports (
	id int NOT NULL UNIQUE AUTO_INCREMENT,
	domain varchar(200) NOT NULL,
	transport varchar(200) NOT NULL,
	PRIMARY KEY (id) );

