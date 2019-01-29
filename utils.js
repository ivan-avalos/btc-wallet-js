const crypto = require ('crypto');
const secp256k1 = require ('secp256k1');
const Base58 = require ('base-58');

/*
 * utils.js
 * 
 * Copyright 2019 Iván Ávalos <ivan.avalos.diaz@hotmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 * 
 */

var wif_private_key = function (private_key_with_version) {
	var hash_a1 = crypto
		.createHash ('sha256')
		.update (Buffer.from (private_key_with_version, 'hex'))
		.digest ('hex');

	var hash_a2 = crypto
		.createHash ('sha256')
		.update (Buffer.from (hash_a1, 'hex'))
		.digest ('hex');

	var checksum_a = Buffer
		.from (hash_a2, 'hex')
		.slice (0, 4)
		.toString ('hex');

	var private_key_checksum = private_key_with_version + checksum_a;

	return Base58.encode (Buffer.from (private_key_checksum, 'hex'));
}

var public_address = function (public_key_version) {
	var hash_c1 = crypto
		.createHash ('sha256')
		.update (Buffer.from (public_key_version, 'hex'))
		.digest ('hex');

	var hash_c2 = crypto
		.createHash ('ripemd160')
		.update (Buffer.from (hash_c1, 'hex'))
		.digest ('hex');

	var public_key_version_hash_c = '00' + hash_c2;

	var hash_c3 = crypto
		.createHash ('sha256')
		.update (Buffer.from (public_key_version_hash_c, 'hex'))
		.digest ('hex');

	var hash_c4 = crypto
		.createHash ('sha256')
		.update (Buffer.from (hash_c3, 'hex'))
		.digest ('hex');

	var checksum_c = Buffer
		.from (hash_c4, 'hex')
		.slice (0, 4)
		.toString ('hex');

	var public_key_checksum_c = 
		public_key_version_hash_c + checksum_c;

	return Base58.encode (Buffer.from (public_key_checksum_c, 'hex'));
}

var validate_public_against_py_bitcoin = function (private_key_hex,
												   public_address_uncompressed,
												   compressed = true) {
	return secp256k1
	.privateKeyVerify (Buffer.from (private_key_hex, 'hex'));
}

module.exports = {
	wif_private_key: wif_private_key,
	public_address: public_address,
	validate_public_against_py_bitcoin: validate_public_against_py_bitcoin
}