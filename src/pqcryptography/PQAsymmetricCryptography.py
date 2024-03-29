# This file provides layer for easy post quantum cipher and signs

from . import SymmetricEncryption as aes
import liboqs

default_kem_algorithm = "Kyber1024"
default_sig_algorithm = "Dilithium5"

class cipher:
	key = None
	def __init__(self, key):
		self.key = key
	def encrypt(self, message):
		return aes.encrypt(self.key, message)
	def decrypt(self, message):
		return aes.decrypt(self.key, message)

class encryption:
	def generate_keypair(algorithm = None):
		algorithm = default_kem_algorithm if not algorithm else algorithm
		with liboqs.KeyEncapsulation(algorithm) as encryptor:
			public_key, private_key = encryptor.generate_keypair(), encryptor.export_secret_key()
		return public_key, private_key

	def create_cipher(public_key, algorithm = None):
		algorithm = default_kem_algorithm if not algorithm else algorithm
		with liboqs.KeyEncapsulation(algorithm) as encryptor:
			ciphertext, plain_key = encryptor.encap_secret(public_key)
		generated_cipher = cipher(plain_key)
		return generated_cipher, ciphertext

	def decrypt_cipher(private_key, cipher_text, algorithm = None):
		algorithm = default_kem_algorithm if not algorithm else algorithm
		with liboqs.KeyEncapsulation(algorithm, private_key) as encryptor:
			plain_key = encryptor.decap_secret(cipher_text)
		return cipher(plain_key)

	def encrypt(public_key, plaintext, algorithm = None):
		algorithm = default_kem_algorithm if not algorithm else algorithm
		with liboqs.KeyEncapsulation(algorithm) as encryptor:
			encrypted_key, plain_key = encryptor.encap_secret(public_key)
		ciphertext = aes.encrypt(plain_key, plaintext)
		return encrypted_key+ciphertext

	def decrypt(private_key, ciphertext, algorithm = None):
		algorithm = default_kem_algorithm if not algorithm else algorithm
		with liboqs.KeyEncapsulation(algorithm, private_key) as encryptor:
			encrypted_key_size = encryptor.details["length_ciphertext"]
			encrypted_key = ciphertext[:encrypted_key_size]
			ciphertext = ciphertext[encrypted_key_size:]
			plain_key = encryptor.decap_secret(encrypted_key)
		return aes.decrypt(plain_key, ciphertext)

	def get_details(algorithm = None):
		algorithm = default_kem_algorithm if not algorithm else algorithm
		with liboqs.KeyEncapsulation(algorithm) as encryptor:
			details = encryptor.details
		return details

	def get_algorithms():
		return liboqs.get_enabled_kem_mechanisms()

class signing:
	def generate_signs(algorithm = None):
		algorithm = default_sig_algorithm if not algorithm else algorithm
		with liboqs.Signature(algorithm) as signer:
			public_sign, private_sign = signer.generate_keypair(), signer.export_secret_key()
		return public_sign, private_sign

	def sign(private_sign, message, algorithm = None):
		algorithm = default_sig_algorithm if not algorithm else algorithm
		with liboqs.Signature(algorithm, private_sign) as signer:
			signature = signer.sign(message)
		return signature+message

	def verify(public_sign, message, algorithm = None):
		algorithm = default_sig_algorithm if not algorithm else algorithm
		with liboqs.Signature(algorithm) as signer:
			signature_size = signer.details["length_signature"]
			signature = message[:signature_size]
			message = message[signature_size:]
			assert signer.verify(message, signature, public_sign)
		return message

	def get_details(algorithm = None):
		algorithm = default_sig_algorithm if not algorithm else algorithm
		with liboqs.Signature(algorithm) as signer:
			details = signer.details
		return details

	def get_algorithms():
		return liboqs.get_enabled_sig_mechanisms()
