#ifndef FASTBLOCKCIPHER_HPP
#define FASTBLOCKCIPHER_HPP

#include <array>
#include <random>
#include <cstdint>
#include <vector>
#include <string>
#include <thread>

class cipher {

	std::array<std::array<uint8_t, 256>, 256> encryption_table;
	std::array<std::array<uint8_t, 256>, 256> decryption_table;

	std::array<uint8_t, 256> 		KEY;
	uint16_t						RUNS;
	uint16_t 						THREADS;

	std::array<uint8_t, 256> generate_key();

	void generate_encryption_table();
	void generate_decryption_table();

	void encrypt_t(std::vector<uint8_t> &data, uint16_t runs);
	void decrypt_t(std::vector<uint8_t> &data, uint16_t runs);

	void split_data(std::vector<std::vector<uint8_t>> &thread_data, std::vector<uint8_t> &data, size_t &block_size);
	void merge_data(std::vector<std::vector<uint8_t>> &thread_data, std::vector<uint8_t> &data);

public:

	cipher();
	cipher(std::array<uint8_t, 256> key);
	~cipher() = default;

	std::array<uint8_t, 256> get_key();
	void set_key(std::array<uint8_t, 256> key);

	std::vector<uint8_t> encrypt(std::vector<uint8_t> &data);
	std::vector<uint8_t> decrypt(std::vector<uint8_t> &data);

	void set_runs(uint16_t runs);
	void set_threads(uint16_t threads);
};


#endif //FASTBLOCKCIPHER_HPP
