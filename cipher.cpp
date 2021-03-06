#include "cipher.hpp"

cipher::cipher() {
	KEY = generate_key();
	RUNS = 1;
	THREADS = 1;

	generate_encryption_table();
	generate_decryption_table();
}

cipher::cipher(std::array<uint8_t, 256> key) {
	KEY = key;
	RUNS = 1;
	THREADS = 1;

	generate_encryption_table();
	generate_decryption_table();
}

std::array<uint8_t, 256> cipher::get_key() {
	return KEY;
}

void cipher::set_key(std::array<uint8_t, 256> key) {
	KEY = key;
	generate_encryption_table();
	generate_decryption_table();
}

std::array<uint8_t, 256> cipher::generate_key() {
	std::array<uint8_t, 256> output{};
	std::iota(output.begin(), output.end(), 0);

	std::random_device rd;
	std::mt19937 gen(rd());
	
	std::shuffle(output.begin(), output.end(), gen);
	return output;
}

void cipher::generate_encryption_table() {
	for(size_t index_outer = 0; index_outer < 256; index_outer++)
		for(size_t index_inner = 0; index_inner < 256; index_inner++) {
			encryption_table[index_outer][(index_outer+index_inner)%256] = KEY[index_inner];
		}
}

void cipher::generate_decryption_table() {
	for(size_t index_outer = 0; index_outer < 256; index_outer++)
		for(size_t index_inner = 0; index_inner < 256; index_inner++) {
			decryption_table[index_outer][encryption_table[index_outer][index_inner]] = index_inner;
		}

}

std::vector<uint8_t> cipher::encrypt(std::vector<uint8_t> &data) {
	if(THREADS > 1) {
		std::vector<std::vector<uint8_t>> thread_blocks;
		size_t block_size = 0;
		split_data(thread_blocks, data, block_size);

		std::vector<std::thread> threads;
		threads.reserve(thread_blocks.size());

		for(auto &block : thread_blocks) {
			threads.emplace_back(std::thread( [&block, this]() {
				cipher::encrypt_t(block, RUNS);
			}));
		}

		for(auto &t : threads)
			t.join();
		merge_data(thread_blocks, data);

		block_size += RUNS;
		for(int i = 0; i < 8; i++) {
			data.push_back(block_size);
			block_size = block_size >> 8;
		}
		// Prevent data to look like blocks
		encrypt_t(data, 2);
	}
	else {
		encrypt_t(data, RUNS);
	}
	return data;
}

void cipher::encrypt_t(std::vector<uint8_t> &data, uint16_t runs) {
	size_t size = data.size();
	uint8_t table_index = encryption_table[0][size%256];
	data.reserve(size + runs);

	for(size_t run_count = 0; run_count < runs; run_count++) {
		data.push_back(encryption_table[1][table_index]);
		
		for(size_t index = 0; index < size; index++) {
			data[index] = encryption_table[table_index][data[index]];
			table_index += data[index];
			table_index++;
		}
		
		size++;
	}
}

std::vector<uint8_t> cipher::decrypt(std::vector<uint8_t> &data) {
	if(THREADS > 1) {
		decrypt_t(data, 2);

		size_t block_size = 0;
		for(int i = 0; i < 7; i++) {
			block_size += data.back();
			block_size = block_size << 8;
			data.pop_back();
		}
		block_size += data.back();
		data.pop_back();

		std::vector<std::vector<uint8_t>> thread_blocks;
		split_data(thread_blocks, data, block_size);

		std::vector<std::thread> threads;
		threads.reserve(thread_blocks.size());

		for(auto &block : thread_blocks) {
			threads.emplace_back(std::thread( [&block, this]() {
				cipher::decrypt_t(block, RUNS);
			}));
		}

		for(auto &t : threads)
			t.join();
		merge_data(thread_blocks, data);
	}
	else {
		decrypt_t(data, RUNS);
	}
	return data;
}

void cipher::decrypt_t(std::vector<uint8_t> &data, uint16_t runs) {
	size_t size = data.size();
	uint8_t table_index;
	uint8_t table_index_buff;

	for(size_t run_count = 0; run_count < runs; run_count++) {
		table_index = decryption_table[1][data.back()];
		data.pop_back();
		size--;
		
		for(size_t index = 0; index < size; index++) {
			table_index_buff = data[index];
			data[index] = decryption_table[table_index][data[index]];
			table_index += table_index_buff;
			table_index++;
		}
	}
}

void cipher::set_runs(uint16_t runs) {
	if(runs)
		RUNS = runs;
}

void cipher::set_threads(uint16_t threads) {
	if(threads)
		THREADS = threads;
}

void cipher::split_data(std::vector<std::vector<uint8_t>> &thread_data, std::vector<uint8_t> &data, size_t &block_size) {
	if(!block_size)
		block_size = (data.size() / THREADS) + 1;

	uint16_t  limit = THREADS - 1;
	thread_data.clear();
	thread_data.reserve(THREADS);
	thread_data.emplace_back(std::vector<uint8_t> (data.begin(),
								data.begin() +  block_size));
	uint16_t  counter = 1;
	while(counter < limit) {
		std::vector<uint8_t> buffer(data.begin() + ((counter * block_size)),
							  		data.begin() + ((counter + 1) * block_size));
		thread_data.push_back(buffer);
		counter++;
	}
	thread_data.emplace_back(std::vector<uint8_t>(data.begin() + ((counter * block_size)), data.end()));
}

void cipher::merge_data(std::vector<std::vector<uint8_t>> &thread_data, std::vector<uint8_t> &data) {
	data.clear();
	for(auto &buffer : thread_data) {
		data.insert(data.end(), buffer.begin(), buffer.end());
	}
}
