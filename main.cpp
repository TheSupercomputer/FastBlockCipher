#include <iostream>
#include <fstream>

#include "cipher.hpp"

// Little helper function to display usage of the program
void helpViewer() {
	std::cout << "-h shows this Help and exit" << std::endl;
	std::cout << "Need -e OR -d for mode selection" << std::endl;
	std::cout << "if none is given, -e is chosen" << std::endl;
	std::cout << "--------------------------------" << std::endl;
	std::cout << "-f PATH to specify the input file" << std::endl;
	std::cout << "-r INT to specify the runs per crypt usage" << std::endl;
	std::cout << "-t INT to specify the Threads used" << std::endl;
	std::cout << "-o PATH to specify the output file" << std::endl;
	std::cout << "If -o is not given, the input file will be overwritten"  << std::endl;
	std::cout << "-k PATH to specify the Keyfile to use" << std::endl;
	std::cout << "If -k is not give, a Keyfile with matching Filename in the same directory is used" << std::endl;
	std::cout << "If -k is not given while encrypting, a keyfile is generated" << std::endl;
}


int main(int argc, char** argv) {

	if(argc == 1) {
		std::cerr << "No Arguments given!" << std::endl;
		helpViewer();
		return -1;
	}
	int arg_counter = 1;
	bool encrypt = true;
	uint16_t runs = 1;
	uint16_t threads = 1;
	std::string path_in, path_out, key_path;

	// Parsing command line arguments 
	while(arg_counter < argc) {
		if(std::string(argv[arg_counter]) == "-d") {
			encrypt = false;
		}
		else if(std::string(argv[arg_counter]) == "-f" && arg_counter+1 < argc) {
			path_in = std::string(argv[arg_counter+1]);
			arg_counter++;
		}
		else if(std::string(argv[arg_counter]) == "-o" && arg_counter+1 < argc) {
			path_out = std::string(argv[arg_counter+1]);
			arg_counter++;
		}
		else if(std::string(argv[arg_counter]) == "-r" && arg_counter+1 < argc) {
			if(std::strtol(argv[arg_counter+1], nullptr,  10) != 0)
				runs = std::strtol(argv[arg_counter+1], nullptr, 10);
			arg_counter++;
		}
		else if(std::string(argv[arg_counter]) == "-t" && arg_counter+1 < argc) {
			if(std::strtol(argv[arg_counter+1], nullptr, 10) != 0)
				threads = std::strtol(argv[arg_counter+1], nullptr,10);
			arg_counter++;
		}
		else if(std::string(argv[arg_counter]) == "-k" && arg_counter+1 < argc) {
			key_path = std::string(argv[arg_counter+1]);
			arg_counter++;
		}
		else if(std::string(argv[arg_counter]) == "-h") {
			helpViewer();
			return 0;
		} else {
			std::cerr << "Unknown argument {" << argv[arg_counter] << "}, abort!" << std::endl;
			helpViewer();
			return -1;
		}
		// Increment arg_counter once in every option that has an extra argument
		// Incrementing arg_counter once every round 
		arg_counter++;
	}

	cipher FCrypt;
	FCrypt.set_threads(threads);
	FCrypt.set_runs(runs);

	if(encrypt) {
		std::fstream key_file;
		
		std::cout << "Encryption started!" << std::endl;
		if(key_path.empty()) {
			key_file.open(path_out + ".k", std::ios::out | std::ofstream::binary);
			std::cout << "Writing Keyfile: " << path_out << ".k ..." << std::flush;
			
			if(key_file.is_open()) {
				for (auto c : FCrypt.get_key()) {
					key_file << c;
				}
				key_file.close();
				std::cout << "OK" << std::endl;
			}
			else {
				std::cerr << "can't write encryption Key, abort!" << std::endl;
				return -2;
			}
		}
		else {
			key_file.open(key_path, std::ios::in | std::ofstream::binary);
			std::cout << "Reading Keyfile: " << key_path << "... " <<std::flush;
			
			if(key_file.is_open()) {
				uint8_t byte = key_file.get();
				uint8_t index = 0;
				std::array<uint8_t, 256> readKey {};
				
				while (key_file.good()) {
					readKey[index] = byte;
					byte = key_file.get();
					index++;
				}
				
				key_file.close();
				std::cout << "OK" << std::endl;
				FCrypt.set_key(readKey);
			}
			else {
				std::cerr << "can't read encryption Key, abort!" << std::endl;
				return -2;
			}
		}

		std::ifstream data_in;
		data_in.open(path_in, std::ifstream::binary);
		std::cout << "Loading " << path_in << " for encryption ..." << std::flush;
		std::vector<uint8_t> data;

		if(data_in.is_open()) {
			//To make sure no whitspaces get discarded.
			data_in.unsetf(std::ios::skipws);

			data_in.seekg(0, std::ios::end);
			data.reserve(data_in.tellg());
			data_in.seekg(0, std::ios::beg);

			uint8_t byte = data_in.get();
			
			while (data_in.good()) {
				data.push_back(byte);
				byte = data_in.get();
			}
			std::cout << "OK" << std::endl;
		}
		else {
			std::cerr << "can't read File for encryption, abort!" << std::endl;
			return -3;
		}
		std::cout << "Encrypt data ..." << std::flush;
		FCrypt.encrypt(data);
		std::cout << "OK"  << std::endl;

		std::ofstream encryption_out;
		
		if(path_out.empty()) {
			encryption_out.open(path_in, std::ofstream::binary);
			std::cout << "Writing encrypted file: " << path_in << " ..." << std::flush;
		}
		else {
			encryption_out.open(path_out, std::ofstream::binary);
			std::cout << "Writing encrypted file: " << path_out << " ..." << std::flush;
		}
		
		if(encryption_out.is_open()) {
			for (auto &character : data) {
				encryption_out << character;
			}
			encryption_out.close();
			std::cout << "OK" << std::endl;
		}
		else {
			std::cerr << "can't write encrypted File, abort!" << std::endl;
			return -4;
		}
	}
	else {
		std::cout << "Decryption started!" << std::endl;
		std::ifstream key_in;
		
		if(key_path.empty()) {
			key_in.open(path_in + ".k", std::ifstream::binary);
			std::cout << "Reading Keyfile: " << path_in << ".k ..." << std::flush;
		}
		else {
			key_in.open(key_path, std::ifstream::binary);
			std::cout << "Reading Keyfile: " << key_path  << std::flush;
		}
		if(key_in.is_open()) {
			uint8_t byte = key_in.get();
			uint8_t index = 0;
			std::array<uint8_t, 256> readKey {};
			
			while (key_in.good()) {
				readKey[index] = byte;
				byte = key_in.get();
				index++;
			}
			key_in.close();
			std::cout << "OK" << std::endl;
			FCrypt.set_key(readKey);
		}
		else {
			std::cerr << "can't read encryption Key, abort!" << std::endl;
			return -2;
		}

		std::ifstream data_in;
		data_in.open(path_in, std::ofstream::binary);
		std::cout << "Loading " << path_in << " for decryption ..." << std::flush;
		std::vector<uint8_t> data;

		if(data_in.is_open()) {
			//To make sure no whitspaces get discarded.
			data_in.unsetf(std::ios::skipws);

			data_in.seekg(0, std::ios::end);
			data.reserve(data_in.tellg());
			data_in.seekg(0, std::ios::beg);

			uint8_t byte = data_in.get();
			
			while (data_in.good()) {
				data.push_back(byte);
				byte = data_in.get();
			}
			std::cout << "OK" << std::endl;
		}
		else {
			std::cerr << "can't open File for decryption, abort!" << std::endl;
			return -3;
		}

		std::ofstream decryption_out;
		if(path_out.empty()) {
			decryption_out.open(path_in, std::ofstream::binary);
			std::cout << "Writing decrypted file to: " << path_in << "..." << std::flush;
		}
		else {
			decryption_out.open(path_out, std::ofstream::binary);
			std::cout << "Writing decrypted file to: " << path_out << "..." << std::flush;
		}
		if(decryption_out.is_open()) {
			FCrypt.decrypt(data);
			for (auto &character : data) {
				decryption_out << character;
			}
			decryption_out.close();
			std::cout << "OK" << std::endl;
		}
		else {
			std::cerr << "can't write decrypted File, abort!" << std::endl;
			return -4;
		}
	}
	return 0;
}