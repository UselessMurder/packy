#include <fs/file.h>
#include <stdexcept>

namespace fs {

base_file::base_file() {}
base_file::base_file(std_fs::path current_file_path) {
  file_path = current_file_path;
}
base_file::~base_file() {}
void base_file::set_path(std_fs::path current_file_path) {
  file_path = current_file_path;
}
std_fs::path base_file::get_path() { return file_path; }
bool base_file::is_exist(std_fs::path current_file_path) {
  bool result = false;
  try {
    if (std_fs::exists(current_file_path))
      result = true;
  } catch (std_fs::filesystem_error &fe) {
    throw std::domain_error(fe.what());
  }
  return result;
}
void base_file::copy_file(std_fs::path current_file_path) {
  try {
  	#ifdef BOOST_FS
    std_fs::copy_file(file_path, current_file_path,
                      std_fs::copy_option::overwrite_if_exists);
    #else
    std_fs::copy_file(file_path, current_file_path,
                      std_fs::copy_options::overwrite_existing);
    #endif
  } catch (std_fs::filesystem_error &fe) {
    throw std::domain_error(fe.what());
  }
}
std::uint64_t base_file::get_file_size() {
  std::uint64_t size = 0;
  try {
    size = std_fs::file_size(file_path);
  } catch (std_fs::filesystem_error &fe) {
    throw std::domain_error(fe.what());
  }
  return size;
}

in_file::in_file() : base_file() {}

in_file::in_file(std_fs::path current_file_path) : base_file(current_file_path) {}

in_file::~in_file() { close(); }

bool in_file::open() {
  bool result = false;
  stream.open(file_path, std::ifstream::binary | std::ifstream::in);
  if (stream.is_open())
    result = true;
  if (stream.fail())
    throw std::domain_error("Can`t open file for reading");
  return result;
}

void in_file::close() {
  if (stream.is_open())
    stream.close();
}

void in_file::set_position(std::uint64_t position) {
  stream.seekg(position);
  if (stream.fail())
    throw std::domain_error("Can`t set file stream position");
}

std::uint64_t in_file::get_position() {
  std::uint64_t position = stream.tellg();
  if (stream.fail())
    throw std::domain_error("Can`t get file stream position");
  return position;
}

std::uint64_t in_file::read_bytes(std::vector<std::uint8_t> &byte_array,
                                  std::uint64_t size) {
  byte_array.resize(size, 0);
  stream.read((char *)&byte_array[0], size);
  if (!stream) {
    size = stream.gcount();
    byte_array.resize(size);
  }
  if (stream.bad())
    throw std::domain_error("Can`t read bytes form file");
  return size;
}

bool in_file::is_eof() { return stream.eof(); }


out_file::out_file() : base_file() {}

out_file::out_file(boost::filesystem::path current_file_path)
    : base_file(current_file_path) {}

out_file::~out_file() { close(); }

bool out_file::open() {
  bool result = false;
  stream.open(file_path, std::ifstream::binary | std::ifstream::out);
  if (stream.is_open())
    result = true;
  if (stream.fail())
    throw std::domain_error("Can`t open file for writing");
  return result;
}

void out_file::close() {
  if (stream.is_open())
    stream.close();
}

void out_file::set_position(std::uint64_t position) {
  stream.seekp(position);
  if (stream.fail())
    throw std::domain_error("Can`t set file stream position");
}

std::uint64_t out_file::get_position() {
  std::uint64_t position = stream.tellp();
  if (stream.fail())
    throw std::domain_error("Can`t get file stream position");	
  return position;
}

void out_file::write_bytes(std::vector<std::uint8_t> &byte_array) {
  stream.write((char *)&byte_array[0], byte_array.size());
  if (stream.fail())
    throw std::domain_error("Can`t write bytes to file");
}

} // namespace fs