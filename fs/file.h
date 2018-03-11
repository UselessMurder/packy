#ifndef FILE_H
#define FILE_H

#include <boost/filesystem.hpp>

namespace std_fs = boost::filesystem;
namespace std_streams = boost::filesystem;

#define BOOST_FS

namespace fs {

class base_file {
protected:
  std_fs::path file_path;

public:
  base_file();
  base_file(std_fs::path current_file_path);
  virtual ~base_file();
  virtual void set_path(std_fs::path current_file_path);
  virtual std_fs::path get_path();
  static bool is_exist(std_fs::path current_file_path);
  void copy_file(std_fs::path current_file_path);
  std::uint64_t get_file_size();
  virtual bool open() = 0;
  virtual void close() = 0;
  virtual void set_position(std::uint64_t position) = 0;
  virtual std::uint64_t get_position() = 0;
};

class in_file : public base_file {
private:
  std_streams::ifstream stream;

public:
  in_file();
  in_file(std_fs::path current_file_path);
  ~in_file();
  bool open();
  void close();
  std::uint64_t get_position();
  void set_position(std::uint64_t position);
  std::uint64_t read_bytes(std::vector<std::uint8_t> &byte_array,
                           std::uint64_t size);
  bool is_eof();
};

class out_file : public base_file {
private:
  std_streams::ofstream stream;

public:
  out_file();
  out_file(std_fs::path input_path);
  ~out_file();
  virtual bool open();
  virtual void close();
  virtual std::uint64_t get_position();
  virtual void set_position(std::uint64_t position);
  void write_bytes(std::vector<std::uint8_t> &byte_array);
};

} // namespace fs

#endif
