#ifndef PACKY_H
#define PACKY_H

#include <fs/file.h>

class packy {
private:
  fs::in_file src;
  fs::out_file dest;
  std::string reason;

public:
  packy();
  packy(boost::filesystem::path input_path,
        boost::filesystem::path output_path);
  ~packy();
  bool pack();
  std::string why();
  void close();
};

#endif