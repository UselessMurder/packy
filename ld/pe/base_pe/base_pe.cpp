#include <chrono>
#include <cstdlib>
#include <ld/pe/base_pe/base_pe.h>
#include <stdio.h>

namespace ld::pe {

base_pe::base_pe() : base_ld() {
  dos_header = 0;
  file_header = 0;
  nt_signature = 0;
}

base_pe::base_pe(fs::in_file *in_file) : base_ld(in_file) {
  dos_header = 0;
  file_header = 0;
  nt_signature = 0;
}

base_pe::~base_pe() {}

image_dos_header *base_pe::get_dos_header() {
  return reinterpret_cast<image_dos_header *>(&image[dos_header]);
}

image_file_header *base_pe::get_file_header() {
  return reinterpret_cast<image_file_header *>(&image[file_header]);
}

image_section_header *base_pe::get_section_header(std::uint64_t index) {
  return reinterpret_cast<image_section_header *>(
      &image[section_headers[index]]);
}

image_import_descriptor *
base_pe::get_import_descriptor(std::uint32_t rva) {
  return reinterpret_cast<image_import_descriptor *>(&image[rva]);
}

std::vector<library> *base_pe::get_import() { return &import; }

bool base_pe::parse() {
  bool result = true;
  file->open();
  result = read_dos_header_from_file();
  if (result)
    result = is_valid_mz();
  if (result)
    result = read_dos_stub_from_file();
  if (result)
    result = read_nt_signature_from_file();
  if (result)
    result = is_valid_pe();
  if (result)
    result = read_file_header_from_file();
  if (result)
    result = read_optional_header_from_file();
  if (result)
    result = is_valid_nt_magic();
  if (result)
    continue_parsing();
  file->close();
  return result;
}

bool base_pe::read_dos_header_from_file() {
  if (file->get_file_size() < sizeof(image_dos_header))
    return false;
  file->set_position(0);
  file->read_bytes(image, sizeof(image_dos_header));
  dos_header = 0;
  return true;
}

bool base_pe::read_dos_stub_from_file() {
  if (file->get_file_size() < get_dos_header()->e_lfanew)
    return false;
  file->set_position(sizeof(image_dos_header));
  std::vector<std::uint8_t> content;
  file->read_bytes(content,
                   get_dos_header()->e_lfanew - sizeof(image_dos_header));
  image.insert(image.end(), content.begin(), content.end());
  dos_stub = get_dos_header()->e_lfanew - sizeof(image_dos_header);
  return true;
}

bool base_pe::read_nt_signature_from_file() {
  if (file->get_file_size() < get_dos_header()->e_lfanew + 4)
    return false;
  file->set_position(get_dos_header()->e_lfanew);
  std::vector<std::uint8_t> content;
  file->read_bytes(content, 4);
  image.insert(image.end(), content.begin(), content.end());
  nt_signature = get_dos_header()->e_lfanew;
  return true;
}

bool base_pe::read_file_header_from_file() {
  if (file->get_file_size() <
      get_dos_header()->e_lfanew + 4 + sizeof(image_file_header))
    return false;
  std::vector<std::uint8_t> content;
  file->set_position(get_dos_header()->e_lfanew + 4);
  file->read_bytes(content, sizeof(image_file_header));
  image.insert(image.end(), content.begin(), content.end());
  file_header = get_dos_header()->e_lfanew + 4;
  return true;
}

void base_pe::read_section_headers_from_file(std::uint64_t shift) {
  if (get_file_header()->number_of_sections <= 0)
    throw std::domain_error("Image is not contain sections");

  if (file->get_file_size() <
      get_dos_header()->e_lfanew + 4 + sizeof(image_file_header) + shift +
          sizeof(image_section_header) * get_file_header()->number_of_sections)
    throw std::domain_error("Size of image is less than total sections size");

  std::vector<std::uint8_t> content;
  file->set_position(get_dos_header()->e_lfanew + 4 +
                     sizeof(image_file_header) + shift);
  file->read_bytes(content, get_file_header()->number_of_sections *
                                sizeof(image_section_header));
  section_headers.resize(get_file_header()->number_of_sections);
  for (std::uint32_t i = 0; i < get_file_header()->number_of_sections; i++) {
    section_headers[i] = image.size();
    image.insert(image.end(),
                 content.begin() + i * sizeof(image_section_header),
                 content.begin() + i * sizeof(image_section_header) +
                     sizeof(image_section_header));
  }
}

void base_pe::read_sections_from_file(std::uint64_t shift, std::uint32_t align,
                                      std::uint32_t sections_begin) {
  uint64_t pos =
      get_dos_header()->e_lfanew + 4 + sizeof(image_file_header) + shift +
      sizeof(image_section_header) * get_file_header()->number_of_sections;
  file->set_position(pos);
  std::vector<std::uint8_t> content;
  file->read_bytes(content, sections_begin - pos);
  image.insert(image.end(), content.begin(), content.end());
  image.resize(get_section_header(0)->virtual_address);
  for (std::uint32_t i = 0; i < section_headers.size(); i++) {
    file->set_position(get_section_header(i)->pointer_to_raw_data);
    if (get_section_header(i)->size_of_raw_data != 0)
      file->read_bytes(content, get_section_header(i)->size_of_raw_data);
    else
      content.clear();
    std::uint64_t size = get_section_header(i)->misc;
    std::uint64_t overhead = 0;
    global::align(size, overhead, align);
    content.resize(size + overhead);
    image.insert(std::end(image), std::begin(content), std::end(content));
  }
}

void base_pe::parse_import(image_data_directory *directories) {
  if (directories[1].size == 0)
    return;
  std::uint32_t begin = directories[1].virtual_address;
  for (std::uint32_t i = 0;
       i * sizeof(image_import_descriptor) < directories[1].size; i++) {
    if (get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->name == 0)
      return;
    library lib;
    read_ascii_string_from_image(
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->name,
        lib.name);
    lib.iat_begin =
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->first_thunk;
    read_thuncks(
        get_import_descriptor(begin + i * sizeof(image_import_descriptor))
            ->original_first_thunk,
        lib.functions);
    import.push_back(lib);
  }
}

void base_pe::is_valid_sections_size(std::uint64_t size_of_headers) {
  std::uint64_t temporary_size = 0;
  temporary_size += size_of_headers;
  for (std::uint32_t i = 0; i < section_headers.size(); i++)
    temporary_size += get_section_header(i)->size_of_raw_data;
  if (temporary_size > file->get_file_size())
    throw std::domain_error("Sections is truncated!");
}

bool base_pe::is_valid_mz() {
  std::uint8_t image_dos_signature[2] = {0x4D, 0x5A};
  for (std::uint8_t i = 0; i < 2; i++) {
    if (image_dos_signature[i] != image[dos_header + i])
      return false;
  }
  return true;
}

bool base_pe::is_valid_pe() {
  std::uint8_t image_nt_signature[4] = {0x50, 0x45, 0x0, 0x0};
  for (std::uint8_t i = 0; i < 4; i++) {
    if (image[nt_signature + i] != image_nt_signature[i])
      return false;
  }
  return true;
}

void base_pe::is_valid_data_directories(std::uint32_t count,
                                        image_data_directory *directories) {
  if (count != 16)
    throw std::domain_error("Data directories count is invalid");
  for (std::uint32_t i = 0; i < count; i++) {
    if (directories[i].size == 0)
      continue;
    std::uint64_t position =
        rva_to_file_position(directories[i].virtual_address);
    if (position + directories[i].size > file->get_file_size())
      throw std::domain_error("Data directory location is outsize of the file");
  }
}

std::uint64_t base_pe::rva_to_file_position(std::uint32_t rva) {
  std::uint32_t index = 0;
  if (!search_rva_in_sections(rva, index))
    return (std::uint64_t)rva;
  else
    return get_section_header(index)->pointer_to_raw_data +
           (rva - get_section_header(index)->virtual_address);
  return 0;
}

bool base_pe::search_rva_in_sections(std::uint32_t rva, std::uint32_t &index) {
  for (std::uint32_t i = 0; i < section_headers.size(); i++) {
    if (rva >= get_section_header(i)->virtual_address &&
        rva < get_section_header(i)->virtual_address +
                  get_section_header(i)->misc) {
      index = i;
      return true;
    }
  }
  return false;
}

void base_pe::read_ascii_string_from_image(std::uint32_t rva,
                                           std::vector<uint8_t> &string) {
  string.clear();
  for (std::uint32_t i = rva; i < image.size(); i++) {
    string.push_back(image[i]);
    if (image[i] == 0) {
      return;
    }
  }
  throw std::domain_error("Size of string is more than size of file");
}

} // namespace ld::pe