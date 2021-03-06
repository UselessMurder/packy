// This is an open source non-commercial project. Dear PVS-Studio, please check
// it.

// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <ld/pe/pe32/pe32.h>

namespace ld::pe {

pe32::pe32() : base_pe() { optional_header = 0; }

pe32::pe32(fs::in_file *in_file) : base_pe(in_file) { optional_header = 0; }

pe32::~pe32() {}

image_optional_header32 *pe32::get_optional_header() {
  return reinterpret_cast<image_optional_header32 *>(&image[optional_header]);
}

void pe32::continue_parsing() {
  read_section_headers_from_file(sizeof(image_optional_header32));
  is_valid_sections_size(get_optional_header()->size_of_headers);
  is_valid_data_directories(get_optional_header()->number_of_rva_and_sizes,
                            get_optional_header()->data_directory);
  read_sections_from_file(sizeof(image_optional_header32),
                          get_optional_header()->section_alignment,
                          get_optional_header()->size_of_headers);
  if (image.size() != get_optional_header()->size_of_image)
    throw std::domain_error(
        "Size of image is more than size of image declared in header");
  parse_import(get_optional_header()->data_directory);
  parse_relocations(get_optional_header()->data_directory);
  if (is_tls_exists()) {
    std::uint32_t tls_begin = get_tls_rva();
    std::remove(relocations.begin(), relocations.end(), tls_begin);
    std::remove(relocations.begin(), relocations.end(), tls_begin + 4);
    std::remove(relocations.begin(), relocations.end(), tls_begin + 8);
    std::remove(relocations.begin(), relocations.end(), tls_begin + 12);
  }
  parse_resources();
  parse_exports(get_optional_header()->data_directory);
}

machine_types pe32::get_machine_type() {
  machine_types type;
  switch (get_file_header()->machine) {
    case 0x014C: {
      type = machine_types::i386;
      break;
    }
    case 0x8664: {
      type = machine_types::amd64;
      break;
    }
    default: {
      type = machine_types::none;
      break;
    }
  }
  return type;
}

loader_types pe32::get_loader_type() { return loader_types::pe32; }

bool pe32::read_optional_header_from_file() {
  if ((file->get_file_size() <
       get_dos_header()->e_lfanew + 4 + sizeof(image_file_header) +
           get_file_header()->size_of_optional_header) &&
      (get_file_header()->size_of_optional_header !=
       sizeof(image_optional_header32)))
    return false;
  std::vector<std::uint8_t> content;
  file->set_position(get_dos_header()->e_lfanew + 4 +
                     sizeof(image_file_header));
  file->read_bytes(content, sizeof(image_optional_header32));
  image.insert(image.end(), content.begin(), content.end());
  optional_header = get_dos_header()->e_lfanew + 4 + sizeof(image_file_header);
  return true;
}

void pe32::read_thuncks(
    std::uint32_t begin,
    std::vector<std::pair<std::vector<uint8_t>, bool>> &functions) {
  std::vector<std::uint32_t> thuncks;
  for (std::uint32_t i = begin; true; i += 4) {
    if (i + 4 >= image.size())
      throw std::domain_error("thuncks size is more than file size");
    if (*((std::uint32_t *)&image[i]) == 0) break;
    thuncks.push_back(*((std::uint32_t *)&image[i]));
  }
  for (std::uint32_t i = 0; i < thuncks.size(); i++) {
    std::pair<std::vector<uint8_t>, bool> current_function;
    if (thuncks[i] & 0x80000000) {
      std::uint32_t val = thuncks[i] & 0x7FFFFFFF;
      val = val << 16;
      current_function.first.resize(sizeof(val));
      std::memcpy(current_function.first.data(), &val, sizeof(val));
      current_function.second = true;
    } else {
      read_ascii_string_from_image(thuncks[i] + 2, current_function.first);
      current_function.second = false;
    }
    functions.push_back(current_function);
  }
}

void pe32::wipe_thuncks(std::uint32_t begin) {
  std::vector<std::uint32_t> thuncks;
  for (std::uint32_t i = begin; true; i += 4) {
    if (i + 4 >= image.size())
      throw std::domain_error("thuncks size is more than file size");
    if (*((std::uint32_t *)&image[i]) == 0) break;
    thuncks.push_back(*((std::uint32_t *)&image[i]));
    global::wipe_memory(&image, i, 4);
  }
  for (auto th : thuncks) {
    if (!(th & 0x80000000)) {
      wipe_ascii_string(th + 2);
      global::wipe_memory(&image, th, 2);
    }
  }
}

bool pe32::is_valid_nt_magic() {
  std::uint8_t nt_magic[2] = {0x0B, 0x01};
  for (std::uint8_t i = 0; i < 2; i++) {
    if (image[optional_header + i] != nt_magic[i]) return false;
  }
  return true;
}

std::vector<uint8_t> pe32::get_rebuilded_header(
    std::uint32_t stub_size, std::uint32_t code_begin,
    std::pair<std::uint32_t, std::uint32_t> tls_directory,
    std::pair<std::uint32_t, std::uint32_t> reloc_directory,
    std::pair<std::uint32_t, std::uint32_t> resource_directory,
    std::uint32_t export_rva,
    std::pair<std::uint32_t, std::uint32_t> import_directory) {
  std::vector<uint8_t> new_header(
      image.begin(), image.begin() + get_optional_header()->size_of_headers);

  image_optional_header32 *header =
      reinterpret_cast<image_optional_header32 *>(&new_header[optional_header]);
  for (std::uint32_t i = 0; i < 16; i++) {
    header->data_directory[i].virtual_address = 0;
    header->data_directory[i].size = 0;
  }
  ((image_file_header *)&new_header[file_header])->pointer_to_symbol_table = 0;
  ((image_file_header *)&new_header[file_header])->number_of_symbols = 0;
  ((image_file_header *)&new_header[file_header])->number_of_sections = 2;
  header->size_of_code = stub_size;
  header->size_of_initialized_data = stub_size;
  header->size_of_uninitialized_data =
      image.size() - get_section_header(0)->virtual_address;
  header->address_of_entry_point = code_begin;

  header->data_directory[1].virtual_address = import_directory.first;
  header->data_directory[1].size = import_directory.second;
  header->data_directory[2].virtual_address = resource_directory.first;
  header->data_directory[2].size = resource_directory.second;
  header->data_directory[5].virtual_address = reloc_directory.first;
  header->data_directory[5].size = reloc_directory.second;
  header->data_directory[9].virtual_address = tls_directory.first;
  header->data_directory[9].size = tls_directory.second;
  header->data_directory[0].virtual_address = export_rva;
  header->data_directory[0].size =
      get_optional_header()->data_directory[0].size;

  std::uint64_t size = image.size();
  std::uint64_t overhead = 0;
  global::align(size, overhead, get_optional_header()->section_alignment);

  header->base_of_code = static_cast<std::uint32_t>(size + overhead);
  header->base_of_data = static_cast<std::uint32_t>(size + overhead);

  size = image.size() + stub_size;
  overhead = 0;
  global::align(size, overhead, get_optional_header()->section_alignment);
  header->size_of_image = static_cast<std::uint32_t>(size + overhead);
  std::memset(&new_header[section_headers[0]], 0,
              new_header.size() - section_headers[0]);
  make_first_section_header(new_header);
  make_second_section_header(new_header, stub_size);
  return new_header;
};

void pe32::make_first_section_header(std::vector<std::uint8_t> &header) {
  image_section_header *section_header =
      (image_section_header *)&header[section_headers[0]];

  std::memcpy(reinterpret_cast<char *>(section_header->name),
              global::rc.generate_random_string(8, true).c_str(), 8);

  std::uint64_t size = image.size() - get_section_header(0)->virtual_address;
  std::uint64_t overhead = 0;
  global::align(size, overhead, get_optional_header()->section_alignment);

  section_header->misc = static_cast<std::uint32_t>(size + overhead);
  section_header->virtual_address = get_section_header(0)->virtual_address;
  section_header->characteristics |= 0x20;
  section_header->characteristics |= 0x80;
  if (!is_nx_compatible()) section_header->characteristics |= 0x20000000;
  section_header->characteristics |= 0x40000000;
  section_header->characteristics |= 0x80000000;
}

void pe32::make_second_section_header(std::vector<uint8_t> &header,
                                      std::uint32_t size) {
  image_section_header *section_header =
      (image_section_header
           *)&header[section_headers[0] + sizeof(image_section_header)];
  std::memcpy(reinterpret_cast<char *>(section_header->name),
              global::rc.generate_random_string(8, true).c_str(), 8);

  std::uint64_t t_size = size;
  std::uint64_t overhead = 0;
  global::align(t_size, overhead, get_optional_header()->section_alignment);

  section_header->misc = static_cast<std::uint32_t>(t_size + overhead);
  section_header->virtual_address = image.size();

  overhead = 0;
  global::align(t_size, overhead, get_optional_header()->file_alignment);

  section_header->size_of_raw_data =
      static_cast<std::uint32_t>(t_size + overhead);
  section_header->pointer_to_raw_data = get_optional_header()->size_of_headers;
  section_header->characteristics |= 0x20;
  section_header->characteristics |= 0x40;
  section_header->characteristics |= 0x20000000;
  section_header->characteristics |= 0x40000000;
  section_header->characteristics |= 0x80000000;
}

std::vector<uint8_t> pe32::get_protected_data() {
  std::vector<uint8_t> data;
  data.insert(data.end(),
              image.begin() + get_section_header(0)->virtual_address,
              image.end());
  return data;
}

std::uint64_t pe32::get_real_image_begin() {
  return static_cast<std::uint64_t>(get_section_header(0)->virtual_address);
}

std::uint64_t pe32::get_real_image_size() {
  return image.size() -
         static_cast<std::uint64_t>(get_section_header(0)->virtual_address);
}
std::uint64_t pe32::get_begin_of_stub() {
  std::uint64_t size = image.size();
  std::uint64_t overhead = 0;
  global::align(size, overhead, get_optional_header()->section_alignment);
  return size + overhead;
}

std::uint64_t pe32::get_sections_vs() {
  return static_cast<std::uint64_t>(get_optional_header()->size_of_headers);
}

std::uint64_t pe32::get_image_vs() { return image.size(); }

void pe32::resize_with_file_align(std::vector<uint8_t> *data) {
  std::uint64_t size = data->size();
  std::uint64_t overhead = 0;
  global::align(size, overhead, get_optional_header()->file_alignment);
  if ((size + overhead) != data->size()) data->resize(size + overhead);
}

void pe32::resize_with_section_align(std::vector<uint8_t> *data) {
  std::uint64_t size = data->size();
  std::uint64_t overhead = 0;
  global::align(size, overhead, get_optional_header()->section_alignment);
  if ((size + overhead) != data->size()) data->resize(size + overhead);
}

bool pe32::is_tls_exists() {
  if (get_optional_header()->data_directory[9].virtual_address == 0 ||
      get_optional_header()->data_directory[9].size == 0)
    return false;
  return true;
}

bool pe32::is_resources_exists() {
  if (get_optional_header()->data_directory[2].virtual_address == 0 ||
      get_optional_header()->data_directory[2].size == 0)
    return false;
  return true;
}

bool pe32::is_reloc_exists() {
  if (get_optional_header()->data_directory[5].virtual_address == 0 ||
      get_optional_header()->data_directory[5].size == 0)
    return false;
  return true;
}

bool pe32::is_exports_exists() {
  if (get_optional_header()->data_directory[0].virtual_address == 0 ||
      get_optional_header()->data_directory[0].size == 0)
    return false;
  return true;
}

bool pe32::is_nx_compatible() {
  if (get_optional_header()->dll_characteristics & 0x0100) return true;
  return false;
}

image_tls_directory32 *pe32::get_tls_directory() {
  if (!is_tls_exists()) throw std::domain_error("TLS directory is not exists!");

  return (
      image_tls_directory32
          *)&image[get_optional_header()->data_directory[9].virtual_address];
}

std::uint32_t pe32::get_tls_rva() {
  return get_optional_header()->data_directory[9].virtual_address;
}

std::uint32_t pe32::get_resource_rva() {
  return get_optional_header()->data_directory[2].virtual_address;
}

std::uint32_t pe32::get_resource_size() {
  return get_optional_header()->data_directory[2].size;
}

void pe32::wipe_tls_directory() {
  if (!is_tls_exists()) throw std::domain_error("TLS directory is not exists!");

  std::uint32_t size = get_tls_directory()->end_address_of_raw_data -
                       get_tls_directory()->start_address_of_raw_data;
  std::uint32_t begin = get_tls_directory()->start_address_of_raw_data -
                        get_optional_header()->image_base;

  global::wipe_memory(&image, begin, size + 1);

  global::wipe_memory(&image,
                      get_optional_header()->data_directory[9].virtual_address,
                      sizeof(image_tls_directory32));
}

void pe32::get_part_of_image(std::vector<uint8_t> *part, std::uint32_t rva,
                             std::uint32_t size) {
  if (rva + size > image.size()) throw std::domain_error("Extra size part!");
  std::copy(image.begin() + rva, image.begin() + rva + size,
            std::back_inserter((*part)));
}

std::vector<uint8_t> *pe32::get_image() { return &image; }

}  // namespace ld::pe