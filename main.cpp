#include <packy/packy.h>
#include <stdio.h>

#ifdef _WIN32
extern "C" int wmain(std::int32_t argc, wchar_t *argv[]) {
#else
int main(std::int32_t argc, char *argv[]) {
#endif
  for (std::int32_t i = 1; i < argc; i++) {
    std_fs::path src(argv[i]);
    std_fs::path dest(argv[i]);
#ifdef _WIN32
    printf("%ls:\n", argv[i]);
#else
    printf("%s:\n", argv[i]);
#endif
    try {
      if (std_fs::exists(src) && std_fs::is_regular_file(src)) {
        if (src.has_extension()) {
#ifdef _WIN32
          dest.replace_extension(L"packed" + src.extension().wstring());
#else
          dest.replace_extension("packed" + src.extension().string());
#endif
        } else {
#ifdef _WIN32
          dest += L".packed";
#else
          dest += ".packed";
#endif
        }
      } else {
        printf("	Is invalid path!\n");
        break;
      }
    } catch (std_fs::filesystem_error &er) {
      printf("	Is invalid path!\n");
      printf("	Error:\n %s\n", er.what());
      break;
    }
    packy p(src, dest);
    if (!p.pack()) {
      printf("	Packing error:\n reason: %s\n", p.why().c_str());
      try {
        if (boost::filesystem::exists(dest))
          boost::filesystem::remove(dest);
      } catch (std_fs::filesystem_error &er) {
        printf("Remove file error:\n %s\n", er.what());
      }
    } else
      printf("	Is packed!\n");
  }
  return 0;
}