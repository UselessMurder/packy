#ifndef COMPRESS_H
#define COMPRESS_H

#include <vector>
#include <cstdint>


namespace mk {

class lzo_compress {
	void* wrkmem;
public:
	lzo_compress();
	~lzo_compress();
	void compress(std::vector<uint8_t> &data);
};

}

#endif