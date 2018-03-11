#ifndef FORM_H
#define FORM_H

#include <eg/base/part.h>
#include <eg/base/binding.h>
#include <vector>
#include <string>
#include <map>
#include <eg/base/invariant.h>

namespace eg {

class form : public node {
private:
	std::vector<std::pair<std::string, std::uint32_t>> arguments;
public:
	form(node *parent);
	~form();
	void add_argument(std::string argument_name);
	void add_argument(std::string argument_name, std::uint32_t bitness);
	std::vector<std::pair<std::string, std::uint32_t>> *get_arguments();
    void validate_arguments(std::map<std::string, part *> *args);
    void get_invariants(std::vector<invariant *> *invariants);
};

}

#endif